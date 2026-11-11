/**
 * BHARATHLINK PROTECTED INBOX — REVIEW ONLY / NOT IMPORTED BY LIVE APP
 * No network code, credentials, storage, timers or implicit claims.
 * Requires a caller-supplied RPC adapter, account context and trusted
 * E2EE decrypt adapter. Not proof of server authorization or signer status.
 * This is intentionally disabled against the published DEMO-backed TEST page.
 */
export const EXPECTED_ORIGIN = 'https://bharathlink-20-test.netlify.app';
export const EXPECTED_PROJECT = 'fsdusofbpwdrdvgexxyw';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KEY_NAMES = new Set([
  'wrappedKey', 'wrapped_key', 'wrap_iv', 'wrapIv',
  'ephPub', 'eph_pub', 'recipient_device_id',
  'signing_public_key_jwk', 'sender_public_key_jwk',
]);
const UNKNOWN = 'CLAIM_OUTCOME_UNKNOWN_NO_AUTO_RETRY';

export class ProtectedFlowError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ProtectedFlowError';
    this.code = code;
  }
}

function requireUuid(value) {
  if (typeof value !== 'string' || !UUID.test(value)) {
    throw new ProtectedFlowError('INVALID_IDENTIFIER');
  }
  return value.toLowerCase();
}
function requireFunction(value) {
  if (typeof value !== 'function') {
    throw new ProtectedFlowError('MISSING_TRUSTED_ADAPTER');
  }
}
function readerContext(source) {
  const c = source();
  if (!c || c.verifiedSigner !== true ||
      typeof c.sessionEpoch !== 'string' || !c.sessionEpoch ||
      typeof c.userId !== 'string' ||
      typeof c.deviceId !== 'string' ||
      typeof c.conversationId !== 'string') {
    throw new ProtectedFlowError('UNVERIFIED_SESSION');
  }
  return Object.freeze({
    userId: requireUuid(c.userId),
    deviceId: requireUuid(c.deviceId),
    conversationId: requireUuid(c.conversationId),
    sessionEpoch: c.sessionEpoch,
  });
}
function sameContext(a, b) {
  return a.userId === b.userId &&
    a.deviceId === b.deviceId &&
    a.conversationId === b.conversationId &&
    a.sessionEpoch === b.sessionEpoch;
}
function itemFromRpc(input, expectedConversation) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new ProtectedFlowError('INVALID_INBOX_RESPONSE');
  }
  if (Object.keys(input).some(k => KEY_NAMES.has(k))) {
    throw new ProtectedFlowError('INBOX_LEAKED_KEY_MATERIAL');
  }
  const messageId = requireUuid(input.message_id);
  if (requireUuid(input.conversation_id) !== expectedConversation) {
    throw new ProtectedFlowError('INBOX_CONVERSATION_MISMATCH');
  }
  if (!['available', 'consumed', 'expired'].includes(input.availability) ||
      typeof input.is_view_once !== 'boolean' ||
      typeof input.created_at !== 'string' ||
      !Number.isFinite(Date.parse(input.created_at))) {
    throw new ProtectedFlowError('INVALID_INBOX_RESPONSE');
  }
  if (input.availability !== 'available' &&
      (input.message_ciphertext != null || input.message_iv != null)) {
    throw new ProtectedFlowError('INBOX_EXPOSED_CLOSED_BODY');
  }
  if (input.availability === 'available' &&
      (typeof input.message_ciphertext !== 'string' ||
       !input.message_ciphertext ||
       typeof input.message_iv !== 'string' ||
       !input.message_iv)) {
    throw new ProtectedFlowError('INVALID_ENCRYPTED_BODY');
  }
  return Object.freeze({
    messageId,
    conversationId: expectedConversation,
    isViewOnce: input.is_view_once,
    availability: input.availability,
    createdAt: input.created_at,
    // Kept internal. NEVER included in user-visible listing results.
    ciphertext: input.message_ciphertext ?? null,
    iv: input.message_iv ?? null,
  });
}

/**
 * No document/network API is used here; all adapters injected. For the UI:
 * call loadPage on navigation; call openOnce ONLY from an explicit click
 * after an unambiguous synchronous confirmation. Never call openOnce in an
 * effect, route render, lifecycle callback, push handler or background job.
 */
export function createProtectedInboxController({
  getOrigin,
  getSupabaseProject,
  getContext,
  rpc,
  decryptWithCurrentDevice,
}) {
  for (const fn of [
    getOrigin, getSupabaseProject, getContext, rpc, decryptWithCurrentDevice
  ]) requireFunction(fn);

  const items = new Map();
  // Keep prior attempts even across account switches within controller
  // lifetime. Server is the actual cross-tab/cross-device replay guard.
  const claimedAttempts = new Set();
  const active = new Set();
  let boundContext = null;

  function checkOrigin() {
    if (getOrigin() !== EXPECTED_ORIGIN ||
        getSupabaseProject() !== EXPECTED_PROJECT) {
      throw new ProtectedFlowError('TEST_BACKEND_NOT_APPROVED');
    }
  }
  function snapshot() {
    checkOrigin();
    const current = readerContext(getContext);
    if (!boundContext) boundContext = current;
    if (!sameContext(boundContext, current)) {
      items.clear();
      boundContext = current;
      throw new ProtectedFlowError('SESSION_CHANGED_REOPEN_INBOX');
    }
    return current;
  }
  function assertStable(previous) {
    const current = snapshot();
    if (!sameContext(previous, current)) {
      throw new ProtectedFlowError('SESSION_CHANGED_REOPEN_INBOX');
    }
  }
  function publicItem(item) {
    return Object.freeze({
      messageId: item.messageId,
      conversationId: item.conversationId,
      isViewOnce: item.isViewOnce,
      availability: item.availability,
      createdAt: item.createdAt,
    });
  }

  return Object.freeze({
    readiness() {
      checkOrigin();
      return Object.freeze({status: 'REVIEW_ONLY_NOT_RELEASED'});
    },
    async loadPage({limit=20, beforeCreatedAt=null, beforeMessageId=null}={}) {
      const current = snapshot();
      if (!Number.isInteger(limit) || limit < 1 || limit > 50 ||
          (beforeCreatedAt !== null &&
           (typeof beforeCreatedAt !== 'string' ||
            !Number.isFinite(Date.parse(beforeCreatedAt)))) ||
          (beforeMessageId !== null && beforeCreatedAt === null)) {
        throw new ProtectedFlowError('INVALID_PAGE_REQUEST');
      }
      const page = await rpc('list_my_protected_messages_v1', {
        p_conversation_id: current.conversationId,
        p_device_id: current.deviceId,
        p_limit: limit,
        p_before_created_at: beforeCreatedAt,
        p_before_message_id: beforeMessageId == null
          ? null : requireUuid(beforeMessageId),
      });
      assertStable(current);
      if (!Array.isArray(page) || page.length > limit) {
        throw new ProtectedFlowError('INVALID_INBOX_RESPONSE');
      }
      const parsed = page.map(row => itemFromRpc(row, current.conversationId));
      const ids = new Set(parsed.map(m => m.messageId));
      if (ids.size !== parsed.length) {
        throw new ProtectedFlowError('DUPLICATE_INBOX_ITEM');
      }
      for (const item of parsed) items.set(item.messageId, item);
      return Object.freeze(parsed.map(publicItem));
    },
    /**
     * Caller MUST invoke from real user click, not automatically.
     * confirmOpen must synchronously return true; Promise or omitted confirm
     * does not authorize a key claim. No retries after any started claim.
     */
    async openOnce(messageId, {confirmOpen}={}) {
      const current = snapshot();
      const id = requireUuid(messageId);
      const message = items.get(id);
      if (!message || message.availability !== 'available' ||
          message.isViewOnce !== true) {
        throw new ProtectedFlowError('NOT_OPENABLE_VIEW_ONCE');
      }
      if (typeof confirmOpen !== 'function' || confirmOpen(publicItem(message)) !== true) {
        return Object.freeze({status: 'cancelled'});
      }
      const attemptId = current.userId + ':' + current.deviceId + ':' + id;
      if (claimedAttempts.has(attemptId) || active.has(attemptId)) {
        throw new ProtectedFlowError('CLAIM_ALREADY_ATTEMPTED_NO_RETRY');
      }
      // Mark before FIRST await. Any lost HTTP response might mean
      // consumed server-side; never automatically replay.
      claimedAttempts.add(attemptId);
      active.add(attemptId);
      try {
        assertStable(current);
        const envelope = await rpc('claim_protected_wrapped_key_v1', {
          p_message_id: id,
          p_device_id: current.deviceId,
        });
        assertStable(current);
        if (!envelope || envelope.viewOnce !== true ||
            typeof envelope.wrappedKey !== 'string' || !envelope.wrappedKey ||
            typeof envelope.wrapIv !== 'string' || !envelope.wrapIv ||
            !envelope.ephPub || typeof envelope.ephPub !== 'object' ||
            Array.isArray(envelope.ephPub)) {
          throw new ProtectedFlowError('INVALID_CLAIM_RESPONSE');
        }
        // The wrapped key exists ONLY in this call frame; no JS-side cache,
        // localStorage, IndexedDB, log, backup, push or telemetry.
        const plaintext = await decryptWithCurrentDevice({
          messageId: id,
          deviceId: current.deviceId,
          ciphertext: message.ciphertext,
          iv: message.iv,
          wrappedKey: envelope.wrappedKey,
          wrapIv: envelope.wrapIv,
          ephPub: envelope.ephPub,
        });
        assertStable(current);
        items.set(id, Object.freeze({
          ...message, ciphertext: null, iv: null,
          availability: 'consumed',
        }));
        return Object.freeze({status: 'opened', plaintext});
      } catch (_error) {
        // Do not infer whether the server consumed or client decrypted.
        // Do not return backend errors, key material, tokens or plaintext.
        items.delete(id);
        return Object.freeze({status: 'consumption_unknown', code: UNKNOWN});
      } finally {
        active.delete(attemptId);
      }
    },
    clearForAccountSwitch() {
      items.clear();
      boundContext = null;
      // attempted set stays; server remains final single-use authority.
    },
  });
}
