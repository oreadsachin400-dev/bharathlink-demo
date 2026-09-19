(function () {
'use strict';

/* =====================================================================
   1. CONFIG
   No secrets or API keys live here. Anything secret belongs server-side.
   ===================================================================== */
const CONFIG = Object.freeze({
  APP_NAME: 'BharathLink',
  VERSION: '1B.0.0',
  STORAGE_KEY: 'bharathlink.phase1a.state',
  SCHEMA_VERSION: 1,
  // RFC 2606 reserved TLD: can never route real mail. Replace when a real
  // domain and mail backend exist.
  MAIL_DOMAIN: 'bharatmail.test',
  OTP_LENGTH: 6,
  OTP_TTL_MS: 5 * 60 * 1000,
  OTP_MAX_ATTEMPTS: 5,
  OTP_RESEND_MS: 30 * 1000,
  LIMITS: Object.freeze({ messagesPerChat: 500, mailItems: 200, payments: 100,
    chatText: 2000, mailSubject: 150, mailBody: 5000, payNote: 50 })
});

/* =====================================================================
   2. UTILITIES (pure helpers, no app state)
   ===================================================================== */
const Util = {
  bytes(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; },
  hex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); },
  // RFC 4122 v4 UUID via getRandomValues. Works outside secure contexts
  // (unlike crypto.randomUUID), so testing on a phone over LAN http works.
  uuid() {
    const b = Util.bytes(16); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
    const h = Util.hex(b);
    return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
  },
  // Unbiased random digits (rejection sampling).
  randomDigits(n) {
    let out = '';
    while (out.length < n) for (const b of Util.bytes(n)) if (b < 250 && out.length < n) out += String(b % 10);
    return out;
  },
  // cyrb53: fast NON-cryptographic hash. Used only to derive deterministic
  // provisional ID suffixes. Uniqueness is enforced by an explicit collision
  // check, never by the hash alone.
  hash53(str, seed = 0) {
    let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761); h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507); h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507); h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return 4294967296 * (2097151 & h2) + (h1 >>> 0);
  },
  // Human-safe alphabet: no 0/o or 1/l/i ambiguity.
  toCode(num, len) {
    const A = 'abcdefghjkmnpqrstuvwxyz23456789'; let s = '', n = num;
    for (let i = 0; i < len; i++) { s += A[n % A.length]; n = Math.floor(n / A.length); }
    return s;
  },
  constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return r === 0;
  },
  formatMobile(m) { return m ? `+91 ${m.slice(0,5)} ${m.slice(5)}` : ''; },
  maskMobile(m) { return m ? `+91 ${m.slice(0,2)}••• ••${m.slice(7)}` : ''; },
  initials(name) {
    const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
    const first = parts[0] ? Array.from(parts[0])[0] : '?';
    const last = parts.length > 1 ? Array.from(parts[parts.length - 1])[0] : '';
    return (first + last).toUpperCase();
  },
  firstName(name) { return String(name || '').trim().split(/\s+/)[0] || ''; },
  time(ts) { try { return new Intl.DateTimeFormat('en-IN', { hour: 'numeric', minute: '2-digit' }).format(ts); } catch (e) { return ''; } },
  dateTime(ts) { try { return new Intl.DateTimeFormat('en-IN', { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' }).format(ts); } catch (e) { return ''; } },
  rupees(v) { return '₹' + Number(v).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); },
  delay(ms) { return new Promise(r => setTimeout(r, ms)); }
};

/* =====================================================================
   3. VALIDATION (client-side input rules; the server must re-validate)
   ===================================================================== */
const Validate = {
  mobile(raw) {
    let d = String(raw || '').replace(/[\s()-]/g, '');
    if (/^\+91\d{10}$/.test(d)) d = d.slice(3);
    else if (/^91\d{10}$/.test(d)) d = d.slice(2);
    else if (/^0\d{10}$/.test(d)) d = d.slice(1);
    return /^[6-9]\d{9}$/.test(d) ? { ok: true, value: d }
      : { ok: false, error: 'Enter a 10-digit Indian mobile number that starts with 6, 7, 8 or 9.' };
  },
  otp(raw) {
    const v = String(raw || '').replace(/\s/g, '');
    return new RegExp(`^\\d{${CONFIG.OTP_LENGTH}}$`).test(v) ? { ok: true, value: v }
      : { ok: false, error: `Enter the ${CONFIG.OTP_LENGTH}-digit code.` };
  },
  realName(raw) {
    const v = String(raw || '').normalize('NFC').replace(/\s+/g, ' ').trim();
    if (v.length < 2) return { ok: false, error: 'Enter your full name.' };
    if (v.length > 60) return { ok: false, error: 'Keep the name under 60 characters.' };
    if (!/^[\p{L}\p{M}][\p{L}\p{M} .'-]*$/u.test(v)) return { ok: false, error: 'Use letters, spaces, dots, apostrophes and hyphens only.' };
    return { ok: true, value: v };
  },
  vpa(raw) {
    const v = String(raw || '').trim();
    return /^[a-zA-Z0-9][a-zA-Z0-9._-]{1,255}@[a-zA-Z][a-zA-Z0-9]{1,63}$/.test(v) ? { ok: true, value: v }
      : { ok: false, error: 'Enter a UPI ID like name@bank.' };
  },
  amount(raw) {
    const v = String(raw || '').trim();
    if (!/^\d{1,6}(\.\d{1,2})?$/.test(v)) return { ok: false, error: 'Enter an amount in rupees, with up to 2 decimal places.' };
    const n = Number(v);
    if (n < 1 || n > 100000) return { ok: false, error: 'Enter an amount between ₹1 and ₹1,00,000.' };
    return { ok: true, value: n.toFixed(2) };
  },
  email(raw) {
    const v = String(raw || '').trim();
    return v.length <= 254 && /^[^\s@<>()"',;:\\]{1,64}@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$/.test(v)
      ? { ok: true, value: v.toLowerCase() } : { ok: false, error: 'Enter an address like name@example.com.' };
  },
  text(raw, max, label, { required = true } = {}) {
    const v = String(raw || '').replace(/\r\n/g, '\n').trim();
    if (!v) return required ? { ok: false, error: `Write a ${label} first.` } : { ok: true, value: '' };
    if (v.length > max) return { ok: false, error: `Keep the ${label} under ${max} characters.` };
    return { ok: true, value: v };
  }
};

/* =====================================================================
   4. VERIFICATION VOCABULARY
   "verified" can only come from an authoritative provider whose result
   carries a server attestation that Attestation.verify() accepts.
   In Phase 1A nothing can reach that state.
   ===================================================================== */
const VStatus = Object.freeze({ NOT_CHECKED: 'not_checked', PENDING: 'pending', DEMO: 'demo', VERIFIED: 'verified', FAILED: 'failed' });
const VStatusMeta = Object.freeze({
  not_checked: { label: 'Not checked', tone: 'none' },
  pending:     { label: 'Checking…',   tone: 'pending' },
  demo:        { label: 'Demo / Test',  tone: 'demo' },
  verified:    { label: 'Verified',     tone: 'verified' },
  failed:      { label: 'Could not verify', tone: 'failed' }
});
const TRUST_STEPS = Object.freeze([
  { key: 'mobile',  title: 'Mobile number ownership', detail: 'Confirms you control this number.' },
  { key: 'aadhaar', title: 'Aadhaar-linked identity', detail: 'Confirms your legal name through an authorised provider. BharathLink will not store your Aadhaar number.' },
  { key: 'kyc',     title: 'KYC', detail: 'Know-your-customer check by a regulated partner.' },
  { key: 'upi',     title: 'UPI payment identity', detail: 'Checks that an active UPI identity matches you, where applicable.' }
]);
const blankVerification = () => ({ status: VStatus.NOT_CHECKED, source: null, note: null, authoritative: false, updatedAt: null });

/* =====================================================================
   5. STORAGE + STORE
   State slices: account / identity / verification / ids / onboarding /
   messaging / mail / payments. Persisted to localStorage on this device.
   OTP sessions are never persisted.
   ===================================================================== */
const Storage = {
  load() {
    try {
      const raw = localStorage.getItem(CONFIG.STORAGE_KEY);
      if (!raw) return null;
      const o = JSON.parse(raw);
      return o && o.schema === CONFIG.SCHEMA_VERSION ? o : null;
    } catch (e) { return null; }
  },
  save(state) { try { localStorage.setItem(CONFIG.STORAGE_KEY, JSON.stringify(state)); return true; } catch (e) { return false; } },
  clear() { try { localStorage.removeItem(CONFIG.STORAGE_KEY); } catch (e) { /* ignore */ } }
};

function defaultState() {
  return {
    schema: CONFIG.SCHEMA_VERSION,
    createdAt: Date.now(),
    account: null,     // { accountId, mobile, createdAt, authProvider, authAuthoritative }
    identity: null,    // { realName, nameSource, nameLocked, displayAlias, ageStatus, ageSource, createdAt, updatedAt }
    verification: { mobile: blankVerification(), aadhaar: blankVerification(), kyc: blankVerification(), upi: blankVerification() },
    ids: null,         // { handle, messagingId, mailId, allocatedBy, provisional, allocatedAt }
    onboarding: { complete: false },
    messaging: { conversations: {} },
    mail: { messages: [], seeded: false },
    payments: { requests: [] }
  };
}

const Store = {
  state: null,
  persistOk: true,
  init() {
    const loaded = Storage.load();
    this.state = loaded ? Object.assign(defaultState(), loaded) : defaultState();
    // A check cannot still be running after a reload, so "pending" resets.
    for (const k of Object.keys(this.state.verification)) {
      if (this.state.verification[k].status === VStatus.PENDING) this.state.verification[k] = blankVerification();
    }
    this.persist();
  },
  update(mutator) { mutator(this.state); this.persist(); },
  persist() { this.persistOk = Storage.save(this.state); },
  reset() { Storage.clear(); this.state = defaultState(); this.persist(); }
};

/* =====================================================================
   6. AUTH / OTP PROVIDER
   OtpProvider interface (swap DevLocalOtpProvider for a server-backed one):
     sendOtp(mobile)            -> Promise<{ sessionId, expiresAt, resendAvailableAt, devCode? }>
     verifyOtp(sessionId, code) -> Promise<{ ok:true, mobile } | { ok:false, reason, attemptsLeft? }>
   A real provider runs both steps on the server, never exposes the code,
   and on success sets an httpOnly session cookie. The UI does not change.
   ===================================================================== */
const DevLocalOtpProvider = {
  id: 'dev-local-otp', isDevelopment: true, authoritative: false,
  _sessions: new Map(), // memory only
  async sendOtp(mobile) {
    const now = Date.now(), sessionId = Util.uuid(), code = Util.randomDigits(CONFIG.OTP_LENGTH);
    this._sessions.clear();
    this._sessions.set(sessionId, { mobile, code, expiresAt: now + CONFIG.OTP_TTL_MS, attempts: 0 });
    return { sessionId, expiresAt: now + CONFIG.OTP_TTL_MS, resendAvailableAt: now + CONFIG.OTP_RESEND_MS, devCode: code };
  },
  async verifyOtp(sessionId, code) {
    const s = this._sessions.get(sessionId);
    if (!s) return { ok: false, reason: 'no_session' };
    if (Date.now() > s.expiresAt) { this._sessions.delete(sessionId); return { ok: false, reason: 'expired' }; }
    s.attempts++;
    if (Util.constantTimeEqual(code, s.code)) { this._sessions.delete(sessionId); return { ok: true, mobile: s.mobile }; }
    const left = CONFIG.OTP_MAX_ATTEMPTS - s.attempts;
    if (left <= 0) { this._sessions.delete(sessionId); return { ok: false, reason: 'locked' }; }
    return { ok: false, reason: 'mismatch', attemptsLeft: left };
  }
};

const Auth = {
  provider: DevLocalOtpProvider,
  pending: null,     // in-memory OTP session; lost on refresh by design
  lastMobile: '',
  async start(mobile) {
    const r = await this.provider.sendOtp(mobile);
    this.lastMobile = mobile;
    this.pending = Object.assign({ mobile }, r);
    return this.pending;
  },
  resend() { return this.start(this.pending ? this.pending.mobile : this.lastMobile); },
  async verify(code) {
    if (!this.pending) return { ok: false, reason: 'no_session' };
    const r = await this.provider.verifyOtp(this.pending.sessionId, code);
    if (r.ok) { this.pending = null; Account.create(r.mobile, this.provider); }
    else if (r.reason !== 'mismatch') this.pending = null;
    return r;
  }
};

const Account = {
  create(mobile, provider) {
    Store.update(s => {
      s.account = { accountId: Util.uuid(), mobile, createdAt: Date.now(),
        authProvider: provider.id, authAuthoritative: !!provider.authoritative };
    });
    Verification.record('mobile', {
      status: provider.isDevelopment ? VStatus.DEMO : VStatus.VERIFIED,
      note: provider.isDevelopment ? 'Test code shown on screen. No SMS was sent.' : null
    }, provider);
  }
};

/* =====================================================================
   7. VERIFICATION PROVIDERS
   VerificationProvider interface:
     { id, kind, authoritative:boolean, check(context) -> Promise<{ status, note?, attestation? }> }
   Production: check() calls the BharathLink server, which talks to UIDAI /
   KYC / NPCI partners under proper authorisation and returns a signed
   attestation. Only then may a result become "verified".
   ===================================================================== */
const Attestation = {
  // Phase 1A has no trusted server and no signing keys, so nothing is accepted.
  verify(/* attestation */) { return false; }
};

const DemoVerificationProvider = kind => ({
  id: `demo-${kind}`, kind, authoritative: false, isDevelopment: true,
  async check() { await Util.delay(700); return { status: VStatus.DEMO, note: 'Simulated for testing. No real check was made.' }; }
});

const Verification = {
  providers: new Map(['aadhaar', 'kyc', 'upi'].map(k => [k, DemoVerificationProvider(k)])),
  running: false,
  register(kind, provider) { this.providers.set(kind, provider); },
  record(kind, result, provider) {
    let status = result.status;
    // Guard: an unattested "verified" is never stored, whatever the caller claims.
    if (status === VStatus.VERIFIED && !(provider && provider.authoritative && Attestation.verify(result.attestation))) {
      console.warn(`[Verification] Rejected unattested "verified" result for ${kind}.`);
      status = provider && provider.isDevelopment ? VStatus.DEMO : VStatus.NOT_CHECKED;
    }
    Store.update(s => {
      s.verification[kind] = { status, source: provider ? provider.id : null, note: result.note || null,
        authoritative: status === VStatus.VERIFIED, updatedAt: Date.now() };
      // The legal name locks only after an authoritative identity check.
      if (s.identity) s.identity.nameLocked = s.verification.aadhaar.status === VStatus.VERIFIED;
    });
  },
  async runDemoChecks(onProgress) {
    if (this.running) return;
    this.running = true;
    try {
      for (const kind of ['aadhaar', 'kyc', 'upi']) {
        const p = this.providers.get(kind);
        Store.update(s => { s.verification[kind] = Object.assign(blankVerification(), { status: VStatus.PENDING }); });
        if (onProgress) onProgress();
        this.record(kind, await p.check({ accountId: Store.state.account.accountId }), p);
        if (onProgress) onProgress();
      }
    } finally { this.running = false; if (onProgress) onProgress(); }
  },
  clearDemo() { Store.update(s => { for (const k of ['aadhaar', 'kyc', 'upi']) s.verification[k] = blankVerification(); }); },
  summary(s) {
    const statuses = ['aadhaar', 'kyc'].map(k => s.verification[k].status);
    if (statuses.every(x => x === VStatus.VERIFIED)) return { status: VStatus.VERIFIED, label: 'Identity verified' };
    if (statuses.some(x => x === VStatus.DEMO)) return { status: VStatus.DEMO, label: 'Demo checks only' };
    return { status: VStatus.NOT_CHECKED, label: 'Not verified yet' };
  }
};

/* =====================================================================
   8. IDENTITY
   Real Name = legal identity field (self-declared until verified).
   displayAlias is reserved for a future, separate public display name.
   No government ID numbers are ever collected or stored.
   ===================================================================== */
const Identity = {
  create({ realName, ageStatus }) {
    Store.update(s => {
      s.identity = { realName, nameSource: 'self_declared', nameLocked: false, displayAlias: null,
        ageStatus, ageSource: 'self_declared', createdAt: Date.now(), updatedAt: Date.now() };
    });
  },
  async updateRealName(newName) {
    if (Store.state.identity.nameLocked) return { ok: false, error: 'Your legal name is locked because it was verified.' };
    const hadIds = !!Store.state.ids;
    Store.update(s => { s.identity.realName = newName; s.identity.updatedAt = Date.now(); });
    if (hadIds) { const ids = await IdService.allocateFor(Store.state); Store.update(s => { s.ids = ids; }); }
    return { ok: true, reissued: hadIds };
  },
  ageLabel(a) { return a === 'adult' ? '18+' : 'Under 18'; }
};

/* =====================================================================
   9. DIRECTORY (local sample data; stands in for a server directory)
   Fictional, clearly labelled samples. No phone numbers or UPI IDs are
   attached, so the prototype can never call or pay a real stranger.
   Two "Ravi Kumar" entries demonstrate the duplicate-name strategy.
   ===================================================================== */
const SAMPLE_CONTACTS = Object.freeze([
  { id: 's-ravi-1', realName: 'Ravi Kumar',    handle: 'ravi.kumar.h7tq',    city: 'Patna' },
  { id: 's-ravi-2', realName: 'Ravi Kumar',    handle: 'ravi.kumar.m2xe',    city: 'Coimbatore' },
  { id: 's-priya',  realName: 'Priya Nair',    handle: 'priya.nair.c4wk',    city: 'Kochi' },
  { id: 's-arjun',  realName: 'Arjun Mehta',   handle: 'arjun.mehta.p9rd',   city: 'Ahmedabad' },
  { id: 's-fatima', realName: 'Fatima Shaikh', handle: 'fatima.shaikh.k3vy', city: 'Pune' }
].map(Object.freeze));

const Directory = {
  all() { return SAMPLE_CONTACTS; },
  byId(id) { return SAMPLE_CONTACTS.find(c => c.id === id) || null; },
  byHandle(h) { const k = String(h || '').trim().toLowerCase().replace(/^@/, ''); return SAMPLE_CONTACTS.find(c => c.handle === k) || null; },
  takenHandles() { return new Set(SAMPLE_CONTACTS.map(c => c.handle)); }
};

/* =====================================================================
   10. ID ALLOCATION
   IdAllocator interface:
     allocate({ accountId, realName, taken:Set }) -> Promise<{ handle, messagingId, mailId, allocatedBy, provisional }>
   Handle = name slug + suffix derived from the account ID, so two people
   with the same name get different suffixes. Collisions are detected and
   re-derived. Production: the server allocates inside a uniqueness-
   constrained transaction and the client only displays the result.
   ===================================================================== */
const LocalIdAllocator = {
  id: 'local-provisional', authoritative: false,
  slug(name) {
    const ascii = String(name).normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
    const parts = ascii.split(/[^a-z0-9]+/).filter(Boolean);
    let s = parts.length > 2 ? `${parts[0]}.${parts[parts.length - 1]}` : parts.join('.');
    s = s.slice(0, 24).replace(/\.+$/, '');
    // Non-Latin names (e.g. Devanagari) have no ASCII slug yet; transliteration is a future server task.
    return s.length >= 2 ? s : 'member';
  },
  async allocate({ accountId, realName, taken }) {
    const base = this.slug(realName);
    for (let attempt = 0; attempt < 64; attempt++) {
      const suffix = Util.toCode(Util.hash53(`${accountId}|${attempt}`), attempt < 32 ? 4 : 6);
      const handle = `${base}.${suffix}`;
      if (!taken.has(handle)) {
        return { handle, messagingId: `@${handle}`, mailId: `${handle}@${CONFIG.MAIL_DOMAIN}`,
          allocatedBy: this.id, provisional: true, allocatedAt: Date.now(), attempt };
      }
    }
    throw new Error('Could not allocate a unique ID');
  }
};

const IdService = {
  allocator: LocalIdAllocator,
  inflight: null,
  allocateFor(state) {
    if (!this.inflight) {
      this.inflight = this.allocator.allocate({ accountId: state.account.accountId, realName: state.identity.realName,
        taken: Directory.takenHandles() }).finally(() => { this.inflight = null; });
    }
    return this.inflight;
  }
};

/* =====================================================================
   11. MESSAGING (local only)
   MessagingTransport interface: send(conversation, message) -> Promise<{ delivery }>
   E2EE extension point: a CryptoProvider { encrypt, decrypt, audited } can be
   registered later. Until then the UI states messages are NOT E2E encrypted.
   ===================================================================== */
const LocalMessagingTransport = { id: 'local-only', async send() { return { delivery: 'saved_on_device' }; } };
const E2EE = { provider: null, isActive() { return !!(this.provider && this.provider.audited === true); } };

const Messaging = {
  transport: LocalMessagingTransport,
  list() { return Object.values(Store.state.messaging.conversations).sort((a, b) => b.updatedAt - a.updatedAt); },
  get(id) { return Object.prototype.hasOwnProperty.call(Store.state.messaging.conversations, id) ? Store.state.messaging.conversations[id] : null; },
  openWith(contactId) {
    const found = Object.values(Store.state.messaging.conversations).find(c => c.contactId === contactId);
    if (found) return found.id;
    const id = Util.uuid();
    Store.update(s => { s.messaging.conversations[id] = { id, contactId, messages: [], updatedAt: Date.now() }; });
    return id;
  },
  async send(convId, text) {
    const conv = this.get(convId);
    const msg = { id: Util.uuid(), from: 'me', text, at: Date.now(), delivery: 'pending', encrypted: E2EE.isActive() };
    msg.delivery = (await this.transport.send(conv, msg)).delivery;
    Store.update(s => {
      const c = s.messaging.conversations[convId];
      c.messages.push(msg);
      if (c.messages.length > CONFIG.LIMITS.messagesPerChat) c.messages.splice(0, c.messages.length - CONFIG.LIMITS.messagesPerChat);
      c.updatedAt = msg.at;
    });
    return msg;
  }
};

/* =====================================================================
   12. BHARATMAIL (local only)
   MailTransport interface: send(message) -> Promise<{ delivery }>, fetchInbox()
   Nothing leaves the device in Phase 1A.
   ===================================================================== */
const LocalMailTransport = { id: 'local-only', async send() { return { delivery: 'not_delivered' }; } };

const Mail = {
  transport: LocalMailTransport,
  folder: 'inbox',
  seedWelcome() {
    if (Store.state.mail.seeded) return;
    Store.update(s => {
      s.mail.messages.unshift({ id: Util.uuid(), folder: 'inbox', from: 'BharathLink (on this device)', to: s.ids.mailId,
        subject: 'Your BharatMail ID is ready', at: Date.now(), delivery: 'local',
        body: `Your provisional BharatMail ID is ${s.ids.mailId}.\n\nThis message was created on your device. BharatMail can't send to or receive from other email services yet. When the mail backend is connected, your final address will be issued by the BharathLink server.` });
      s.mail.seeded = true;
    });
  },
  list(folder) { return Store.state.mail.messages.filter(m => m.folder === folder); },
  get(id) { return Store.state.mail.messages.find(m => m.id === id) || null; },
  async send({ to, subject, body }) {
    const msg = { id: Util.uuid(), folder: 'sent', from: Store.state.ids.mailId, to, subject, body, at: Date.now(), delivery: 'pending' };
    msg.delivery = (await this.transport.send(msg)).delivery;
    Store.update(s => {
      s.mail.messages.unshift(msg);
      if (s.mail.messages.length > CONFIG.LIMITS.mailItems) s.mail.messages.length = CONFIG.LIMITS.mailItems;
    });
    return msg;
  }
};

/* =====================================================================
   13. PAYMENTS
   Initiation (UPI deep link, handled by the user's own UPI app) is kept
   strictly separate from verification (server confirmation via PSP/bank).
   PaymentVerifier interface: verify(request) -> Promise<{ available, status?, attestation? }>
   A client report is never treated as a verified result.
   ===================================================================== */
const PayStatus = Object.freeze({ CREATED: 'created', HANDED_OFF: 'handed_off',
  CLIENT_SUCCESS: 'client_reported_success', CLIENT_FAILURE: 'client_reported_failure', SERVER_VERIFIED: 'server_verified' });
const PayStatusMeta = Object.freeze({
  created:                 { label: 'Request created', tone: 'none' },
  handed_off:              { label: 'Opened in UPI app. Result unknown', tone: 'pending' },
  client_reported_success: { label: 'You reported: paid (unverified)', tone: 'pending' },
  client_reported_failure: { label: 'You reported: not paid', tone: 'failed' },
  server_verified:         { label: 'Confirmed by server', tone: 'verified' }
});
const PaymentVerifier = { id: 'none', available: false, async verify() { return { available: false }; } };

const Payments = {
  verifier: PaymentVerifier,
  list() { return Store.state.payments.requests; },
  get(id) { return Store.state.payments.requests.find(r => r.id === id) || null; },
  create({ payeeVpa, payeeName, amount, note }) {
    const now = Date.now();
    const req = { id: Util.uuid(), payeeVpa, payeeName: payeeName || null, amount, note: note || null,
      status: PayStatus.CREATED, beneficiaryTrust: VStatus.NOT_CHECKED, serverVerification: 'unavailable',
      createdAt: now, updatedAt: now, history: [{ status: PayStatus.CREATED, at: now, by: 'client' }] };
    Store.update(s => {
      s.payments.requests.unshift(req);
      if (s.payments.requests.length > CONFIG.LIMITS.payments) s.payments.requests.length = CONFIG.LIMITS.payments;
    });
    return req.id;
  },
  setStatus(id, status, { attestation } = {}) {
    if (status === PayStatus.SERVER_VERIFIED && !Attestation.verify(attestation)) {
      console.warn('[Payments] Refused to mark a payment verified without a server attestation.');
      return false;
    }
    Store.update(s => {
      const r = s.payments.requests.find(x => x.id === id);
      if (!r) return;
      r.status = status; r.updatedAt = Date.now();
      r.history.push({ status, at: r.updatedAt, by: status === PayStatus.SERVER_VERIFIED ? 'server' : 'client' });
    });
    return true;
  },
  upiLink(req) {
    // Standard UPI intent parameters, URI-encoded. This only opens the user's UPI app.
    const p = [['pa', req.payeeVpa]];
    if (req.payeeName) p.push(['pn', req.payeeName]);
    p.push(['am', req.amount], ['cu', 'INR']);
    if (req.note) p.push(['tn', req.note]);
    return 'upi://pay?' + p.map(([k, v]) => `${k}=${encodeURIComponent(v).replace(/%40/g, '@')}`).join('&');
  }
};

/* =====================================================================
   14. UI PRIMITIVES
   All DOM is built with createElement / textContent. innerHTML is never
   used, so user-controlled text is always rendered as plain text.
   ===================================================================== */
const SAFE_HREF = /^(#|tel:|upi:|mailto:)/i;

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) { if (typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v); }
      else if (k === 'href') { if (SAFE_HREF.test(v)) el.setAttribute('href', v); }
      else if (k === 'value') el.value = v;
      else if (typeof v === 'boolean') el[k] = v;
      else el.setAttribute(k, String(v));
    }
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function svgEl(tag, attrs, children = []) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  children.forEach(c => el.appendChild(c));
  return el;
}

const ICONS = Object.freeze({
  back:  ['M15 18l-6-6 6-6'],
  home:  ['M3 11l9-7 9 7v9a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z'],
  phone: ['M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1.9.4 1.8.7 2.7a2 2 0 0 1-.5 2.1L8.1 9.8a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.9.3 1.8.6 2.7.7a2 2 0 0 1 1.7 2z'],
  chat:  ['M21 12a8.5 8.5 0 0 1-12.4 7.6L3.5 21l1.4-4.8A8.5 8.5 0 1 1 21 12z'],
  mail:  ['M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1z', 'M3.5 6.5l8.5 6 8.5-6'],
  rupee: ['M6 4h12', 'M6 9h12', 'M9 4c4 0 6 2 6 5s-2.5 5-6 5H7l8 7'],
  id:    ['M4 4h16a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1z', 'M9 12.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z', 'M5.5 17c.7-1.8 2-2.8 3.5-2.8s2.8 1 3.5 2.8', 'M15 9h3.5', 'M15 13h2.5'],
  shield:['M12 3l8 3v6c0 5-3.4 8.2-8 9-4.6-.8-8-4-8-9V6z', 'M8.5 12l2.5 2.5 4.5-5'],
  plus:  ['M12 5v14', 'M5 12h14'],
  send:  ['M21 3L10 14', 'M21 3l-7 18-4-7-7-4z'],
  info:  ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M12 16v-5', 'M12 8h.01'],
  copy:  ['M9 9h11v11H9z', 'M5 15H4V4h11v1'],
  edit:  ['M4 20h4L19 9l-4-4L4 16z']
});
function Icon(name, size = 24) {
  const svg = svgEl('svg', { viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor',
    'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false', class: 'icon' });
  for (const d of ICONS[name] || []) svg.appendChild(svgEl('path', { d }));
  return svg;
}
function Logo(size = 40) {
  return svgEl('svg', { viewBox: '0 0 48 48', width: size, height: size, 'aria-hidden': 'true', focusable: 'false' }, [
    svgEl('rect', { x: 1.5, y: 1.5, width: 45, height: 45, rx: 14, fill: '#14205A', stroke: '#E4A13A', 'stroke-width': 2 }),
    svgEl('circle', { cx: 19.5, cy: 24, r: 8, fill: 'none', stroke: '#E4A13A', 'stroke-width': 3.4 }),
    svgEl('circle', { cx: 28.5, cy: 24, r: 8, fill: 'none', stroke: '#FFFFFF', 'stroke-width': 3.4 })
  ]);
}

/* ---------- Reusable components ---------- */
function Button(label, { variant = 'primary', onClick, type = 'button', disabled = false, icon } = {}) {
  return h('button', { class: `btn btn--${variant}`, type, onClick, disabled }, icon ? Icon(icon, 20) : null, label);
}
function LinkButton(label, href, { variant = 'primary', onClick, icon } = {}) {
  return h('a', { class: `btn btn--${variant}`, href, onClick }, icon ? Icon(icon, 20) : null, label);
}
function IconButton(icon, label, onClick) {
  return h('button', { class: 'iconbtn', type: 'button', 'aria-label': label, title: label, onClick }, Icon(icon));
}
function StatusBadge(status, label) {
  const meta = VStatusMeta[status] || VStatusMeta.not_checked;
  return h('span', { class: `badge badge--${meta.tone}` }, label || meta.label);
}
function ToneBadge(tone, label) { return h('span', { class: `badge badge--${tone}` }, label); }
function Notice(tone, children, icon = 'info') {
  return h('div', { class: `notice notice--${tone}`, role: 'note' }, Icon(icon, 20), h('div', null, children));
}
function Avatar(name, extra = '') {
  const c = Util.hash53(String(name || '')) % 5;
  return h('span', { class: `avatar avatar--c${c} ${extra}`.trim(), 'aria-hidden': 'true' }, Util.initials(name));
}
function Field({ id, label, input, hint, error }) {
  return h('div', { class: 'field' }, h('label', { for: id }, label), input,
    hint ? h('p', { class: 'hint', id: `${id}-hint` }, hint) : null, error || null);
}
function ErrorText(id) { return h('p', { class: 'error', id, role: 'alert' }); }
function setError(errEl, input, message) {
  errEl.textContent = message || '';
  if (!input) return;
  if (message) { input.setAttribute('aria-invalid', 'true'); input.focus(); } else input.removeAttribute('aria-invalid');
}
function Section(title, ...children) {
  return h('section', { class: 'section' }, h('h2', { class: 'section-title' }, title), children);
}
function ListRow({ href, onClick, avatar, title, sub, trail }) {
  return h('li', null, h(href ? 'a' : 'button', { class: 'row', href: href ? `#${href}` : null, type: href ? null : 'button', onClick },
    avatar || null,
    h('span', { class: 'row__body' }, h('span', { class: 'row__title' }, title), sub ? h('span', { class: 'row__sub' }, sub) : null),
    trail ? h('span', { class: 'row__trail' }, trail) : null));
}
/* Lets long IDs and addresses wrap at "." and "@" instead of mid-word. */
function breakable(str) {
  const parts = String(str).split(/(?=[@.])/);
  return parts.flatMap((p, i) => (i ? [h('wbr'), p] : [p]));
}
function KvRow(label, value) { return h('div', { class: 'kv__row' }, h('dt', null, label), h('dd', null, value)); }
function IdBlock(label, value, icon) {
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); Toast.show('Copied'); }
    catch (e) { Toast.show('Copy isn\u2019t available here. Press and hold the ID to select it.'); }
  };
  return h('div', { class: 'idblock' },
    h('div', { class: 'idblock__label' }, Icon(icon, 18), label),
    h('div', { class: 'idblock__value' }, h('span', { class: 'idblock__text' }, breakable(value)), IconButton('copy', `Copy ${label}`, copy)));
}

/* Trust thread: the four-step chain of trust, coloured by actual state. */
function TrustThread(s) {
  return h('ol', { class: 'thread', 'aria-label': 'Trust checks' }, TRUST_STEPS.map(step => {
    const v = s.verification[step.key];
    const tone = (VStatusMeta[v.status] || VStatusMeta.not_checked).tone;
    return h('li', { class: 'thread__step' },
      h('span', { class: `thread__node thread__node--${tone}`, 'aria-hidden': 'true' }),
      h('div', { class: 'thread__head' }, h('span', { class: 'thread__title' }, step.title), StatusBadge(v.status)),
      h('p', { class: 'thread__detail' }, step.detail),
      v.note ? h('p', { class: 'thread__note' }, v.note) : null);
  }));
}

/* Trust card: the minimal user-facing Digital Identity. */
function TrustCard(s, { showIds = true } = {}) {
  const i = s.identity, v = s.verification;
  const rows = [
    KvRow('Mobile number', [Util.formatMobile(s.account.mobile), StatusBadge(v.mobile.status, v.mobile.status === VStatus.DEMO ? 'Test OTP only' : null)]),
    KvRow('Age status', [Identity.ageLabel(i.ageStatus), h('span', { class: 'hint' }, 'Self-declared')]),
    KvRow('Aadhaar', StatusBadge(v.aadhaar.status)),
    KvRow('KYC', StatusBadge(v.kyc.status))
  ];
  if (showIds && s.ids) rows.push(KvRow('Messaging ID', breakable(s.ids.messagingId)), KvRow('BharatMail ID', breakable(s.ids.mailId)));
  return h('article', { class: 'trustcard', 'aria-label': 'Digital identity trust card' },
    h('div', { class: 'trustcard__head' }, Avatar(i.realName, 'avatar--lg avatar--on-ink'),
      h('div', { class: 'trustcard__who' }, h('p', { class: 'trustcard__label' }, 'Real name'),
        h('p', { class: 'trustcard__name' }, i.realName),
        h('p', { class: 'trustcard__source' }, i.nameLocked ? 'Verified legal name (locked)' : 'Self-declared. Not verified.'))),
    h('dl', { class: 'kv' }, rows),
    h('p', { class: 'trustcard__foot' }, 'Not checked and Demo / Test mean no real verification has happened. Authorised checks are not connected in this build.'));
}

function CallerCard({ name, sub, badge }) {
  return h('div', { class: 'caller' }, Avatar(name, 'avatar--lg avatar--on-ink'),
    h('p', { class: 'caller__name' }, name), sub ? h('p', { class: 'caller__sub' }, sub) : null, badge);
}

const NAV = Object.freeze([
  ['home', '/home', 'home', 'Home'], ['chats', '/chats', 'chat', 'Chats'], ['mail', '/mail', 'mail', 'Mail'],
  ['pay', '/pay', 'rupee', 'Pay'], ['identity', '/identity', 'id', 'Identity']
]);
function BottomNav(active) {
  return h('nav', { class: 'bottomnav', 'aria-label': 'Main' }, NAV.map(([k, r, ic, label]) =>
    h('a', { href: `#${r}`, 'aria-current': k === active ? 'page' : null }, Icon(ic), h('span', null, label))));
}

/* Screen shell: top bar with back navigation, main content, optional nav/footer. */
function Screen({ title, back, actions = [], nav = null, children, header, footer }) {
  const top = header || h('header', { class: 'topbar' },
    back ? IconButton('back', 'Go back', () => Router.back(back)) : h('span', { class: 'topbar__spacer' }),
    h('h1', { id: 'screen-title', tabindex: '-1' }, title), actions);
  return h('div', { class: 'screen' }, top,
    h('main', { class: nav ? 'content' : 'content content--nonav', id: 'main' }, children),
    footer || null, nav ? BottomNav(nav) : null);
}

const Toast = {
  el: null, timer: null,
  show(msg) {
    this.el.textContent = msg; this.el.classList.add('is-visible');
    clearTimeout(this.timer); this.timer = setTimeout(() => this.el.classList.remove('is-visible'), 3000);
  }
};

/* Timers that must stop when the screen changes. */
const Lifecycle = { cleanups: [], add(fn) { this.cleanups.push(fn); }, run() { this.cleanups.splice(0).forEach(fn => fn()); } };

/* =====================================================================
   15. VIEWS (one function per screen; each returns a DOM node)
   ===================================================================== */
const Views = {

  /* ----- Onboarding 1: Welcome ----- */
  welcome() {
    return h('div', { class: 'welcome' },
      h('div', { class: 'welcome__brand' }, Logo(52), h('p', { class: 'wordmark' }, 'BharathLink')),
      h('h1', { class: 'welcome__title', id: 'screen-title', tabindex: '-1' }, 'One verified identity for every way you connect.'),
      h('div', { class: 'eco' },
        h('span', { class: 'eco__core' }, Icon('shield', 20), 'Your identity'),
        h('ul', { class: 'eco__spokes', 'aria-label': 'Services connected to your identity' },
          [['phone', 'Calls'], ['chat', 'Messages'], ['mail', 'Mail'], ['rupee', 'Pay']].map(([ic, l]) => h('li', null, Icon(ic), l)))),
      h('p', { class: 'welcome__lede' }, 'Calling, messaging, mail and payments, all anchored to your mobile number and one trusted identity.'),
      h('div', { class: 'welcome__actions' }, Button('Get started', { variant: 'marigold', onClick: () => Router.go('/mobile') })),
      h('p', { class: 'welcome__note' }, 'Phase 1A prototype. No real identity, KYC or payment checks happen in this build.'));
  },

  /* ----- Onboarding 2: Mobile number ----- */
  mobile() {
    const err = ErrorText('mobile-err');
    const input = h('input', { class: 'input', id: 'mobile', name: 'mobile', type: 'tel', inputmode: 'numeric',
      autocomplete: 'tel-national', maxlength: '14', placeholder: '98765 43210', required: true,
      'aria-describedby': 'mobile-hint mobile-err', value: Auth.lastMobile || '' });
    const btn = Button('Send code', { type: 'submit' });
    const form = h('form', { novalidate: 'novalidate', onSubmit: async e => {
      e.preventDefault(); setError(err, input, '');
      const v = Validate.mobile(input.value);
      if (!v.ok) return setError(err, input, v.error);
      btn.disabled = true;
      try { await Auth.start(v.value); Router.go('/otp'); }
      catch (ex) { setError(err, input, 'The code could not be sent. Try again.'); btn.disabled = false; }
    } },
      h('div', { class: 'field' }, h('label', { for: 'mobile' }, 'Mobile number'),
        h('div', { class: 'prefix' }, h('span', { class: 'prefix__cc', 'aria-hidden': 'true' }, '+91'), input),
        h('p', { class: 'hint', id: 'mobile-hint' }, 'Indian mobile numbers only for now.'), err),
      btn);
    return Screen({ title: 'Your mobile number', back: '/welcome', children: [
      h('p', { class: 'lede' }, 'Your mobile number anchors your BharathLink identity. You\u2019ll confirm you own it with a one-time code.'), form] });
  },

  /* ----- Onboarding 3: OTP ----- */
  otp() {
    const P = Auth.pending;
    const err = ErrorText('otp-err');
    const input = h('input', { class: 'input input--otp', id: 'otp', name: 'otp', type: 'text', inputmode: 'numeric',
      autocomplete: 'one-time-code', maxlength: String(CONFIG.OTP_LENGTH), required: true, 'aria-describedby': 'otp-err' });
    const btn = Button('Verify code', { type: 'submit' });
    const resendBtn = Button('Resend code', { variant: 'ghost' });
    const tick = () => {
      const wait = Math.ceil((P.resendAvailableAt - Date.now()) / 1000);
      resendBtn.disabled = wait > 0;
      resendBtn.textContent = wait > 0 ? `Resend code in ${wait}s` : 'Resend code';
    };
    tick();
    const iv = setInterval(tick, 1000); Lifecycle.add(() => clearInterval(iv));
    resendBtn.addEventListener('click', async () => { await Auth.resend(); Toast.show('New test code created'); App.render(); });

    const form = h('form', { novalidate: 'novalidate', onSubmit: async e => {
      e.preventDefault(); setError(err, input, '');
      const v = Validate.otp(input.value);
      if (!v.ok) return setError(err, input, v.error);
      btn.disabled = true;
      const r = await Auth.verify(v.value);
      if (r.ok) return Router.go('/setup', { replace: true });
      btn.disabled = false;
      const msg = {
        mismatch: `That code doesn\u2019t match. ${r.attemptsLeft} ${r.attemptsLeft === 1 ? 'attempt' : 'attempts'} left.`,
        expired: 'This code has expired. Request a new one.',
        locked: 'Too many wrong attempts. Request a new code.',
        no_session: 'This code is no longer valid. Request a new one.'
      }[r.reason] || 'The code could not be checked.';
      if (r.reason !== 'mismatch') { clearInterval(iv); btn.disabled = true; resendBtn.disabled = false; resendBtn.textContent = 'Request a new code'; }
      setError(err, input, msg);
    } }, Field({ id: 'otp', label: 'One-time code', input, error: err }), btn);

    return Screen({ title: 'Enter the code', back: '/mobile', children: [
      h('p', { class: 'lede' }, `Code for ${Util.formatMobile(P.mobile)}.`),
      Auth.provider.isDevelopment ? Notice('dev', [h('strong', null, 'Test mode. '), 'No SMS was sent. Your test code is ',
        h('strong', { class: 'devcode', id: 'dev-otp' }, P.devCode), '.']) : null,
      form,
      h('div', { class: 'stack section' }, resendBtn,
        Button('Change number', { variant: 'ghost', onClick: () => Router.go('/mobile', { replace: true }) }))] });
  },

  /* ----- Onboarding 4: Activation / Identity setup ----- */
  setup() {
    const err = ErrorText('name-err'), ageErr = ErrorText('age-err');
    const input = h('input', { class: 'input', id: 'realname', name: 'realname', type: 'text', autocomplete: 'name',
      autocapitalize: 'words', maxlength: '60', required: true, 'aria-describedby': 'realname-hint name-err' });
    const radio = (value, label) => h('label', { class: 'choice' }, h('input', { type: 'radio', name: 'age', value }), h('span', null, label));
    const form = h('form', { novalidate: 'novalidate', onSubmit: e => {
      e.preventDefault(); setError(err, input, ''); ageErr.textContent = '';
      const v = Validate.realName(input.value);
      if (!v.ok) return setError(err, input, v.error);
      const age = form.querySelector('input[name="age"]:checked');
      if (!age) { ageErr.textContent = 'Choose your age group.'; return; }
      Identity.create({ realName: v.value, ageStatus: age.value === 'adult' ? 'adult' : 'minor' });
      Router.go('/onboard/identity', { replace: true });
    } },
      Field({ id: 'realname', label: 'Real name', input, error: err,
        hint: 'Enter your name as it appears on your government ID. Once an authorised check verifies it, it will be locked.' }),
      h('fieldset', { class: 'fieldset' }, h('legend', null, 'Age'),
        h('div', { class: 'choices' }, radio('adult', '18 or older'), radio('minor', 'Under 18')),
        h('p', { class: 'hint' }, 'Self-declared for now.'), ageErr),
      Notice('info', 'This prototype never asks for your Aadhaar number or any ID document number, and does not store them.', 'shield'),
      Button('Continue', { type: 'submit' }));
    return Screen({ title: 'Set up your identity', children: [
      h('p', { class: 'lede' }, 'Your number is confirmed for this test session. Now tell us who you are.'), form] });
  },

  /* ----- Onboarding 5: Digital identity + activation chain ----- */
  onboardIdentity() {
    const s = Store.state, running = Verification.running;
    return Screen({ title: 'Your digital identity', children: [
      h('p', { class: 'lede' }, 'This is your identity so far. Each trust check below activates when an authorised partner is connected.'),
      TrustCard(s, { showIds: false }),
      Section('Activation', TrustThread(s),
        h('p', { class: 'hint section' }, 'You can simulate the checks to preview activation. Simulated results are labelled Demo / Test and never count as verification.')),
      h('div', { class: 'stack section' },
        Button(running ? 'Simulating\u2026' : 'Simulate checks (demo)', { variant: 'secondary', disabled: running,
          onClick: () => Verification.runDemoChecks(() => App.refresh()) }),
        Button('Continue', { disabled: running, onClick: () => Router.go('/onboard/ids') }))] });
  },

  /* ----- Onboarding 6: Automatic IDs ----- */
  onboardIds() {
    const s = Store.state;
    if (!s.ids) {
      const status = h('p', { class: 'lede', role: 'status' }, 'Creating your IDs\u2026');
      IdService.allocateFor(s).then(ids => { Store.update(st => { st.ids = ids; }); App.refresh(); })
        .catch(() => { status.textContent = 'Your IDs could not be created. Go back and try again.'; });
      return Screen({ title: 'Your BharathLink IDs', back: '/onboard/identity', children: [status] });
    }
    return Screen({ title: 'Your BharathLink IDs', back: '/onboard/identity', children: [
      h('p', { class: 'lede' }, 'These were created automatically from your account. They aren\u2019t usernames you pick, so two people with the same name always get different IDs.'),
      IdBlock('Messaging ID', s.ids.messagingId, 'chat'),
      IdBlock('BharatMail ID', s.ids.mailId, 'mail'),
      Notice('warn', 'Provisional: allocated on this device. In production the BharathLink server issues final IDs and guarantees they are unique.'),
      Button('Go to Home', { onClick: () => {
        Store.update(st => { st.onboarding.complete = true; });
        Mail.seedWelcome();
        Router.go('/home', { replace: true });
      } })] });
  },

  /* ----- Home ----- */
  home() {
    const s = Store.state, sum = Verification.summary(s);
    const header = h('header', { class: 'topbar topbar--home' }, Logo(32), h('span', { class: 'wordmark' }, 'BharathLink'),
      h('span', { class: 'pill' }, 'Prototype'));
    const tile = (key, route, icon, title, desc) => h('a', { class: `tile tile--${key}`, href: `#${route}` },
      h('span', { class: 'tile__icon' }, Icon(icon)), h('span', { class: 'tile__title' }, title), h('span', { class: 'tile__desc' }, desc));
    return Screen({ header, nav: 'home', children: [
      h('section', { class: 'hero' },
        h('h1', { id: 'screen-title', tabindex: '-1' }, `Namaste, ${Util.firstName(s.identity.realName)}`),
        h('a', { class: 'hero__strip', href: '#/identity', 'aria-label': 'Open your digital identity' },
          Avatar(s.identity.realName, 'avatar--on-ink'),
          h('span', { class: 'hero__who' }, h('span', { class: 'hero__name' }, s.identity.realName),
            h('span', { class: 'hero__mobile' }, Util.maskMobile(s.account.mobile)),
            StatusBadge(sum.status, sum.label)))),
      Store.persistOk ? null : Notice('warn', 'This browser is blocking storage. Your data will be lost when you refresh.'),
      h('div', { class: 'services' },
        h('a', { class: 'tile tile--identity', href: '#/identity' }, h('span', { class: 'tile__icon' }, Icon('id')),
          h('span', { class: 'tile__text' }, h('span', { class: 'tile__title' }, 'Digital Identity'),
            h('span', { class: 'tile__desc' }, 'Your trust card and verification status'))),
        tile('calls', '/calls', 'phone', 'Verified Calling', 'See who is calling, not just a number'),
        tile('chats', '/chats', 'chat', 'Verified Messaging', 'Conversations tied to real identities'),
        tile('mail', '/mail', 'mail', 'BharatMail', 'Mail on your verified identity'),
        tile('pay', '/pay', 'rupee', 'UPI / Verified Payment', 'Know who you\u2019re paying before you pay')),
      h('p', { class: 'footnote' }, `Phase 1A prototype, version ${CONFIG.VERSION}. Data stays on this device.`)] });
  },

  /* ----- Digital Identity ----- */
  identity() {
    const s = Store.state, running = Verification.running;
    const nameErr = ErrorText('edit-name-err');
    const nameInput = h('input', { class: 'input', id: 'edit-name', type: 'text', autocomplete: 'name', maxlength: '60',
      value: s.identity.realName, 'aria-describedby': 'edit-name-hint edit-name-err' });
    let editBtn = null;
    const editForm = h('form', { hidden: true, novalidate: 'novalidate', onSubmit: async e => {
      e.preventDefault(); setError(nameErr, nameInput, '');
      const v = Validate.realName(nameInput.value);
      if (!v.ok) return setError(nameErr, nameInput, v.error);
      const r = await Identity.updateRealName(v.value);
      if (!r.ok) return setError(nameErr, nameInput, r.error);
      Toast.show(r.reissued ? 'Name saved. Provisional IDs updated.' : 'Name saved.');
      App.render();
    } },
      Field({ id: 'edit-name', label: 'Real name', input: nameInput, error: nameErr,
        hint: 'Changing your name before verification reissues your provisional IDs.' }),
      h('div', { class: 'btn-row' },
        Button('Cancel', { variant: 'secondary', onClick: () => { editForm.hidden = true; editBtn.hidden = false; } }),
        Button('Save name', { type: 'submit' })));
    editBtn = Button('Edit real name', { variant: 'secondary', icon: 'edit', onClick: () => { editForm.hidden = false; editBtn.hidden = true; nameInput.focus(); } });
    const anyDemo = ['aadhaar', 'kyc', 'upi'].some(k => s.verification[k].status === VStatus.DEMO);

    return Screen({ title: 'Digital Identity', back: '/home', nav: 'identity', children: [
      TrustCard(s),
      Section('Trust checks', TrustThread(s),
        h('div', { class: 'btn-row section' },
          Button(running ? 'Simulating\u2026' : 'Simulate checks', { variant: 'secondary', disabled: running, onClick: () => Verification.runDemoChecks(() => App.refresh()) }),
          Button('Clear results', { variant: 'ghost', disabled: running || !anyDemo, onClick: () => { Verification.clearDemo(); App.refresh(); } }))),
      Section('Legal name',
        s.identity.nameLocked
          ? Notice('info', 'Your legal name was verified by an authorised check and can\u2019t be edited here.', 'shield')
          : h('div', { class: 'stack' }, h('p', { class: 'hint' }, 'Your real name is self-declared and not yet verified, so you can still correct it. A separate display name will come in a later phase.'), editBtn, editForm)),
      Section('On this device',
        h('p', { class: 'hint' }, 'Your prototype data is stored only in this browser. No Aadhaar, PAN or other ID numbers are stored.'),
        h('div', { class: 'section' }, Button('Erase all prototype data', { variant: 'danger', onClick: () => {
          if (!window.confirm('Erase your BharathLink prototype data from this browser? This can\u2019t be undone.')) return;
          Store.reset(); Auth.pending = null; Auth.lastMobile = ''; Mail.folder = 'inbox';
          Router.stack = []; Router.go('/welcome', { replace: true });
        } })))] });
  },

  /* ----- Verified Calling ----- */
  calls() {
    const s = Store.state, sum = Verification.summary(s);
    const err = ErrorText('dial-err');
    const result = h('div', { 'aria-live': 'polite' });
    const input = h('input', { class: 'input', id: 'dial', type: 'tel', inputmode: 'numeric', autocomplete: 'off', maxlength: '14',
      placeholder: '98765 43210', 'aria-describedby': 'dial-err' });
    const form = h('form', { novalidate: 'novalidate', onSubmit: e => {
      e.preventDefault(); setError(err, input, ''); result.replaceChildren();
      const v = Validate.mobile(input.value);
      if (!v.ok) return setError(err, input, v.error);
      // A number-to-identity lookup will be a server call. Samples carry no numbers, so nothing matches locally.
      result.appendChild(h('div', { class: 'result' },
        h('p', { class: 'result__title' }, Util.formatMobile(v.value)),
        StatusBadge(VStatus.NOT_CHECKED, 'Unknown number'),
        h('p', { class: 'hint' }, 'No BharathLink identity is linked to this number on this device. The call will show only the number.'),
        LinkButton('Open phone dialer', `tel:+91${v.value}`, { icon: 'phone' })));
    } },
      h('div', { class: 'field' }, h('label', { for: 'dial' }, 'Phone number'),
        h('div', { class: 'prefix' }, h('span', { class: 'prefix__cc', 'aria-hidden': 'true' }, '+91'), input), err),
      Button('Look up number', { type: 'submit', variant: 'secondary' }));
    return Screen({ title: 'Verified Calling', back: '/home', nav: 'home', children: [
      Section('Your caller card',
        CallerCard({ name: s.identity.realName, sub: Util.formatMobile(s.account.mobile), badge: StatusBadge(sum.status, sum.label) }),
        h('p', { class: 'hint section' }, 'This is how BharathLink plans to present you on a call once network-level caller verification exists. Nothing is shared with anyone yet.')),
      Section('Call a number', form, result),
      Section('Sample contacts', h('ul', { class: 'list' }, Directory.all().map(c => ListRow({
        href: `/call/${c.id}`, avatar: Avatar(c.realName), title: c.realName, sub: `${c.city}, @${c.handle}`,
        trail: StatusBadge(VStatus.DEMO, 'Sample') }))))] });
  },

  callDetail(id) {
    const c = Directory.byId(id);
    if (!c) return Views.notFound('/calls');
    return Screen({ title: 'Caller identity', back: '/calls', children: [
      CallerCard({ name: c.realName, sub: `@${c.handle}`, badge: StatusBadge(VStatus.DEMO, 'Sample contact') }),
      h('dl', { class: 'kv paycard section' },
        KvRow('Real name', [c.realName, h('span', { class: 'hint' }, 'Sample data, not verified')]),
        KvRow('Mobile number', 'Hidden for sample contacts'),
        KvRow('Trust state', StatusBadge(VStatus.DEMO))),
      h('div', { class: 'stack section' },
        Button('Call', { icon: 'phone', disabled: true }),
        h('p', { class: 'hint' }, 'Sample contacts have no real phone number, so calling is turned off.'),
        Button('Send a message', { variant: 'secondary', icon: 'chat', onClick: () => Router.go(`/chat/${Messaging.openWith(c.id)}`) })),
      h('div', { class: 'section' }, Notice('info', 'BharathLink does not verify callers at the telecom network level yet. When it does, this card will show the identity confirmed by the network.'))] });
  },

  /* ----- Verified Messaging ----- */
  chats() {
    const convs = Messaging.list();
    return Screen({ title: 'Messages', back: '/home', nav: 'chats',
      actions: [IconButton('plus', 'New message', () => Router.go('/chats/new'))], children: [
      Notice('warn', 'Messages stay on this device. They are not sent to anyone and are not end-to-end encrypted.'),
      convs.length
        ? h('ul', { class: 'list' }, convs.map(cv => {
            const c = Directory.byId(cv.contactId) || { realName: 'Unknown' };
            const last = cv.messages[cv.messages.length - 1];
            return ListRow({ href: `/chat/${cv.id}`, avatar: Avatar(c.realName),
              title: [c.realName, StatusBadge(VStatus.DEMO, 'Sample')],
              sub: last ? last.text : 'No messages yet', trail: last ? Util.time(last.at) : null });
          }))
        : h('div', { class: 'empty' }, h('p', null, 'No conversations yet. Start one with a sample contact.'),
            Button('New message', { icon: 'plus', onClick: () => Router.go('/chats/new') }))] });
  },

  chatsNew() {
    const err = ErrorText('find-err');
    const input = h('input', { class: 'input', id: 'find', type: 'text', autocomplete: 'off', autocapitalize: 'none',
      spellcheck: 'false', maxlength: '64', placeholder: '@name.abcd', 'aria-describedby': 'find-err' });
    const form = h('form', { novalidate: 'novalidate', onSubmit: e => {
      e.preventDefault(); setError(err, input, '');
      const c = Directory.byHandle(input.value);
      if (!c) return setError(err, input, 'No BharathLink member with that Messaging ID was found on this device.');
      Router.go(`/chat/${Messaging.openWith(c.id)}`, { replace: true });
    } }, Field({ id: 'find', label: 'Messaging ID', input, error: err }), Button('Start conversation', { type: 'submit', variant: 'secondary' }));
    return Screen({ title: 'New message', back: '/chats', children: [
      form,
      Section('Sample contacts', h('p', { class: 'hint' }, 'Both Ravi Kumars have different IDs: the same name never means the same identity.'),
        h('ul', { class: 'list section' }, Directory.all().map(c => ListRow({
          avatar: Avatar(c.realName), title: c.realName, sub: `@${c.handle}, ${c.city}`,
          onClick: () => Router.go(`/chat/${Messaging.openWith(c.id)}`, { replace: true }) }))))] });
  },

  chat(id) {
    const cv = Messaging.get(id);
    const c = cv && Directory.byId(cv.contactId);
    if (!cv || !c) return Views.notFound('/chats');
    const bubble = m => h('div', { class: 'bubble' }, m.text,
      h('span', { class: 'bubble__meta' }, `${Util.time(m.at)}, saved on device`));
    const empty = h('p', { class: 'hint', hidden: cv.messages.length > 0 }, 'No messages yet.');
    const list = h('div', { class: 'messages', 'aria-label': 'Messages', role: 'log' }, cv.messages.map(bubble));
    const err = ErrorText('chat-err');
    const box = h('textarea', { class: 'input', id: 'composer', rows: '1', maxlength: String(CONFIG.LIMITS.chatText),
      placeholder: 'Write a message', 'aria-label': 'Message', 'aria-describedby': 'chat-err' });
    box.addEventListener('input', () => { box.style.height = 'auto'; box.style.height = `${Math.min(box.scrollHeight, 140)}px`; });
    const composer = h('form', { class: 'composer', novalidate: 'novalidate', onSubmit: async e => {
      e.preventDefault(); err.textContent = '';
      const v = Validate.text(box.value, CONFIG.LIMITS.chatText, 'message');
      if (!v.ok) { err.textContent = v.error; return; }
      const m = await Messaging.send(id, v.value);
      empty.hidden = true;
      list.appendChild(bubble(m)); box.value = ''; box.style.height = 'auto'; box.focus();
      list.lastChild.scrollIntoView({ block: 'end' });
    } }, box, h('button', { class: 'sendbtn', type: 'submit', 'aria-label': 'Send message' }, Icon('send', 22)));
    const node = Screen({ title: c.realName, back: '/chats',
      actions: [IconButton('phone', `Call ${c.realName}`, () => Router.go(`/call/${c.id}`))],
      footer: composer, children: [
        h('div', { class: 'chat-meta' }, StatusBadge(VStatus.DEMO, 'Sample contact'), h('span', null, `@${c.handle}, ${c.city}`)),
        Notice('warn', E2EE.isActive() ? 'End-to-end encrypted.' : 'Not end-to-end encrypted. Messages are saved only on this device and are not delivered.'),
        err, empty, list] });
    setTimeout(() => { if (list.lastChild) list.lastChild.scrollIntoView({ block: 'end' }); }, 0);
    return node;
  },

  /* ----- BharatMail ----- */
  mail() {
    const s = Store.state, folder = Mail.folder;
    const seg = (key, label) => h('button', { type: 'button', 'aria-pressed': String(folder === key),
      onClick: () => { Mail.folder = key; App.refresh(); } }, label);
    const items = Mail.list(folder);
    return Screen({ title: 'BharatMail', back: '/home', nav: 'mail', children: [
      IdBlock('Your BharatMail ID', s.ids.mailId, 'mail'),
      Notice('warn', 'Provisional address. BharatMail can\u2019t send to or receive from other email services yet.'),
      h('div', { class: 'segmented', role: 'group', 'aria-label': 'Folder' }, seg('inbox', 'Inbox'), seg('sent', 'Sent')),
      items.length
        ? h('ul', { class: 'list' }, items.map(m => ListRow({ href: `/mail/${m.id}`,
            title: folder === 'inbox' ? m.from : breakable(`To ${m.to}`), sub: m.subject,
            trail: folder === 'sent' ? ToneBadge('none', 'Not delivered') : Util.time(m.at) })))
        : h('div', { class: 'empty' }, h('p', null, folder === 'sent' ? 'Nothing in Sent yet. Mail you write is saved here.' : 'Your inbox is empty.')),
      h('div', { class: 'section' }, LinkButton('Compose', '#/mail/compose', { icon: 'edit' }))] });
  },

  mailCompose() {
    const s = Store.state;
    const mk = (id, extra) => h('input', Object.assign({ class: 'input', id, type: 'text', 'aria-describedby': `${id}-err` }, extra));
    const to = mk('to', { type: 'email', autocomplete: 'email', autocapitalize: 'none', spellcheck: 'false', maxlength: '254' });
    const subject = mk('subject', { maxlength: String(CONFIG.LIMITS.mailSubject) });
    const body = h('textarea', { class: 'input', id: 'body', rows: '8', maxlength: String(CONFIG.LIMITS.mailBody), 'aria-describedby': 'body-err' });
    const eTo = ErrorText('to-err'), eSub = ErrorText('subject-err'), eBody = ErrorText('body-err');
    const form = h('form', { novalidate: 'novalidate', onSubmit: async e => {
      e.preventDefault();
      [[eTo, to], [eSub, subject], [eBody, body]].forEach(([er, i]) => setError(er, i, ''));
      const vTo = Validate.email(to.value), vSub = Validate.text(subject.value, CONFIG.LIMITS.mailSubject, 'subject'),
        vBody = Validate.text(body.value, CONFIG.LIMITS.mailBody, 'message');
      if (!vBody.ok) setError(eBody, body, vBody.error);
      if (!vSub.ok) setError(eSub, subject, vSub.error);
      if (!vTo.ok) setError(eTo, to, vTo.error);
      if (!vTo.ok || !vSub.ok || !vBody.ok) return;
      await Mail.send({ to: vTo.value, subject: vSub.value, body: vBody.value });
      Mail.folder = 'sent';
      Toast.show('Saved to Sent. Not delivered: mail delivery isn\u2019t connected yet.');
      Router.go('/mail', { replace: true });
    } },
      Field({ id: 'from', label: 'From', input: h('input', { class: 'input', id: 'from', type: 'text', readonly: 'readonly', value: s.ids.mailId }) }),
      Field({ id: 'to', label: 'To', input: to, error: eTo }),
      Field({ id: 'subject', label: 'Subject', input: subject, error: eSub }),
      Field({ id: 'body', label: 'Message', input: body, error: eBody }),
      Notice('warn', 'Delivery isn\u2019t connected. Your message will be saved in Sent on this device and won\u2019t reach the recipient.'),
      Button('Save to Sent', { type: 'submit' }));
    return Screen({ title: 'New mail', back: '/mail', children: [form] });
  },

  mailMessage(id) {
    const m = Mail.get(id);
    if (!m) return Views.notFound('/mail');
    return Screen({ title: m.folder === 'sent' ? 'Sent mail' : 'Inbox', back: '/mail', children: [
      h('h2', { class: 'mailview__subject' }, m.subject),
      h('dl', { class: 'kv paycard' },
        KvRow('From', m.from), KvRow('To', m.to), KvRow('Time', Util.dateTime(m.at)),
        m.folder === 'sent' ? KvRow('Delivery', ToneBadge('none', 'Not delivered')) : null),
      h('div', { class: 'mailview__body' }, m.body)] });
  },

  /* ----- UPI / Verified Payment ----- */
  pay() {
    const reqs = Payments.list(), sum = Verification.summary(Store.state);
    const step = (title, badge, text) => h('li', null, h('div', { class: 'steps__body' },
      h('span', { class: 'steps__title' }, title), badge, h('span', { class: 'hint' }, text)));
    return Screen({ title: 'UPI / Verified Payment', back: '/home', nav: 'pay', children: [
      h('p', { class: 'lede' }, 'You pay in your own UPI app. BharathLink prepares the request and shows what it knows about who you\u2019re paying.'),
      Section('How a payment works',
        h('ol', { class: 'steps' },
          step('Your identity', StatusBadge(sum.status, sum.label), 'Your trust card is attached to the request.'),
          step('Payment request', ToneBadge('verified', 'Available'), 'Enter a UPI ID and amount.'),
          step('Beneficiary trust', StatusBadge(VStatus.NOT_CHECKED, 'Not connected'), 'Checking who owns a UPI ID needs an authorised provider.'),
          step('UPI authorisation', ToneBadge('none', 'In your UPI app'), 'You approve with your UPI PIN in your own app. BharathLink never sees it.'),
          step('Verified result', StatusBadge(VStatus.NOT_CHECKED, 'Not connected'), 'Confirmation needs a server link to your bank or payment provider.'))),
      h('div', { class: 'section' }, LinkButton('New payment request', '#/pay/new', { icon: 'plus' })),
      reqs.length ? Section('Your requests', h('ul', { class: 'list' }, reqs.map(r => ListRow({
        href: `/pay/${r.id}`, title: Util.rupees(r.amount), sub: `To ${r.payeeVpa}`,
        trail: ToneBadge(PayStatusMeta[r.status].tone, PayStatusMeta[r.status].label) })))) : null] });
  },

  payNew() {
    const mk = (id, label, extra, hint) => {
      const input = h('input', Object.assign({ class: 'input', id, type: 'text', 'aria-describedby': `${id}-err` }, extra));
      const err = ErrorText(`${id}-err`);
      return { input, err, field: Field({ id, label, input, error: err, hint }) };
    };
    const vpa = mk('vpa', 'Payee UPI ID', { autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', maxlength: '256', placeholder: 'name@bank' });
    const name = mk('payee', 'Payee name (optional)', { autocomplete: 'off', maxlength: '60' }, 'As you know them. This is not checked.');
    const amt = mk('amount', 'Amount in rupees', { inputmode: 'decimal', autocomplete: 'off', maxlength: '9', placeholder: '0.00' });
    const note = mk('note', 'Note (optional)', { autocomplete: 'off', maxlength: String(CONFIG.LIMITS.payNote) });
    const form = h('form', { novalidate: 'novalidate', onSubmit: e => {
      e.preventDefault(); [vpa, name, amt, note].forEach(f => setError(f.err, f.input, ''));
      const vV = Validate.vpa(vpa.input.value), vA = Validate.amount(amt.input.value);
      const vN = name.input.value.trim() ? Validate.realName(name.input.value) : { ok: true, value: '' };
      const vT = Validate.text(note.input.value.replace(/\n/g, ' '), CONFIG.LIMITS.payNote, 'note', { required: false });
      if (!vT.ok) setError(note.err, note.input, vT.error);
      if (!vA.ok) setError(amt.err, amt.input, vA.error);
      if (!vN.ok) setError(name.err, name.input, vN.error);
      if (!vV.ok) setError(vpa.err, vpa.input, vV.error);
      if (!vV.ok || !vA.ok || !vN.ok || !vT.ok) return;
      const id = Payments.create({ payeeVpa: vV.value, payeeName: vN.value, amount: vA.value, note: vT.value });
      Router.go(`/pay/${id}`, { replace: true });
    } }, vpa.field, name.field, amt.field, note.field, Button('Review request', { type: 'submit' }));
    return Screen({ title: 'New payment request', back: '/pay', children: [form] });
  },

  payRequest(id) {
    const r = Payments.get(id);
    if (!r) return Views.notFound('/pay');
    const meta = PayStatusMeta[r.status];
    const reported = r.status === PayStatus.CLIENT_SUCCESS || r.status === PayStatus.CLIENT_FAILURE;
    const report = status => () => { Payments.setStatus(r.id, status); App.refresh(); };
    return Screen({ title: 'Payment request', back: '/pay', children: [
      h('div', { class: 'paycard' },
        h('p', { class: 'hint' }, 'Amount'), h('p', { class: 'amount' }, Util.rupees(r.amount)),
        h('dl', { class: 'kv' },
          KvRow('To UPI ID', r.payeeVpa),
          r.payeeName ? KvRow('Name you entered', r.payeeName) : null,
          r.note ? KvRow('Note', r.note) : null)),
      Section('Beneficiary trust', StatusBadge(VStatus.NOT_CHECKED),
        h('p', { class: 'hint section' }, 'BharathLink can\u2019t yet confirm who owns this UPI ID. Your UPI app will show the registered name. Check it before you approve.')),
      Section('Pay in your UPI app',
        LinkButton('Open UPI app', Payments.upiLink(r), { icon: 'rupee', onClick: () => {
          if (r.status === PayStatus.CREATED) setTimeout(() => { Payments.setStatus(r.id, PayStatus.HANDED_OFF); App.refresh(); }, 300);
        } }),
        h('p', { class: 'hint section' }, 'Works on a phone with a UPI app installed. Opening the app does not mean money was sent.'),
        r.status === PayStatus.CREATED ? Button('I\u2019ve opened my UPI app', { variant: 'ghost', onClick: report(PayStatus.HANDED_OFF) }) : null),
      Section('Result',
        h('dl', { class: 'kv paycard' },
          KvRow('Status', ToneBadge(meta.tone, meta.label)),
          KvRow('Server verification', StatusBadge(VStatus.NOT_CHECKED, 'Not available in this build'))),
        r.status !== PayStatus.CREATED ? h('div', { class: 'stack section' },
          h('p', { class: 'hint' }, reported
            ? 'Reported by you. Not confirmed by your bank, NPCI or BharathLink. Check your UPI app or bank statement for the real result.'
            : 'What did your UPI app show? Your answer is recorded as your own report only.'),
          h('div', { class: 'btn-row' },
            Button('It showed paid', { variant: 'secondary', disabled: r.status === PayStatus.CLIENT_SUCCESS, onClick: report(PayStatus.CLIENT_SUCCESS) }),
            Button('It failed', { variant: 'secondary', disabled: r.status === PayStatus.CLIENT_FAILURE, onClick: report(PayStatus.CLIENT_FAILURE) }))) : null)] });
  },

  notFound(back) {
    return Screen({ title: 'Not found', back, children: [h('div', { class: 'empty' }, h('p', null, 'This item doesn\u2019t exist on this device.'),
      Button('Go back', { onClick: () => Router.go(back, { replace: true }) }))] });
  }
};

/* =====================================================================
   16. ROUTER (hash-based, so browser and Android back work)
   Each route declares the onboarding stage it belongs to; the guard in
   App.render redirects to the right screen for the account's stage.
   ===================================================================== */
const ROUTES = [
  { re: /^\/welcome$/,           stage: 'auth',    view: () => Views.welcome() },
  { re: /^\/mobile$/,            stage: 'auth',    view: () => Views.mobile() },
  { re: /^\/otp$/,               stage: 'auth',    view: () => Views.otp() },
  { re: /^\/setup$/,             stage: 'setup',   view: () => Views.setup() },
  { re: /^\/onboard\/identity$/, stage: 'onboard', view: () => Views.onboardIdentity() },
  { re: /^\/onboard\/ids$/,      stage: 'onboard', view: () => Views.onboardIds() },
  { re: /^\/home$/,              stage: 'app',     view: () => Views.home() },
  { re: /^\/identity$/,          stage: 'app',     view: () => Views.identity() },
  { re: /^\/calls$/,             stage: 'app',     view: () => Views.calls() },
  { re: /^\/call\/([\w-]+)$/,    stage: 'app',     view: id => Views.callDetail(id) },
  { re: /^\/chats$/,             stage: 'app',     view: () => Views.chats() },
  { re: /^\/chats\/new$/,        stage: 'app',     view: () => Views.chatsNew() },
  { re: /^\/chat\/([\w-]+)$/,    stage: 'app',     view: id => Views.chat(id) },
  { re: /^\/mail$/,              stage: 'app',     view: () => Views.mail() },
  { re: /^\/mail\/compose$/,     stage: 'app',     view: () => Views.mailCompose() },
  { re: /^\/mail\/([\w-]+)$/,    stage: 'app',     view: id => Views.mailMessage(id) },
  { re: /^\/pay$/,               stage: 'app',     view: () => Views.pay() },
  { re: /^\/pay\/new$/,          stage: 'app',     view: () => Views.payNew() },
  { re: /^\/pay\/([\w-]+)$/,     stage: 'app',     view: id => Views.payRequest(id) }
];

const Router = {
  stack: [], replacing: false,
  current() { return location.hash.replace(/^#/, ''); },
  go(path, { replace = false } = {}) {
    if (this.current() === path) { App.render(); return; }
    this.replacing = replace;
    if (replace) location.replace(`#${path}`); else location.hash = path;
  },
  back(fallback) {
    if (this.stack.length > 1) history.back();
    else this.go(fallback, { replace: true });
  },
  onChange() {
    const p = this.current();
    if (this.replacing) { this.stack[Math.max(0, this.stack.length - 1)] = p; this.replacing = false; }
    else if (this.stack.length > 1 && this.stack[this.stack.length - 2] === p) this.stack.pop();
    else if (this.stack[this.stack.length - 1] !== p) this.stack.push(p);
    App.render();
  }
};

/* =====================================================================
   17. APP (boot + render loop)
   ===================================================================== */
const App = {
  root: null,
  stage() {
    const s = Store.state;
    if (!s.account) return 'auth';
    if (!s.identity) return 'setup';
    if (!s.onboarding.complete) return 'onboard';
    return 'app';
  },
  defaultRoute() {
    return { auth: '/welcome', setup: '/setup', onboard: Store.state.ids ? '/onboard/ids' : '/onboard/identity', app: '/home' }[this.stage()];
  },
  render({ soft = false } = {}) {
    Lifecycle.run();
    const path = Router.current(), stage = this.stage();
    const route = ROUTES.find(r => r.re.test(path));
    if (!route || route.stage !== stage) return Router.go(this.defaultRoute(), { replace: true });
    if (path === '/otp' && !Auth.pending) return Router.go('/mobile', { replace: true });
    const scrollY = window.scrollY;
    this.root.replaceChildren(route.view(...path.match(route.re).slice(1)));
    if (soft) { window.scrollTo(0, scrollY); return; }
    window.scrollTo(0, 0);
    const title = document.getElementById('screen-title');
    if (title) title.focus({ preventScroll: true });
    document.title = title ? `${title.textContent} | BharathLink` : 'BharathLink';
  },
  refresh() { this.render({ soft: true }); },
  init() {
    this.root = document.getElementById('app');
    Toast.el = document.getElementById('toast');
    Store.init();
    window.addEventListener('hashchange', () => Router.onChange());
    // Optional hooks for local testing only (open index.html?devtools=1). They expose no secrets
    // and go through the same guards as the UI, so they cannot create a "verified" state.
    if (new URLSearchParams(location.search).has('devtools')) {
      window.BharathLinkDev = Object.freeze({
        Validate, slug: n => LocalIdAllocator.slug(n),
        allocate: (accountId, realName, taken = []) => LocalIdAllocator.allocate({ accountId, realName, taken: new Set(taken) }),
        tryForceVerified: kind => Verification.record(kind, { status: VStatus.VERIFIED }, { id: 'rogue', authoritative: true }),
        tryForcePaymentVerified: id => Payments.setStatus(id, PayStatus.SERVER_VERIFIED, { attestation: { fake: true } }),
        snapshot: () => JSON.parse(JSON.stringify(Store.state))
      });
    }
    if (!Router.current()) Router.go(this.defaultRoute(), { replace: true });
    else { Router.stack = [Router.current()]; this.render(); }
  }
};

document.addEventListener('DOMContentLoaded', () => App.init());
})();
