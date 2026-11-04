/* BharathLink Mail Trust Engine v1 — local, explainable, privacy preserving.
 * This component produces CAUTION signals only. It does NOT verify legal
 * identity, organizational authority, mailbox ownership, or SPF/DKIM/DMARC.
 * NEVER treat message-supplied Authentication-Results or booleans as trusted.
 * No network access, raw HTML injection, attachment execution, or model calls.
 */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.BharatMailTrustEngine = api;
})(typeof window !== 'undefined' ? window : null, function () {
  'use strict';
  const VERSION = 'bharathmail-trust-local-v1-2026-11-04';
  const MAX_SUBJECT = 300;
  const MAX_BODY = 12000;
  const PUBLIC_INBOX = new Set([
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'live.com', 'icloud.com', 'proton.me', 'protonmail.com', 'aol.com'
  ]);
  const SHORTENER = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy'
  ]);
  function safeText(value, limit) {
    return typeof value === 'string' ? value.slice(0, limit) : '';
  }
  function add(list, code, severity, reason) {
    if (!list.some(x => x.code === code)) list.push({code, severity, reason});
  }
  function sender(raw) {
    const input = safeText(raw, 320).trim();
    const bracketed = input.match(/<\s*([^<>]+)\s*>/);
    const address = (bracketed ? bracketed[1] : input).trim().toLowerCase();
    const displayName = bracketed ? input.slice(0, bracketed.index).replace(/["']/g, '').trim() : '';
    const matched = address.match(/^[a-z0-9.!#$%&'*+/=?^_\u0060{|}~-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)$/i);
    if (!matched || address.length > 254 || address.includes('..')) {
      return {address: '', domain: '', displayName, valid: false};
    }
    const domain = matched[1].toLowerCase();
    if (domain.split('.').some(label => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) {
      return {address: '', domain: '', displayName, valid: false};
    }
    return {address, domain, displayName, valid: true};
  }
  function extractUrls(value) {
    const urls = safeText(value, MAX_BODY).match(/https?:\/\/[^\s<>"']+/gi) || [];
    return urls.slice(0, 12).map(s => s.replace(/[),.;!?]+$/g, '')).filter(Boolean);
  }
  function inspect(mail) {
    const m = (mail && typeof mail === 'object') ? mail : {};
    const external = String(m.source || '').toLowerCase() === 'external';
    const visibleSender = sender(m.from);
    const subject = safeText(m.subject, MAX_SUBJECT);
    const body = safeText(m.body, MAX_BODY);
    const content = (subject + '\n' + body).toLowerCase();
    const reasons = [];
    if (external && !visibleSender.valid) {
      add(reasons, 'MALFORMED_FROM', 'high', 'The visible sender address could not be parsed as a normal email address.');
    }
    if (visibleSender.valid) {
      if (visibleSender.domain.includes('xn--')) {
        add(reasons, 'IDN_SENDER', 'medium', 'The sender domain uses internationalized/punycode notation. Check the exact spelling.');
      }
      const claim = /\b(bank|banking|fraud|police|cybercrime|government|govt|tax department|security team|helpdesk|customer care|upi|payment support)\b/i.test(visibleSender.displayName);
      if (external && claim && PUBLIC_INBOX.has(visibleSender.domain)) {
        add(reasons, 'AUTHORITY_CLAIM_PUBLIC_MAIL', 'high', 'The display name claims an organization or authority, but uses a public mailbox provider.');
      }
      const sensitiveSubdomain = /\b(?:login|verify|verification|secure|security|account-update|password-reset)\b/i.test(visibleSender.domain.replace(/[-.]/g, ' '));
      if (external && claim && sensitiveSubdomain && visibleSender.domain.includes('-')) {
        add(reasons, 'POSSIBLE_LOOKALIKE_DOMAIN', 'medium', 'The sender domain contains login/security-style words; verify it independently.');
      }
    }
    const reply = sender(m.reply_to || m.replyTo || '');
    if (external && visibleSender.valid && reply.valid && reply.domain !== visibleSender.domain) {
      add(reasons, 'REPLY_TO_DIFFERS', 'medium', 'The reply address uses a different domain from the visible sender.');
    }
    const asksForSecret = /\b(?:send|share|tell|provide|give|reply with|enter|submit|forward)\b.{0,45}\b(?:otp|one.time (?:code|password)|verification code|pin|cvv|password|passcode)\b|\b(?:otp|password|pin|cvv)\b.{0,35}\b(?:send|share|forward|provide)\b/i.test(content);
    const warnsNotToShare = /\b(?:do not|don't|never|avoid|mat|nahi|nahin)\s+(?:\w+\s+){0,3}(?:send|share|provide|give|forward)\b/i.test(content);
    if (asksForSecret && !warnsNotToShare) {
      add(reasons, 'SECRET_REQUEST', 'high', 'The email appears to ask for a password, OTP, PIN or other secret.');
    }
    const urgency = /\b(?:urgent|immediately|last chance|act now|within \d+ (?:minutes?|hours?)|account (?:blocked|suspended)|final warning|arrest warrant|digital arrest|turant|jaldi|abhi)\b/i.test(content);
    const pay = /\b(?:send money|transfer money|pay now|make payment|upi|bank account|account number|send funds|pay the fee|wire transfer|payment required|refund processing fee)\b|₹\s*\d+/i.test(content);
    if (pay && urgency) {
      add(reasons, 'URGENT_PAYMENT', 'high', 'Urgency is combined with money-transfer or payment instructions.');
    } else if (pay) {
      add(reasons, 'PAYMENT_REQUEST', 'info', 'The email mentions a payment or destination; verify the beneficiary independently.');
    }
    const urls = extractUrls(content);
    for (const value of urls) {
      let url;
      try { url = new URL(value); } catch (_) {
        add(reasons, 'UNUSUAL_LINK', 'medium', 'One of the links has an unusual structure.');
        continue;
      }
      const host = url.hostname.toLowerCase().replace(/\.$/, '');
      if (url.protocol === 'http:') {
        add(reasons, 'INSECURE_LINK', 'medium', 'An email link does not use HTTPS.');
      }
      if (url.username || url.password || host.includes('xn--') || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
        add(reasons, 'DISGUISED_LINK', 'high', 'A link contains a disguised account/domain form or IP-style destination.');
      }
      if (SHORTENER.has(host)) {
        add(reasons, 'SHORTENED_LINK', 'medium', 'A shortened link hides the destination until opened.');
      }
    }
    if (urls.length && urgency && (pay || asksForSecret)) {
      add(reasons, 'SENSITIVE_LINK_REQUEST', 'medium', 'A link is combined with urgent payment or credential language.');
    }
    // No outgoing client/network request or DNS lookup is performed. Do not infer
    // an authoritative email authentication pass from an email's own headers.
    // The existing external-message table does not expose a verified, server-
    // computed SPF/DKIM/DMARC result nor trusted organization authorization.
    const high = reasons.some(x => x.severity === 'high');
    const medium = reasons.some(x => x.severity === 'medium');
    const status = high ? 'suspicious' : medium ? 'caution' : 'unverified';
    const label = status === 'suspicious' ? 'Suspicious · verify before acting'
      : status === 'caution' ? 'Check sender and links' : 'Sender not verified';
    const independentCheck = 'Check the sender, organization, and any payment destination through an independently known official channel.';
    return Object.freeze({
      version: VERSION,
      status,
      label,
      source: external ? 'internet' : 'bharathmail',
      addressValid: visibleSender.valid,
      domain: visibleSender.domain,
      domainAuthentication: external ? 'not_checked' : 'not_applicable',
      identityVerification: 'not_verified',
      organizationAuthority: 'not_verified',
      paymentRequestVerification: 'not_verified',
      reasons: Object.freeze(reasons.slice(0, 8).map(x => Object.freeze(x))),
      advice: independentCheck,
      limitations: external
        ? 'SPF, DKIM and DMARC have not been independently authenticated by the receiving server. A genuine email address can still send a scam.'
        : 'BharathMail routing does not prove legal identity, authority, or safety.',
      isVerified: false,
      isFakeProven: false
    });
  }
  return Object.freeze({VERSION, inspect});
});
