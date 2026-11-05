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
  const VERSION = 'bharathmail-trust-local-v6-2026-11-05';
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
    // Reject header injection and ambiguous multiple sender addresses.
    if (/[\r\n\0]/.test(input) || (input.match(/<[^<>]*>/g)||[]).length>1) {
      return {address:'',domain:'',displayName:'',valid:false};
    }
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
    // Both the plain and HTML alternatives are already bounded. Examine
    // their combined text, not only the first 12 KB of the plain version.
    const urls = safeText(value, MAX_BODY + MAX_HTML + MAX_SUBJECT + 32)
      .match(/https?:\/\/[^\s<>"']+/gi) || [];
    const sample = urls.length > 24
      ? [...urls.slice(0, 12), ...urls.slice(-12)] : urls;
    return sample.map(s => s.replace(/[),.;!?]+$/g, '')).filter(Boolean);
  }
  // Risk analysis is deliberately bounded. A sender may hide malicious text
  // beyond the first 12 KB; sampling both ends is a mitigation, not a claim
  // that all content has been checked.
  const MAX_HTML = 48000;
  function boundedSample(value, limit) {
    if (typeof value !== 'string') return '';
    if (value.length <= limit) return value;
    const half = Math.floor(limit / 2);
    return value.slice(0, half) + '\n' + value.slice(-half);
  }
  function decodeHtmlEntities(value) {
    return value.replace(/&(#x[0-9a-f]{1,6}|#[0-9]{1,7}|amp|quot|apos|lt|gt|colon|sol);/gi, (_, entity) => {
      const e = entity.toLowerCase();
      const named = {amp:'&',quot:'"',apos:"'",lt:'<',gt:'>',colon:':',sol:'/'};
      if (Object.hasOwn(named, e)) return named[e];
      let point = e.startsWith('#x') ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      // Do not inject unpaired surrogate or control characters into the result.
      return point >= 32 && point <= 0x10ffff &&
        !(point >= 0xd800 && point <= 0xdfff)
        ? String.fromCodePoint(point) : '';
    });
  }
  function htmlSignals(value) {
    if (typeof value !== 'string' || value.length === 0) {
      return {text:'',links:[],partial:false,unparsed:false};
    }
    const limited = boundedSample(value, MAX_HTML);
    const links = [];
    let anchors = 0, unparsed = false;
    // Parse *only* the href of conventional anchors for caution signals.
    // This intentionally is not a security HTML parser; malformed/complex
    // markup is unreviewed, never claimed clean or executed in a DOM.
    const anchorRx = /<a\b([^>]{0,2048})>([\s\S]{0,2048}?)<\/a\s*>/gi;
    let match;
    while ((match = anchorRx.exec(limited)) !== null) {
      anchors++;
      if (anchors > 16) { unparsed = true; break; }
      const attrs = match[1];
      const href = attrs.match(/\bhref\s*=\s*(?:"([^"]{0,2048})"|'([^']{0,2048})'|([^\s>'"]{1,2048}))/i);
      if (!href) { unparsed = true; continue; }
      const target = decodeHtmlEntities((href[1] ?? href[2] ?? href[3]).trim());
      const label = decodeHtmlEntities(match[2].replace(/<[^>]*>/g, ' ').trim());
      links.push({target, label});
    }
    // Some malformed anchors may coexist with parseable ones. Never imply
    // we inspected all HTML links when not every <a> was recognized.
    if ((limited.match(/<a\b/gi) || []).length > anchors) unparsed = true;
    const stripped = limited
      .replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, ' ')
      .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, ' ')
      .replace(/<[^>]*>/g, ' ');
    return {
      text:decodeHtmlEntities(stripped),
      links,
      partial:value.length > MAX_HTML,
      unparsed
    };
  }
  function parsedWebUrl(value) {
    try {
      const candidate = value.startsWith('//') ? 'https:' + value : value;
      const url = new URL(candidate);
      if (!['https:', 'http:'].includes(url.protocol) || !url.hostname) return null;
      return url;
    } catch (_) { return null; }
  }
  function comparableHost(host) {
    return String(host || '').toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
  }
  const REDIRECT_KEYS = new Set([
    'url','redirect','redirect_url','redirect_uri','next','continue',
    'return','return_url','target','dest','destination','to'
  ]);
  function inspectUrl(value, reasons) {
    const raw = decodeHtmlEntities(value.trim());
    const low = raw.toLowerCase();
    if(raw.length>4096) {
      add(reasons,'INCOMPLETE_LINK_SCAN','medium','This link is too long for the local inspection limit.');
      return;
    }
    if (/^(?:javascript|data|file|vbscript|blob):/.test(low)) {
      add(reasons, 'UNSAFE_HTML_LINK', 'high', 'An HTML link uses an unsafe or non-web destination scheme.');
      return;
    }
    const url = parsedWebUrl(raw);
    if (!url) {
      add(reasons, 'UNUSUAL_LINK', 'medium', 'One of the links has an unusual structure.');
      return;
    }
    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    if (url.protocol === 'http:') {
      add(reasons, 'INSECURE_LINK', 'medium', 'An email link does not use HTTPS.');
    }
    if (url.username || url.password || host.includes('xn--') ||
        /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes('[')) {
      add(reasons, 'DISGUISED_LINK', 'high', 'A link contains a disguised account/domain form or IP-style destination.');
    }
    if (SHORTENER.has(host)) {
      add(reasons, 'SHORTENED_LINK', 'medium', 'A shortened link hides the destination until opened.');
    }
    // Never follow, download or DNS-resolve URLs from an email. Legitimate
    // redirects also exist; this is caution, not a fraud determination.
    let count=0;
    for(const [key,value] of url.searchParams){
      if(++count>32){
        add(reasons,'INCOMPLETE_LINK_SCAN','medium','Some URL parameters were not inspected.');
        break;
      }
      if(!REDIRECT_KEYS.has(key.toLowerCase()))continue;
      const dest=decodeHtmlEntities(value.trim());
      if(/^(?:javascript|data|file|vbscript|blob):/i.test(dest)){
        add(reasons,'UNSAFE_REDIRECT_PARAMETER','high','A redirect parameter references a non-web URL scheme.');
        continue;
      }
      const next=parsedWebUrl(dest);
      if(next && comparableHost(next.hostname)!==comparableHost(host))
        add(reasons,'CROSS_DOMAIN_REDIRECT_PARAMETER','medium',
          'A redirect parameter points to a different domain. Destination not visited.');
    }
  }
  function bilingualSignals(text,header){
    // Only bounded local caution. No email is verified or deemed safe.
    const content=text.normalize('NFKC').replace(/[\u200b-\u200d\u2060\ufeff]/g,'');
    const official=/(?:\b(?:sarkari|sarkar|cyber[ -]?crime|police|bank)\b|पुलिस|बैंक|साइबर\s*क्राइम|सरकार|सरकारी|आयकर\s*विभाग)/iu.test(header.normalize('NFKC'));
    const secret=/(?:\b(?:otp|cvv|pin|password|passcode)\b|ओटीपी|पासवर्ड|सीवीवी|वेरिफिकेशन\s*कोड)/iu;
    const action=/(?:\b(?:bhejo|bhejna|bhej\s*do|batao|bata\s*do|dena|de\s*do|send\s*karo|share\s*karo)\b|भेजो|भेजें|भेजिए|भेजना|बताओ|बताएं|बताना|दीजिए|दे\s*दो|देना)/iu;
    const noSecret=/(?:\b(?:mat|nahi|nahin|never|don't|do\s*not)\b|मत|नहीं|ना)\s+(?:(?:[\p{L}\p{N}]+\s+){0,2})(?:bhejo|bhejna|batao|dena|भेजो|भेजें|भेजिए|भेजना|बताओ|देना)/iu;
    const payment=/(?:\b(?:paisa|paise|rupaye|rupiya|rupiye|money|payment)\s+(?:bhejo|bhejna|bhej\s*do|transfer|karo)\b|₹\s*\d+|पैसे|पैसा|रुपये|रुपया|रुपए|भुगतान)/iu;
    // Separate requesting money from a routine invoice or statement.
    // Both are still unverified; this is a bounded linguistic caution only.
    const amount=/(?:₹\s*[\d,]+(?:\.\d{1,2})?|\b\d[\d,]{0,11}(?:\.\d{1,2})?\s*(?:rs\.?|inr|rupees?|rupaye|rupiya|rupiye|रुपये|रुपए|रुपया)\b)/iu;
    const sendVerb=/(?:\b(?:send|bhejo|bhejna|bhej\s*do|chahiye|de\s*do|dena|dijiye|pay|transfer|jama\s*karo)\b|भेजो|भेजें|भेजिए|भेजना|भेज\s*दो|चाहिए|दे\s*दो|दीजिए|भुगतान\s*करो|ट्रांसफर\s*करो)/iu;
    const noPayment=/(?:\b(?:mat|nahi|nahin|don't|do\s*not|never)\b|मत|नहीं)\s+(?:(?:[\p{L}\p{M}\p{N}]+\s+){0,3})(?:bhejo|bhejna|pay|send|transfer|dena|de\s*do|भेजो|भेजें|भेजिए|भेजना|ट्रांसफर\s*करो|भुगतान\s*करो)/iu;
    const noPaymentAfter=/(?:\b(?:bhejo|bhejna|send|pay|transfer|dena)\s+(?:mat\b|nahi\b(?!\s+to\b)|nahin\b(?!\s+to\b))|(?:भेजो|भेजना|भेजें|भेजिए|देना)\s+(?:मत|नहीं(?!\s+तो)))/iu;
    const urgent=/(?:\b(?:turant|jaldi|abhi|fauran|aaj\s*hi|khata\s*band)\b|तुरंत|फ़ौरन|जल्दी|अभी|आज\s*ही|अंतिम\s*चेतावनी|डिजिटल\s*अरेस्ट|खाता\s*बंद)/iu.test(content);
    // Preserve comma-separated thousands and decimal amounts in the same clause.
    const parts=content.split(/[!?;\n।]+|,(?!\d)|\.(?!\d)/u);
    const affirmative=p=>!noPayment.test(p)&&!noPaymentAfter.test(p);
    const moneyRequest=parts.some(p=>amount.test(p)&&sendVerb.test(p)&&affirmative(p));
    return {official,urgent,moneyRequest,
      secret:parts.some(p=>secret.test(p)&&action.test(p)&&!noSecret.test(p)),
      pay:parts.some(p=>(payment.test(p)||amount.test(p)&&sendVerb.test(p))&&affirmative(p))};
  }


  // Reference list backed by public first-party pages, not a live issuer.
  // Domain equality cannot prove control of a sender's mailbox.
  const ORGS=Object.freeze([
    Object.freeze({key:'icici_bank',name:'ICICI Bank',refs:Object.freeze([
      Object.freeze({domain:'icici.bank.in',kind:'current'}),
      Object.freeze({domain:'icicibank.com',kind:'previously_published'})
    ]),sources:Object.freeze([
      'https://www.icici.bank.in/customer-care',
      'https://www.icici.bank.in/contact-us'
    ])}),
    Object.freeze({key:'reliance_industries',name:'Reliance Industries',refs:Object.freeze([
      Object.freeze({domain:'ril.com',kind:'corporate'})
    ]),sources:Object.freeze([
      'https://www.ril.com/fraud-alert',
      'https://www.ril.com/careers/search-apply/fraud-alert'
    ])})
  ]);
  const REFERENCE_REVIEWED='2026-11-05';
  function closeTo(label,word) {
    if(!label||label.length>48)return false;
    if(label===word||label.startsWith(word+'-'))return true;
    if(Math.abs(label.length-word.length)>1)return false;
    let i=0,j=0,edits=0;
    while(i<label.length&&j<word.length){
      if(label[i]===word[j]){i++;j++;continue;}
      if(++edits>1)return false;
      if(label.length>word.length)i++;
      else if(label.length<word.length)j++;
      else{i++;j++;}
    }
    return edits+label.length-i+word.length-j<=1;
  }
  function organizationReference(input) {
    const m=input&&typeof input==='object'?input:{};
    const p=sender(m.from),domain=p.valid?p.domain:'';
    const words=(p.displayName+' '+safeText(m.subject,MAX_SUBJECT)).normalize('NFKC');
    const icici=/\bicici(?:\s+bank)?\b/i.test(words),ril=/\b(?:reliance(?:\s+industries)?|ril)\b/i.test(words);
    const claim=icici!==ril?(icici?'icici_bank':'reliance_industries'):null;
    let exact=null,match=null;
    for(const org of ORGS){const r=org.refs.find(x=>x.domain===domain);if(r){exact=org;match=r;break;}}
    const subdomain=ORGS.find(org=>org.refs.some(x=>domain.endsWith('.'+x.domain)));
    const first=domain.split('.')[0]||'';
    const resembles=closeTo(first,'icici')||closeTo(first,'icicibank')?'icici_bank':
      closeTo(first,'reliance')||closeTo(first,'ril')?'reliance_industries':null;
    let status='not_listed',key=null,kind=null,listed=null;
    if(!p.valid)status='invalid_sender';
    else if(exact&&claim&&claim!==exact.key){status='brand_claim_mismatch';key=claim;}
    else if(exact){status='published_domain_reference';key=exact.key;kind=match.kind;listed=match.domain;}
    else if(subdomain){status='unlisted_subdomain';key=subdomain.key;}
    else if(resembles){status='possible_lookalike';key=resembles;}
    else if(claim){status='brand_claim_mismatch';key=claim;}
    const known=ORGS.find(x=>x.key===key);
    return Object.freeze({
      status,organizationKey:key,organization:known?known.name:null,
      listedDomain:listed,referenceKind:kind,reviewedOn:REFERENCE_REVIEWED,
      referenceSources:known?known.sources:Object.freeze([]),
      domainAuthentication:'not_checked',organizationVerification:'not_verified',
      senderMailboxAuthorization:'not_verified',individualRoleAuthorization:'not_verified',
      paymentBeneficiaryVerification:'not_verified',
      isSenderVerified:false,isOrganizationVerified:false,isFraudProven:false
    });
  }

  const REPORT_CODES=new Set(["AUTHORITY_CLAIM_PUBLIC_MAIL","CROSS_DOMAIN_REDIRECT_PARAMETER","DISGUISED_LINK","HTML_LINK_DESTINATION_MISMATCH","IDN_SENDER","INCOMPLETE_HTML_SCAN","INCOMPLETE_LINK_SCAN","INCOMPLETE_TEXT_SCAN","INSECURE_LINK","MALFORMED_FROM","ORG_REFERENCE_MISMATCH","ORG_REFERENCE_UNLISTED_SUBDOMAIN","PAYMENT_REQUEST","PAYMENT_SOLICITATION","POSSIBLE_LOOKALIKE_DOMAIN","REPLY_TO_DIFFERS","SECRET_REQUEST","SENSITIVE_LINK_REQUEST","SHORTENED_LINK","UNSAFE_HTML_LINK","UNSAFE_REDIRECT_PARAMETER","UNUSUAL_LINK","URGENT_PAYMENT"]);
  // Only signal codes. Never export sender, subject, raw reasons, email text,
  // recipient, URLs, JWT, identifiers or any caller-controlled free text.
  function redactedReport(r){
    if(!r||typeof r!=='object'||r.version!==VERSION||r.source!=='internet'||
       r.scanCoverage!=='bounded_heuristics_only'||
       !['suspicious','caution','unverified'].includes(r.status)||
       r.isVerified!==false||r.isFakeProven!==false||
       r.identityVerification!=='not_verified'||
       r.organizationAuthority!=='not_verified'||
       r.paymentRequestVerification!=='not_verified'||
       r.domainAuthentication!=='not_checked'||
       !Array.isArray(r.reasons)||r.reasons.length>8)
      throw Error('Untrusted or incompatible local scan result.');
    const codes=[];
    for(const item of r.reasons){
      if(!item||!REPORT_CODES.has(item.code)||
         !['high','medium','info'].includes(item.severity)||
         codes.includes(item.code))
        throw Error('Unknown security signal; report blocked.');
      codes.push(item.code);
    }
    return [
      'BHARATMAIL TEST — REDACTED LOCAL CAUTION REPORT',
      'Scanner: '+VERSION,
      'Result: '+r.status.toUpperCase(),
      'Warning codes: '+(codes.join(', ')||'NONE_DETECTED_IN_LIMITED_SCAN'),
      'Coverage: BOUNDED_HEURISTICS_ONLY',
      'Domain authentication: NOT CHECKED BY LOCAL SCAN',
      'Sender identity: NOT VERIFIED',
      'Organization authority: NOT VERIFIED',
      'Payment beneficiary: NOT VERIFIED',
      'Attachments and malware: NOT SCANNED',
      'Warnings do not prove fraud. No warning does not mean safe.',
      'No sender, subject, body, recipient, URLs, message IDs or tokens included.'
    ].join('\n');
  }
  function inspect(mail) {
    const m = (mail && typeof mail === 'object') ? mail : {};
    const external = String(m.source || '').toLowerCase() === 'external';
    const visibleSender = sender(m.from);
    const subject = safeText(m.subject, MAX_SUBJECT);
    const body = boundedSample(m.body, MAX_BODY);
    const html = external ? htmlSignals(m.html_body) : {text:'',links:[],partial:false,unparsed:false};
    const content = (subject + '\n' + body + '\n' + html.text).toLowerCase();
    const reasons = [];
    const org=organizationReference({from:m.from,subject});
    if(external&&['brand_claim_mismatch','possible_lookalike'].includes(org.status))
      add(reasons,'ORG_REFERENCE_MISMATCH','medium',
        'Sender domain does not match this published organization-domain reference. Spelling alone cannot prove fraud.');
    if(external&&org.status==='unlisted_subdomain')
      add(reasons,'ORG_REFERENCE_UNLISTED_SUBDOMAIN','medium',
        'Unlisted subdomain is not automatically an authorized company sender. Verify independently.');
    const local = bilingualSignals(content,visibleSender.displayName+' '+subject);
    if(external && local.official && visibleSender.valid && PUBLIC_INBOX.has(visibleSender.domain))
      add(reasons,'AUTHORITY_CLAIM_PUBLIC_MAIL','high','Public mailbox claims government, police or bank authority; verify independently.');
    if(external && local.secret)
      add(reasons,'SECRET_REQUEST','high','Email appears to request an OTP or password. Do not share secrets.');
    if(external && local.pay && local.urgent)
      add(reasons,'URGENT_PAYMENT','high','Urgency with a payment request: verify the beneficiary independently.');
    else if(external && local.moneyRequest)
      add(reasons,'PAYMENT_SOLICITATION','medium','This message asks for money. Verify the person and beneficiary independently before paying.');
    else if(external && local.pay)
      add(reasons,'PAYMENT_REQUEST','info','Money mentioned: verify the beneficiary independently.');
    if (external && (
      (typeof m.body === 'string' && m.body.length > MAX_BODY) ||
      (typeof m.subject === 'string' && m.subject.length > MAX_SUBJECT)
    )) {
      add(reasons, 'INCOMPLETE_TEXT_SCAN', 'medium', 'This message is longer than the local inspection limit. Unchecked content may contain further risks.');
    }
    if (external && (html.partial || html.unparsed)) {
      add(reasons, 'INCOMPLETE_HTML_SCAN', 'medium', 'Part of the HTML message or its links could not be inspected. Check destinations independently.');
    }
    if (external && !visibleSender.valid) {
      add(reasons, 'MALFORMED_FROM', 'high', 'The visible sender address could not be parsed as a normal email address.');
    }
    if (visibleSender.valid) {
      if (visibleSender.domain.includes('xn--')) {
        add(reasons, 'IDN_SENDER', 'medium', 'The sender domain uses internationalized/punycode notation. Check the exact spelling.');
      }
      // External storage currently keeps from_address without a reliable
      // original display name, so also inspect the untrusted subject claim.
      const claimText = visibleSender.displayName + ' ' + subject;
      const claim = /\b(bank|banking|police|cyber[ -]?crime|government|govt|income[ -]?tax|tax department|security team|helpdesk|customer care|upi|payment support)\b/i.test(claimText);
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
    // Evaluate independent clauses, not the whole email: a scammer must not
    // suppress "send OTP" simply by adding "never share OTP" elsewhere.
    const asksSecret = /\b(?:send|share|tell|provide|give|reply with|enter|submit|forward)\b.{0,45}\b(?:otp|one.time (?:code|password)|verification code|pin|cvv|password|passcode)\b|\b(?:otp|password|pin|cvv)\b.{0,35}\b(?:send|share|forward|provide)\b/i;
    const negatedSecret = /\b(?:do not|don't|never|avoid|mat|nahi|nahin)\s+(?:\w+\s+){0,3}(?:send|share|provide|give|forward)\b/i;
    const asksForSecret = content.split(/[.!?;\n]+/).some(clause =>
      asksSecret.test(clause) && !negatedSecret.test(clause));
    if (asksForSecret) {
      add(reasons, 'SECRET_REQUEST', 'high', 'The email appears to ask for a password, OTP, PIN or other secret.');
    }
    const urgency = /\b(?:urgent|immediately|last chance|act now|within \d+ (?:minutes?|hours?)|account (?:blocked|suspended)|final warning|arrest warrant|digital arrest|turant|jaldi|abhi)\b/i.test(content);
    const pay = /\b(?:send money|transfer money|pay now|make payment|upi|bank account|account number|send funds|pay the fee|wire transfer|payment required|refund processing fee)\b|₹\s*\d+/i.test(content);
    if (pay && urgency) {
      add(reasons, 'URGENT_PAYMENT', 'high', 'Urgency is combined with money-transfer or payment instructions.');
    } else if (pay) {
      add(reasons, 'PAYMENT_REQUEST', 'info', 'The email mentions a payment or destination; verify the beneficiary independently.');
    }
    if ((content.match(/https?:\/\/[^\s<>"']+/gi) || []).length > 24) {
      add(reasons, 'INCOMPLETE_LINK_SCAN', 'medium', 'This email contains more links than can be individually checked in the local preview.');
    }
    const urls = extractUrls(content);
    for (const value of urls) inspectUrl(value, reasons);
    // HTML href attributes may not appear in the plain-text alternative.
    // Analyze them as untrusted text without following links or rendering HTML.
    if (external) {
      for (const link of html.links) {
        // Mailto/phone links and same-document fragment anchors are common
        // in legitimate newsletters. They are not web page destinations.
        if (!/^(?:mailto:|tel:|#)/i.test(link.target.trim()))
          inspectUrl(link.target, reasons);
        const visible = extractUrls(link.label)[0];
        const bareText=decodeHtmlEntities(link.label.trim()).replace(/[),.;!?]+$/g,'');
        const bareDomain=/^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/[^\s]*)?$/i.test(bareText);
        const shown=visible ? parsedWebUrl(visible) :
          bareDomain ? parsedWebUrl('https://'+bareText) : null;
        const target=parsedWebUrl(decodeHtmlEntities(link.target.trim()));
        if (shown && target &&
          comparableHost(shown.hostname) !== comparableHost(target.hostname)) {
          add(reasons, 'HTML_LINK_DESTINATION_MISMATCH', 'high', 'A visible website address points to a different website when opened.');
        }
      }
    }
    if ((urls.length || html.links.length) && urgency && (pay || asksForSecret)) {
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
      // Prioritize severe signals; limited-size UI must not hide a malicious
      // HTML destination behind eight earlier low-priority warnings.
      reasons: Object.freeze(reasons.slice().sort((a,b) =>
        ({high:0,medium:1,info:2}[a.severity] ?? 3) -
        ({high:0,medium:1,info:2}[b.severity] ?? 3)
      ).slice(0, 8).map(x => Object.freeze(x))),
      advice: independentCheck,
      scanCoverage: 'bounded_heuristics_only',
      limitations: external
        ? 'SPF, DKIM and DMARC have not been independently authenticated by the receiving server. HTML scanning is limited and cannot guarantee link safety. A genuine email address can still send a scam.'
        : 'BharathMail routing does not prove legal identity, authority, or safety.',
      isVerified: false,
      isFakeProven: false
    });
  }
  return Object.freeze({VERSION, inspect, redactedReport, organizationReference});
});
