/* BharatLink Security Shield · TEST v1 (offline-only heuristic checks).
   No third-party chat access, no background monitoring, no server upload,
   no identity attestation and no claim that a website is safe or fraudulent.
*/
(function(root) {
  'use strict';
  const base=(level,title,reasons,actions,detail={})=>
    Object.assign({level,title,reasons,actions,verified:false,networkChecked:false},detail);
  function inspectUrl(value) {
    if(typeof value!=='string'||!value.trim())
      return base('unknown','Enter a link',['No website link provided.'],['Paste an HTTP or HTTPS link.']);
    const raw=value.trim();
    if(raw.length>2048||/[\x00-\x1f]/.test(raw))
      return base('unknown','Invalid link',['Input exceeds limits or contains control characters.'],['Ask for a valid link through an independent channel.']);
    const candidate=/^www\./i.test(raw)?'https://'+raw:raw;
    if(!/^https?:\/\//i.test(candidate))
      return base('high','Unrecognized scheme',['Only http:// and https:// web addresses are supported.'],['Do not execute unexpected app or script links.']);
    let url;
    try{url=new URL(candidate);}catch(_){
      return base('unknown','Invalid web address',['This URL cannot be parsed.'],['Confirm the exact site address independently.']);
    }
    const host=url.hostname.toLowerCase().replace(/\.$/,'');
    if(!host||!host.includes('.')||/\s/.test(host))
      return base('unknown','Unusual website address',['A conventional public hostname was not found.'],['Verify the destination separately.']);
    const reasons=[],actions=[];let level=0;
    const add=(risk,why,what)=>{level=Math.max(level,risk);reasons.push(why);if(what)actions.push(what);};
    if(url.username||url.password)add(3,'The address contains misleading text before @.','Do not enter any login details.');
    if(url.protocol==='http:')add(2,'HTTP does not encrypt the page connection.','Do not enter private information or payment details.');
    if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)||host.startsWith('['))
      add(2,'This link uses a numeric IP destination.','Confirm the official organization domain.');
    if(host.includes('xn--'))add(2,'Internationalized domain encoding needs extra review.','Carefully compare the entire domain with the official address.');
    if(/^(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at)$/.test(host))
      add(2,'The link is shortened and its final destination is not known here.','Ask for the full destination first.');
    if(url.port&&!['80','443'].includes(url.port))
      add(2,'This site uses an unusual web port.','Verify the exact site through an independent source.');
    if(/\.(apk|exe|msi|bat|scr|cmd)$/i.test(url.pathname))
      add(3,'The link appears to download executable or installable software.','Do not install unexpected software.');
    if(host.split('.').length>5)
      add(1,'Many subdomains can make the true domain hard to spot.','Read the complete hostname carefully.');
    if(/%40|%2f%2f/i.test(url.pathname))
      add(1,'Encoded path characters can mislead readers.','Rely on the actual hostname, not the message text.');
    if(!reasons.length)reasons.push('No obvious red flags were detected by these limited offline rules. This does not certify the site.');
    if(!actions.length)actions.push('Independently verify the exact website and sender before acting.');
    return base(level===3?'high':level===2?'medium':level===1?'caution':'unknown',
      level===3?'Strong warning signs':level===2?'Review before opening':level===1?'Use extra caution':'No obvious local warning signs',
      reasons,actions,{host});
  }
  function inspectMessage(value) {
    const text=String(value||'').slice(0,4000);
    if(!text.trim())return base('unknown','Enter message text',['No message provided.'],['Paste only text you choose to review on this device.']);
    const secret=/(otp|one.time.pass(?:word|code)?|cvv|password|passcode|verification.code|secret.pin|6.digit.code|ओटीपी|पासवर्ड|पिन)/i;
    const request=/(send|share|tell|forward|give|reply|provide|bata|bhej|dena|भेज|बताओ|शेयर)/i;
    const payment=/(₹|\brs\.?\b|rupees?|paisa|rupiya|upi|payment|transfer|paise|पैसे|रुपय|भुगतान)/i;
    const urgent=/(urgent|immediately|abhi|turant|now|asap|within\s+\d+\s+min|अभी|तुरंत|जल्दी)/i;
    const reasons=[],actions=[];let risk=0;
    const add=(n,r,a)=>{risk=Math.max(risk,n);reasons.push(r);actions.push(a);};
    if(secret.test(text)&&request.test(text))
      add(3,'The message may request an OTP, password, PIN or CVV.','Do not share secret credentials.');
    if(payment.test(text)&&urgent.test(text))
      add(2,'Money or payment language appears with urgency.','Verify the requester and payment destination independently.');
    const urls=(text.match(/https?:\/\/[^\s<>"']+|\bwww\.[^\s<>"']+/gi)||[]).slice(0,3);
    for(const part of urls) {
      const scan=inspectUrl(part.replace(/[),.;!?]+$/,''));
      if(scan.level==='high')add(3,'A linked URL has strong warning signs.','Avoid opening it until verified.');
      else if(scan.level==='medium')add(2,'A linked URL needs extra review.','Check the destination outside the message.');
    }
    return base(risk===3?'high':risk===2?'medium':'unknown',
      risk===3?'High-priority warning':risk===2?'Review this request':'No obvious local warning signs',
      reasons.length?reasons:['No specific local patterns were found. That is not a guarantee of safety.'],
      actions.length?actions:['Verify WHO, SAME WHO, WHERE and AUTHORITY.']);
  }
  const api=Object.freeze({version:'security-shield-test-v1',inspectUrl,inspectMessage});
  if(typeof module!=='undefined'&&module.exports)module.exports=api;
  if(root)root.BharatLinkSecurityShield=api;
})(typeof window!=='undefined'?window:(typeof globalThis!=='undefined'?globalThis:null));
