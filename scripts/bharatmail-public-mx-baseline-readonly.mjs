/**
 * BharatMail read-only PUBLIC DNS MX baseline — no inbound SMTP authority.
 * This script does NOT touch registrar/Cloudflare/Resend, send mail or assert SPF.
 * Source-only test feature. Do not automate DNS mutations based on this output.
 */
import {resolveMx,resolveNs} from "node:dns/promises";

const ALLOWED_APEX = "bharathlink.com";
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const err = (code) => { throw Error(code); };

function host(value) {
  if (typeof value !== "string" || value.length > 254 || /[\r\n\t\s\/\\@:?#]/.test(value))
    err("invalid_hostname");
  const clean=value.toLowerCase().replace(/\.$/,"");
  if(clean.length > 253 || clean.split(".").length < 2 ||
     clean.split(".").some(part => !LABEL.test(part)))
    err("invalid_hostname");
  return clean;
}

function redactError() {
  // DNS exception text sometimes includes resolver-local network details.
  return Object.freeze({
    scope:"public_dns_only",domain:ALLOWED_APEX,status:"UNAVAILABLE",
    reason:"dns_lookup_failed_or_untrusted",mx:[],nameservers:[],
    spf:"NOT_CHECKED",dkim:"NOT_CHECKED",dmarc:"NOT_CHECKED",
    receiver_provenance:"NOT_VERIFIED",legal_sender_identity:"NOT_VERIFIED",
    deployment_authorized:false,change_mx_authorized:false
  });
}

async function observePublicMxBaseline({
  domain=ALLOWED_APEX,
  mxLookup=resolveMx,nsLookup=resolveNs
}={}) {
  if(domain!==ALLOWED_APEX)err("only_explicit_apex_allowed");
  if(typeof mxLookup!=="function"||typeof nsLookup!=="function")
    err("dns_resolver_required");

  let mx,ns;
  try {
    [mx,ns] = await Promise.all([mxLookup(ALLOWED_APEX),nsLookup(ALLOWED_APEX)]);
  } catch {
    return redactError();
  }
  if(!Array.isArray(mx)||!Array.isArray(ns)||mx.length>30||ns.length>30)
    return redactError();
  try {
    const records=mx.map(x=>{
      if(!x||typeof x!=="object"||!Number.isSafeInteger(x.priority)||
         x.priority<0||x.priority>65535)
        err("invalid_mx_priority");
      return {priority:x.priority,exchange:host(x.exchange)};
    });
    const uniq = new Set(records.map(r=>r.priority+":"+r.exchange));
    if(uniq.size!==records.length)err("ambiguous_duplicate_mx");
    const nss=ns.map(host);
    if(new Set(nss).size!==nss.length)err("ambiguous_duplicate_ns");
    records.sort((a,b)=>a.priority-b.priority||a.exchange.localeCompare(b.exchange));
    nss.sort();
    if(records.length===0||nss.length===0)return redactError();
    return Object.freeze({
      scope:"public_dns_only",domain:ALLOWED_APEX,
      status:"OBSERVED_NOT_AUTHENTICATED",mx:records.map(x=>Object.freeze(x)),
      nameservers:nss,
      observation:"Public DNS snapshot; NOT a signed historical baseline or proof of zone ownership",
      spf:"NOT_CHECKED",dkim:"NOT_CHECKED",dmarc:"NOT_CHECKED",
      receiver_provenance:"NOT_VERIFIED",legal_sender_identity:"NOT_VERIFIED",
      deployment_authorized:false,change_mx_authorized:false
    });
  } catch {
    return redactError();
  }
}

async function main() {
  const result=await observePublicMxBaseline();
  process.stdout.write(JSON.stringify(result,null,2)+"\n");
  if(result.status!=="OBSERVED_NOT_AUTHENTICATED")process.exitCode=1;
}

if(import.meta.url===new URL(process.argv[1]||"/dev/null","file:").href){
  await main();
}

export {ALLOWED_APEX,observePublicMxBaseline};
