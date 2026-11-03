/**
 * BHARATHLINK-20-TEST ONLY / PHASE 7F STAGED REVIEW SOURCE.
 * NOT DEPLOYED. No live trust, no first-device bootstrap.
 * DO NOT FLIP THE GATE. Requires further auth-session, issuer governance,
 * Android Play Protect, UX, threat model, abuse controls and release review.
 */
import {isUuid,verifyDeviceApproval,sha256Hex}
  from "../bl20-device-approval/approval-crypto.mjs";
const V2_RELEASED=false; // deliberately not overridable via environment
const ORIGIN="https://bharathlink-20-test.netlify.app";
const reply=(status:number,body:unknown)=>
  new Response(JSON.stringify(body),{status,headers:{
    "content-type":"application/json","cache-control":"no-store",
    "x-content-type-options":"nosniff","vary":"Origin",
    "access-control-allow-origin":ORIGIN
  }});
async function rpc(host:string,secret:string,name:string,body:unknown){
  const r=await fetch(host+"/rest/v1/rpc/"+name,{
    method:"POST",headers:{"apikey":secret,
      "Authorization":"Bearer "+secret,
      "content-type":"application/json"},
    body:JSON.stringify(body),signal:AbortSignal.timeout(8000)
  });
  if(!r.ok)throw new Error("Privileged RPC denied");
  return r.json();
}
Deno.serve(async req=>{
  // Hard fail before any request reading, authentication or privileged API.
  if(!V2_RELEASED)return reply(503,{approved:false,error:"Approval v2 disabled"});
  if(req.headers.get("origin")&&req.headers.get("origin")!==ORIGIN)
    return reply(403,{approved:false,error:"Origin not allowed"});
  if(req.method!=="POST")return reply(405,{approved:false,error:"Method not allowed"});
  if(Number(req.headers.get("content-length")||0)>1024)
    return reply(413,{approved:false,error:"Request too large"});
  const host=Deno.env.get("SUPABASE_URL");
  const anon=Deno.env.get("SUPABASE_ANON_KEY");
  const service=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const token=req.headers.get("authorization")?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if(!host||!anon||!service||!token||token===service)
    return reply(401,{approved:false,error:"Unauthorized"});
  try{
    const raw=await req.text();
    if(raw.length>1024)return reply(413,{approved:false,error:"Request too large"});
    const data=JSON.parse(raw);
    const {requestId,approverDeviceId,candidateProofId,signatureBase64Url}=data||{};
    if(!isUuid(requestId)||!isUuid(approverDeviceId)||
       !isUuid(candidateProofId)||
       typeof signatureBase64Url!=="string"||
       signatureBase64Url.length<8||signatureBase64Url.length>128)
      return reply(400,{approved:false,error:"Invalid request"});
    const auth=await fetch(host+"/auth/v1/user",{
      headers:{apikey:anon,Authorization:"Bearer "+token},
      signal:AbortSignal.timeout(8000)
    });
    if(!auth.ok)return reply(401,{approved:false,error:"Unauthorized"});
    const principal=await auth.json();
    if(!isUuid(principal?.id)||principal?.is_anonymous===true)
      return reply(401,{approved:false,error:"Unauthorized"});
    const userId=principal.id;
    const context=await rpc(host,service,"bl20_device_approval_context",{
      p_user_id:userId,p_request_id:requestId,
      p_approver_device_id:approverDeviceId
    });
    if(!context||context.userId!==userId||
       context.requestId!==requestId||
       context.approverDeviceId!==approverDeviceId||
       typeof context.payload!=="string"||
       !/^[a-f0-9]{64}$/.test(context.signingKeyDigest||""))
      return reply(403,{approved:false,error:"Approval denied"});
    if(!await verifyDeviceApproval({
       payload:context.payload,signingPublicJwk:context.signingPublicJwk,
       signatureBase64Url
    }))return reply(403,{approved:false,error:"Invalid signature"});
    const payloadDigest=await sha256Hex(context.payload);
    // DB v2 rechecks the independent NEW device's candidate proof, exact
    // ECDH/signing keys, freshness, existing trusted approver, replay.
    const outcome=await rpc(host,service,"bl20_commit_device_approval_v2",{
      p_user_id:userId,p_request_id:requestId,
      p_approver_device_id:approverDeviceId,p_candidate_proof_id:candidateProofId,
      p_payload_digest:payloadDigest,
      p_signing_key_digest:context.signingKeyDigest
    });
    if(outcome?.approved!==true||outcome.candidateProofBound!==true||
       outcome.requestId!==requestId||!isUuid(outcome.deviceId))
      return reply(403,{approved:false,error:"Approval denied"});
    // This is ONLY additional-device approval behind existing verified
    // signer; never authorizes independent first-device bootstrap.
    return reply(200,{approved:true,deviceId:outcome.deviceId,
      requestId, candidateProofBound:true});
  }catch{
    return reply(503,{approved:false,error:"Secure approval unavailable"});
  }
});
