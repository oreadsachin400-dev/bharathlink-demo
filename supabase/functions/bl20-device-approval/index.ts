// BharathLink-20-TEST ONLY. This function is deliberately disabled until
// independent trusted-device provisioning and staging approval are completed.
// Do not deploy with BHARATHLINK_DEVICE_APPROVAL_ENABLED=true yet.
import {isUuid,verifyDeviceApproval,sha256Hex} from "./approval-crypto.mjs";

const allowedOrigin="https://bharathlink-20-test.netlify.app";
function response(data,status=200) {
  return new Response(JSON.stringify(data),{status,headers:{
    "content-type":"application/json",
    "cache-control":"no-store",
    "x-content-type-options":"nosniff",
    "access-control-allow-origin":allowedOrigin,"vary":"Origin"
  }});
}
async function api(url,apikey,authorization,body) {
  const result=await fetch(url,{method:"POST",headers:{
    "content-type":"application/json",apikey,Authorization:"Bearer "+authorization
  },body:JSON.stringify(body),signal:AbortSignal.timeout(8000)});
  if(!result.ok) throw new Error("Secure backend declined request");
  return result.json();
}
Deno.serve(async req=>{
  if(req.headers.get("origin") && req.headers.get("origin")!==allowedOrigin)
    return response({approved:false,error:"Origin not allowed"},403);
  if(req.method==="OPTIONS") return new Response(null,{status:204,headers:{
    "access-control-allow-origin":allowedOrigin,"vary":"Origin",
    "access-control-allow-methods":"POST,OPTIONS",
    "access-control-allow-headers":"authorization,apikey,content-type",
    "cache-control":"no-store"
  }});
  if(req.method!=="POST") return response({approved:false,error:"Method not allowed"},405);
  if(Deno.env.get("BHARATHLINK_DEVICE_APPROVAL_ENABLED")!=="true")
    return response({approved:false,error:"Trusted-device approval not enabled"},503);
  if(Number(req.headers.get("content-length")||0)>1024)
    return response({approved:false,error:"Request too large"},413);

  const url=Deno.env.get("SUPABASE_URL");
  const anon=Deno.env.get("SUPABASE_ANON_KEY");
  const secret=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const token=req.headers.get("authorization")?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if(!url||!anon||!secret) return response({approved:false,error:"Configuration unavailable"},503);
  if(!token || token===secret) return response({approved:false,error:"Unauthorized"},401);
  try {
    const bodyText=await req.text();
    if(bodyText.length>1024) return response({approved:false,error:"Request too large"},413);
    const body=JSON.parse(bodyText);
    const requestId=body?.requestId,approverDeviceId=body?.approverDeviceId;
    const signature=body?.signatureBase64Url;
    if(!isUuid(requestId)||!isUuid(approverDeviceId)
       ||typeof signature!=="string"||signature.length<8||signature.length>128)
      return response({approved:false,error:"Invalid approval request"},400);

    // Independent online JWT validation. Never accept client-asserted account IDs.
    const auth=await fetch(url+"/auth/v1/user",{
      headers:{"apikey":anon,"Authorization":"Bearer "+token},
      signal:AbortSignal.timeout(8000)
    });
    if(!auth.ok) return response({approved:false,error:"Unauthorized"},401);
    const user=await auth.json();
    if(!isUuid(user.id)) return response({approved:false,error:"Unauthorized"},401);

    // Privileged lookups are scoped to the *authenticated* account, not request body.
    const context=await api(url+"/rest/v1/rpc/bl20_device_approval_context",
      secret,secret,{p_user_id:user.id,p_request_id:requestId,
      p_approver_device_id:approverDeviceId});
    if(!context || context.userId!==user.id ||
       context.requestId!==requestId || context.approverDeviceId!==approverDeviceId ||
       !/^[a-f0-9]{64}$/.test(context.signingKeyDigest||""))
      return response({approved:false,error:"Device approval unavailable"},403);
    if(!await verifyDeviceApproval({payload:context.payload,
      signingPublicJwk:context.signingPublicJwk,signatureBase64Url:signature}))
      return response({approved:false,error:"Invalid approval signature"},403);

    // DB rechecks challenge, ownership, signer key, revocation, expiry, atomic replay.
    const digest=await sha256Hex(context.payload);
    const committed=await api(url+"/rest/v1/rpc/bl20_commit_device_approval",
      secret,secret,{p_user_id:user.id,p_request_id:requestId,
      p_approver_device_id:approverDeviceId,
      p_payload_digest:digest,p_signing_key_digest:context.signingKeyDigest});
    if(committed?.approved!==true || committed.requestId!==requestId)
      return response({approved:false,error:"Device approval rejected"},403);
    return response({approved:true,requestId,deviceId:committed.deviceId});
  }catch {
    // Generic failure prevents leaking details of devices, signer keys, or account state.
    return response({approved:false,error:"Secure approval unavailable"},503);
  }
});
