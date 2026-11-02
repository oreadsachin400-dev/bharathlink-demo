// TEST ONLY, possession is NOT verification/approval. Deployed hard-disabled.
// Never enable without reviewed Android authenticated-session binding.
import {validatePublicKeys,verifyCandidateSignature,sha256Hex}
  from "./candidate-crypto.mjs";

const FEATURE_RELEASED=false; // deliberately non-configurable from environment
const ALLOWED_ORIGIN="https://bharathlink-20-test.netlify.app";
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const response=(data,status=200)=>new Response(JSON.stringify(data),{
  status,headers:{"content-type":"application/json","cache-control":"no-store",
    "x-content-type-options":"nosniff","access-control-allow-origin":ALLOWED_ORIGIN,
    "vary":"Origin"}
});
async function rpc(host,service,name,args){
 const url=host+"/rest/v1/rpc/"+name;
 const r=await fetch(url,{method:"POST",headers:{"apikey":service,
     "Authorization":"Bearer "+service,"content-type":"application/json"},
   body:JSON.stringify(args),signal:AbortSignal.timeout(8000)});
 if(!r.ok) throw new Error("Privileged RPC denied");
 return r.json();
}
Deno.serve(async(request)=>{
 if(request.headers.get("origin") && request.headers.get("origin")!==ALLOWED_ORIGIN)
   return response({ok:false,error:"Origin not allowed"},403);
 if(request.method==="OPTIONS")return new Response(null,{status:204,headers:{
   "access-control-allow-origin":ALLOWED_ORIGIN,"vary":"Origin",
   "access-control-allow-methods":"POST,OPTIONS",
   "access-control-allow-headers":"authorization,apikey,content-type",
   "cache-control":"no-store"
 }});
 if(request.method!=="POST")return response({ok:false,error:"Method not allowed"},405);
 if(!FEATURE_RELEASED)return response({ok:false,error:"Candidate enrollment not enabled"},503);
 if(Number(request.headers.get("content-length")||0)>2048)
   return response({ok:false,error:"Request too large"},413);
 const host=Deno.env.get("SUPABASE_URL");
 const anon=Deno.env.get("SUPABASE_ANON_KEY");
 const secret=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
 const token=request.headers.get("authorization")?.match(/^Bearer\s+(\S+)$/i)?.[1];
 if(!host||!anon||!secret)return response({ok:false,error:"Service unavailable"},503);
 if(!token||token===secret)return response({ok:false,error:"Unauthorized"},401);
 try{
   const bodyText=await request.text();
   if(bodyText.length>2048)return response({ok:false,error:"Request too large"},413);
   const data=JSON.parse(bodyText);
   const operation=data?.operation;
   if(operation!=="start"&&operation!=="finish")return response({ok:false,error:"Invalid operation"},400);

   // Live auth round-trip; never use a client-supplied accountId for DB writes.
   const ar=await fetch(host+"/auth/v1/user",{
     headers:{"apikey":anon,"authorization":"Bearer "+token},
     signal:AbortSignal.timeout(8000)});
   if(!ar.ok)return response({ok:false,error:"Unauthorized"},401);
   const principal=await ar.json();
   if(typeof principal?.id!=="string"||!UUID.test(principal.id))
     return response({ok:false,error:"Unauthorized"},401);
   const userId=principal.id;

   if(operation==="start"){
     if(typeof data.deviceId!=="string"||!UUID.test(data.deviceId))
       return response({ok:false,error:"Invalid device ID"},400);
     if(!await validatePublicKeys(data.ecdhPublicJwk,data.signingPublicJwk))
       return response({ok:false,error:"Invalid public keys"},400);
     const challenge=await rpc(host,secret,"bl20_candidate_proof_start",{
       p_user_id:userId,p_device_id:data.deviceId,
       p_ecdh_public_jwk:data.ecdhPublicJwk,
       p_signing_public_jwk:data.signingPublicJwk
     });
     if(!challenge || challenge.userId!==userId || challenge.deviceId!==data.deviceId ||
        challenge.serverApproved!==false || typeof challenge.payload!=="string")
       return response({ok:false,error:"Candidate creation denied"},403);
     // Caller receives a short-lived server-defined payload to sign locally.
     return response({ok:true,challenge});
   }

   if(typeof data.proofId!=="string"||!UUID.test(data.proofId) ||
      typeof data.signatureBase64Url!=="string"||
      data.signatureBase64Url.length<8||data.signatureBase64Url.length>128)
     return response({ok:false,error:"Invalid proof"},400);
   const context=await rpc(host,secret,"bl20_candidate_proof_context",{
     p_user_id:userId,p_proof_id:data.proofId
   });
   if(!context || context.proofId!==data.proofId||context.userId!==userId ||
      typeof context.payload!=="string")
     return response({ok:false,error:"Candidate proof unavailable"},403);
   if(!await verifyCandidateSignature({
      payload:context.payload,signingPublicJwk:context.signingPublicJwk,
      signatureBase64Url:data.signatureBase64Url
   }))return response({ok:false,error:"Invalid proof signature"},403);
   const digest=await sha256Hex(context.payload);
   const outcome=await rpc(host,secret,"bl20_candidate_proof_finish",{
     p_user_id:userId,p_proof_id:data.proofId,p_payload_hash:digest
   });
   if(outcome?.possessionProven!==true || outcome.serverApproved!==false)
     return response({ok:false,error:"Proof not committed"},403);
   return response({ok:true, ...outcome});
 }catch{
   return response({ok:false,error:"Secure candidate proof unavailable"},503);
 }
});
