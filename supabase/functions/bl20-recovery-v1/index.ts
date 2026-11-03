import {verifyRecoveryReviewSignature,sha256Hex} from './review-crypto.mjs';
/**
 * BharathLink-20-TEST only. Phase 4 recovery review receipt service.
 * NOT DEPLOYED. Permanently disabled in this reviewed revision.
 *
 * This never calls register_e2ee_v2_device or bl20_commit_device_approval.
 * Positive result == receipt recorded; NOT approved or trusted.
 */
const RECOVERY_RELEASED = false; // do not change without independent audited authority
const ALLOWED_ORIGIN = 'https://bharathlink-20-test.netlify.app';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ALLOWED_ACTIONS = new Set(['challenge', 'record-reviewed-evidence']);
function res(status:number, body:unknown, origin:string|null=null){
  const headers:Record<string,string> = {
    'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',
    'X-Content-Type-Options':'nosniff','Vary':'Origin'
  };
  if(origin===ALLOWED_ORIGIN) headers['Access-Control-Allow-Origin']=ALLOWED_ORIGIN;
  return new Response(JSON.stringify(body),{status,headers});
}
function jwtSession(accessToken:string):string|null{
  // These claims are NOT trusted until Supabase /auth/v1/user validates token.
  try {
    const part=accessToken.split('.')[1]; if(!part || part.length>4096)return null;
    const s=atob(part.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(part.length/4)*4,'='));
    const payload=JSON.parse(s);
    return typeof payload.session_id==='string' && UUID.test(payload.session_id)?payload.session_id:null;
  }catch{return null;}
}
async function jsonApi(url:string,key:string,headers:Record<string,string>,body:unknown){
  const reply=await fetch(url,{method:'POST',
    headers:{'Content-Type':'application/json','apikey':key,...headers},
    body:JSON.stringify(body)});
  if(!reply.ok)throw new Error('rpc_failed');
  return reply.json();
}
Deno.serve(async(req:Request)=>{
 const origin=req.headers.get('origin');
 // Hard-disable before any provider secret lookup, request parsing or DB access.
 if(!RECOVERY_RELEASED)return res(503,{ok:false,error:'Recovery is not available'},origin);
 if(req.method==='OPTIONS'){
   if(origin!==ALLOWED_ORIGIN)return res(403,{ok:false},origin);
   return new Response(null,{status:204,headers:{
    'Access-Control-Allow-Origin':ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods':'POST,OPTIONS',
    'Access-Control-Allow-Headers':'authorization,apikey,content-type',
    'Access-Control-Max-Age':'300','Vary':'Origin'}});
 }
 if(req.method!=='POST' || (origin && origin!==ALLOWED_ORIGIN))
   return res(403,{ok:false},origin);
 try{
   const host=Deno.env.get('SUPABASE_URL'),service=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
   const anon=Deno.env.get('SUPABASE_ANON_KEY');
   const auth=req.headers.get('authorization')||'';
   if(!host || !service || !anon || !auth.startsWith('Bearer ') || auth.length>8000)
     return res(403,{ok:false},origin);
   const jwt=auth.slice(7);
   const verified=await fetch(host+'/auth/v1/user',{headers:{Authorization:'Bearer '+jwt,apikey:anon}});
   if(!verified.ok)return res(401,{ok:false},origin);
   const user=await verified.json();
   const sessionId=jwtSession(jwt);
   if(!UUID.test(user?.id||'')||!sessionId)return res(403,{ok:false},origin);
   const bodyText=await req.text();
   if(bodyText.length>4096)return res(400,{ok:false},origin);
   const data=JSON.parse(bodyText);
   if(!data || !ALLOWED_ACTIONS.has(data.action))return res(400,{ok:false},origin);
   const rpc=(name:string,body:unknown)=>jsonApi(
      host+'/rest/v1/rpc/'+name,service,{},body);
   if(data.action==='challenge'){
      if(!UUID.test(data.requestId||'')||!UUID.test(data.proofId||''))
         return res(400,{ok:false},origin);
      const challenge=await rpc('bl20_recovery_v1_challenge_start',{
        p_user:user.id,p_session:sessionId,p_request:data.requestId,p_proof:data.proofId});
      return res(200,{ok:true,challenge,deviceApproved:false},origin);
   }
   if(!UUID.test(data.challengeId||''))return res(400,{ok:false},origin);
   const ctx=await rpc('bl20_recovery_v1_review_context',{
      p_user:user.id,p_session:sessionId,p_challenge:data.challengeId});
   if(!await verifyRecoveryReviewSignature(ctx))return res(403,{ok:false},origin);
   const digest=await sha256Hex(ctx.payload);
   const signatureDigest=await sha256Hex(ctx.signatureBase64Url);
   const key=ctx.issuerPublicJwk;
   const issuerKeyDigest=await sha256Hex(['EC','P-256',key.x,key.y].join('\n'));
   const receipt=await rpc('bl20_recovery_v1_review_consume_v2',{
      p_user:user.id,p_session:sessionId,p_challenge:data.challengeId,
      p_payload_sha:digest,p_attestation_sha:signatureDigest,
      p_issuer_public_key_sha:issuerKeyDigest});
   if(receipt?.reviewReceiptStored!==true ||
      receipt?.deviceApproved!==false || receipt?.trustedDevice!==false ||
      receipt?.e2eeV2Ready!==false)return res(403,{ok:false},origin);
   return res(200,{ok:true,reviewReceiptStored:true,
     deviceApproved:false,trustedDevice:false,e2eeV2Ready:false},origin);
 }catch{
   return res(403,{ok:false,error:'Recovery rejected'},origin);
 }
});
