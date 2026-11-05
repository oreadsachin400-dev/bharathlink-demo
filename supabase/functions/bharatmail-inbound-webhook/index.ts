import {captureInboundAttachmentSnapshot} from './auto-metadata.mjs';
// BharathLink TEST only. Fail closed until Resend webhook signing secret is configured.
const json=(status:number,body:unknown)=>new Response(JSON.stringify(body),{status,headers:{"content-type":"application/json"}});
Deno.serve(async(req:Request)=>{
 if(req.method!=="POST")return json(405,{error:"method_not_allowed"});
 const secret=Deno.env.get("RESEND_WEBHOOK_SIGNING_SECRET");
 if(!secret)return json(503,{error:"webhook_not_configured"});
 const id=req.headers.get("svix-id"),ts=req.headers.get("svix-timestamp"),sig=req.headers.get("svix-signature");
 if(!id||!ts||!sig)return json(401,{error:"missing_signature"});
 const t=Number(ts);if(!Number.isFinite(t)||Math.abs(Date.now()/1000-t)>300)return json(401,{error:"expired_signature"});
 const raw=await req.text();if(raw.length>1048576)return json(413,{error:"payload_too_large"});
 try{
  const keyBytes=Uint8Array.from(atob(secret.replace(/^whsec_/, "")),c=>c.charCodeAt(0));
  const key=await crypto.subtle.importKey("raw",keyBytes,{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const digest=new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(id+"."+ts+"."+raw)));
  const expected=btoa(String.fromCharCode(...digest));
  const ok=sig.split(" ").some(s=>{const a=s.split(",");if(a.length!==2||a[0]!=="v1")return false;const x=a[1];if(x.length!==expected.length)return false;let diff=0;for(let i=0;i<x.length;i++)diff|=x.charCodeAt(i)^expected.charCodeAt(i);return diff===0;});
  if(!ok)return json(401,{error:"invalid_signature"});
  const event=JSON.parse(raw);
  if(event?.type!=="email.received")return json(200,{ok:true,ignored:true});
  const data=event?.data||{};
  const emailId=String(data.email_id||"");
  if(!emailId||emailId.length>200)return json(400,{error:"missing_email_id"});
  const apiUrl=Deno.env.get("SUPABASE_URL"),role=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if(!apiUrl||!role)return json(503,{error:"database_not_configured"});
  const tos=Array.isArray(data.to)?data.to.filter((x:unknown)=>typeof x==="string").slice(0,30):[];
  const row={provider_email_id:emailId,event_id:id,from_address:typeof data.from==="string"?data.from:null,to_addresses:tos,status:"pending_routing",payload:{type:event.type,data:{email_id:emailId,from:data.from,to:tos,subject:data.subject,created_at:data.created_at}}};
  const save=await fetch(apiUrl+"/rest/v1/bharatmail_inbound_events?on_conflict=provider_email_id",{method:"POST",headers:{"apikey":role,"Authorization":"Bearer "+role,"Content-Type":"application/json","Prefer":"resolution=ignore-duplicates,return=minimal"},body:JSON.stringify(row)});
  if(!save.ok)return json(503,{error:"durable_save_failed"});
  // Fetch full content from Resend server-side; never expose provider API key to clients.
  const resendKey=Deno.env.get("RESEND_INBOUND_API_KEY");
  if(!resendKey)return json(503,{error:"provider_key_missing"});
  const detail=await fetch("https://api.resend.com/emails/receiving/"+encodeURIComponent(emailId),{headers:{"Authorization":"Bearer "+resendKey}});
  if(!detail.ok)return json(503,{error:"provider_fetch_failed",provider_status:detail.status});
  const full=await detail.json();
  const content={type:event.type,data:{email_id:emailId,from:data.from,to:tos,subject:data.subject,created_at:data.created_at},email:{text:typeof full.text==="string"?full.text.slice(0,500000):null,html:typeof full.html==="string"?full.html.slice(0,500000):null,subject:typeof full.subject==="string"?full.subject:null,attachments:Array.isArray(full.attachments)?full.attachments.map((a:Record<string,unknown>)=>({filename:a.filename,content_type:a.content_type})).slice(0,30):[]}};
  const update=await fetch(apiUrl+"/rest/v1/bharatmail_inbound_events?provider_email_id=eq."+encodeURIComponent(emailId),{method:"PATCH",headers:{"apikey":role,"Authorization":"Bearer "+role,"Content-Type":"application/json","Prefer":"return=minimal"},body:JSON.stringify({payload:content})});
  if(!update.ok)return json(503,{error:"content_save_failed"});
  const route=await fetch(apiUrl+"/rest/v1/rpc/bharatmail_route_inbound_event",{method:"POST",headers:{"apikey":role,"Authorization":"Bearer "+role,"Content-Type":"application/json"},body:JSON.stringify({p_email_id:emailId})});
  if(!route.ok)return json(503,{error:"routing_failed"});
  const routing=await route.json();
  // This optional TEST-only metadata stage is AFTER the existing verified
  // event persistence, Resend detail retrieval, and successful email routing.
  // Its failure must never change the successful mail-delivery acknowledgement.
  try{
    const metadata=await captureInboundAttachmentSnapshot({
      projectUrl:apiUrl,adminKey:role,resendKey,
      providerEmailId:emailId,fetchFn:fetch
    });
    console.info('bharatmail_auto_metadata',metadata.status);
  }catch{
    console.info('bharatmail_auto_metadata','metadata_background_unavailable');
  }
  return json(200,{ok:true,stored:true,content_saved:true,routing});
 }catch{return json(400,{error:"invalid_webhook"});}
});