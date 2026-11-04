/**
 * BharathMail LOOPBACK SMTP evidence test harness.
 *
 * NOT a production MTA, not TLS, not Internet-facing, no external DNS, no
 * inbox delivery, no persistent storage, no authenticated external issuer.
 * Enabled solely by an explicit TEST environment guard and IPv4 127.0.0.1.
 * Observes real local socket.remoteAddress, SMTP HELO, MAIL FROM, RCPT TO and
 * actual SMTP DATA bytes; never trusts message Received/Auth-Results headers.
 */
import {createServer} from "node:net";
import {createHash,randomUUID,webcrypto} from "node:crypto";
import {AUD,canonical} from "./verify-signed-smtp-receipt.mjs";
import {addressPart} from "../supabase/functions/bl-mail-auth-attest/signed-report.mjs";

const MAX_MIME=256*1024;
const MAX_LINE=1000;
const HOST="127.0.0.1";
const RECEIVER="mx.bharathlink.example";
const MAIL_HOST=/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;
const invalid=()=>{throw Error("invalid_mailbox");};
function mailbox(value){
  if(!/^<[^<>]+>$/.test(value))invalid();
  const raw=value.slice(1,-1);
  const addr=addressPart(raw);
  if(raw!==addr)invalid(); // strict ASCII lower-case local test envelope
  return addr;
}
function authorFrom(raw){
  // Deliberately narrow synthetic fixture: no obsolete syntax, folded fields,
  // SMTPUTF8 or MIME policy support. Unsupported input is rejected, not
  // silently authenticated; a real receiver needs a reviewed RFC parser.
  const sep=raw.indexOf(Buffer.from("\r\n\r\n"));
  if(sep<0||sep>65536)throw Error("bad_headers");
  const fields=raw.subarray(0,sep).toString("utf8").split("\r\n");
  const found=[];
  let previous="";
  for(const field of fields){
    if(/^\s/.test(field)){
      if(!previous||previous==="from")throw Error("unsupported_folded_from");
      continue; // DKIM-Signature may be folded; we do not trust its values
    }
    const i=field.indexOf(":");
    if(i<=0)throw Error("bad_headers");
    previous=field.slice(0,i).toLowerCase();
    if(previous==="from")found.push(field.slice(i+1).trim());
  }
  if(found.length!==1)throw Error("ambiguous_from");
  const from=found[0];
  addressPart(from);
  return from;
}
async function startLoopbackSmtpEvidenceTest({
  privateKey,kid,receivedAt=()=>Math.floor(Date.now()/1000)
}={}){
  if(process.env.BHARATHLINK_OFFLINE_SMTP_LOOPBACK_TEST!=="enabled")
    throw Error("loopback_test_guard_required");
  if(!privateKey||privateKey.type!=="private"||
     privateKey.algorithm?.name!=="ECDSA"||
     privateKey.algorithm?.namedCurve!=="P-256")
    throw Error("ephemeral_test_signer_required");
  if(typeof kid!=="string"||!/^[A-Za-z0-9_.-]{1,64}$/.test(kid))
    throw Error("receiver_key_id");
  if(typeof receivedAt!=="function")throw Error("invalid_clock");
  const deliveries=[];
  const sockets=new Set();
  const server=createServer(socket=>{
    sockets.add(socket);
    socket.setTimeout(4000,()=>socket.destroy());
    socket.on("close",()=>sockets.delete(socket));
    if(socket.remoteAddress!==HOST){socket.destroy();return;}
    let state="helo",helo="",mailFrom="",rcpt="",pending=Buffer.alloc(0),
      dataParts=[],dataBytes=0,finished=false,working=false;
    const reply=(code,msg)=>{if(!socket.destroyed)socket.write(code+" "+msg+"\r\n");};
    const stop=(code,msg)=>{
      finished=true;
      if(!socket.destroyed)socket.end(code+" "+msg+"\r\n");
    };
    reply(220,"bharathlink.example synthetic loopback only");
    const complete=async()=>{
      socket.pause();
      working=true;
      try{
        const rawMime=Buffer.concat(dataParts,dataBytes);
        const from=authorFrom(rawMime);
        const now=receivedAt();
        if(!Number.isSafeInteger(now)||now<0)throw Error("invalid_clock");
        // The local TCP peer address is the sole source of the client IP.
        const receipt={
          v:1,aud:AUD,kid,
          provider_email_id:"offline-"+randomUUID(),
          from_address:from,recipient_address:rcpt,
          raw_sha256:createHash("sha256").update(rawMime).digest("hex"),
          smtp_client_ip:socket.remoteAddress,
          smtp_mail_from:mailFrom,smtp_helo:helo,receiver_mta:RECEIVER,
          received_at:now,expires_at:now+120,nonce:randomUUID()
        };
        const sig=new Uint8Array(await webcrypto.subtle.sign(
          {name:"ECDSA",hash:"SHA-256"},privateKey,
          new TextEncoder().encode(canonical(receipt,now))
        ));
        deliveries.push(Object.freeze({
          rawMime:Buffer.from(rawMime),
          receiverEnvelope:Object.freeze({
            receipt:Object.freeze(receipt),
            signature:Buffer.from(sig).toString("base64url")
          }),
          origin:"REAL_LOOPBACK_TCP_SYNTHETIC_RECEIVER_ONLY",
          production_authorized:false,external_receiver_audited:false
        }));
        stop(250,"synthetic local receipt captured; no mail delivered");
      }catch{
        stop(550,"synthetic mail rejected; no receipt");
      }finally{working=false;}
    };
    const line=(line)=>{
      if(finished||working)return;
      if(line.length>MAX_LINE||line.includes(0)){stop(552,"invalid line");return;}
      if(state==="data"){
        if(line.length===1&&line[0]===46){
          finished=true; // no pipelined commands accepted during signing
          void complete();
          return;
        }
        let segment=line;
        if(line.length>=2&&line[0]===46&&line[1]===46)
          segment=line.subarray(1); // RFC 5321 dot unstuff
        else if(line[0]===46){stop(550,"invalid SMTP dot stuffing");return;}
        dataBytes+=segment.length+2;
        if(dataBytes>MAX_MIME){stop(552,"synthetic message too large");return;}
        dataParts.push(segment,Buffer.from("\r\n"));
        return;
      }
      if(line.length>512){stop(500,"oversized command");return;}
      const cmd=line.toString("ascii");
      if(!Buffer.from(cmd,"ascii").equals(line)){stop(500,"non-ASCII command");return;}
      if(cmd==="QUIT"){stop(221,"synthetic session closed");return;}
      if(/^STARTTLS|^AUTH|^XCLIENT|^XFORWARD/i.test(cmd)){
        stop(502,"unsupported in loopback test");
        return;
      }
      if(state==="helo"&&/^(EHLO|HELO) /i.test(cmd)){
        const host=cmd.slice(5).toLowerCase();
        if(!MAIL_HOST.test(host)||host.length>253){
          stop(501,"invalid HELO");return;
        }
        helo=host;state="mail";reply(250,"synthetic HELO accepted");return;
      }
      if(state==="mail"&&cmd.startsWith("MAIL FROM:")){
        try{mailFrom=mailbox(cmd.slice(10));state="rcpt";
          reply(250,"synthetic sender accepted");}
        catch{stop(553,"bad MAIL FROM");}
        return;
      }
      if(state==="rcpt"&&cmd.startsWith("RCPT TO:")){
        try{
          rcpt=mailbox(cmd.slice(8));
          if(!rcpt.endsWith("@bharathlink.example"))
            throw Error("test_domain_only");
          state="await-data";reply(250,"synthetic recipient accepted");
        }catch{stop(550,"synthetic recipient not permitted");}
        return;
      }
      if(state==="await-data"&&cmd==="DATA"){
        state="data";reply(354,"end with <CRLF>.<CRLF>");return;
      }
      stop(503,"invalid synthetic SMTP sequence");
    };
    socket.on("data",chunk=>{
      if(finished||working)return;
      pending=Buffer.concat([pending,chunk]);
      if(pending.length>MAX_MIME+MAX_LINE+4){stop(552,"buffer exceeded");return;}
      while(!finished&&!working){
        const end=pending.indexOf("\r\n");
        if(end<0){
          if(pending.length>MAX_LINE+2)stop(552,"line too long");
          break;
        }
        const one=pending.subarray(0,end);
        pending=pending.subarray(end+2);
        line(one);
      }
    });
    socket.on("error",()=>{});
  });
  server.maxConnections=10;
  try{
    await new Promise((resolve,reject)=>{
      const onErr=e=>{server.off("listening",onListen);reject(e);};
      const onListen=()=>{server.off("error",onErr);resolve();};
      server.once("error",onErr);
      server.once("listening",onListen);
      server.listen(0,HOST);
    });
  }catch(e){server.close();throw e;}
  return Object.freeze({
    host:HOST,port:server.address().port,deliveries,
    close:async()=>{
      for(const sock of sockets)sock.destroy();
      await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));
    }
  });
}
export {startLoopbackSmtpEvidenceTest};
