import assert from "node:assert/strict";
import {spawn,execFileSync} from "node:child_process";
// Disposable CI PostgreSQL only: race TWO first-device candidates for an
// account with a historical unverified device but NO verified signing key.
const UID="99999999-9999-4999-8999-999999999999";
const pg=sql=>execFileSync("psql",["-X","-A","-t","-v","ON_ERROR_STOP=1","-c",sql],
 {encoding:"utf8",stdio:["ignore","pipe","pipe"]}).trim();
const attempt=(uuid)=>new Promise(resolve=>{
 const sql="INSERT INTO public.messaging_devices(id,user_id,public_key_jwk,key_algorithm) "+
  "VALUES ('"+uuid+"'::uuid,'"+UID+"'::uuid,"+
  "jsonb_build_object('kty','EC','crv','P-256'),'ECDH-P256');";
 const p=spawn("psql",["-X","-A","-t","-v","ON_ERROR_STOP=1","-c",sql],
   {stdio:["ignore","pipe","pipe"]});
 let err="";
 p.stderr.on("data",v=>err+=v.toString());
 p.on("error",e=>resolve({ok:false,err:String(e)}));
 p.on("close",code=>resolve({ok:code===0,err}));
});
const [a,b]=await Promise.all([
 attempt("56565656-5656-4656-8656-565656565656"),
 attempt("78787878-7878-4878-8878-787878787878")
]);
assert.equal(a.ok,false,"first concurrent contender must be denied");
assert.equal(b.ok,false,"second concurrent contender must be denied");
assert.match(a.err,/First-device authorization held/);
assert.match(b.err,/First-device authorization held/);
assert.equal(pg("SELECT count(*) FROM public.messaging_devices WHERE user_id='"+
 UID+"'::uuid"),"1","historical device count unchanged");
assert.equal(pg("SELECT count(*) FROM public.messaging_device_signing_keys WHERE user_id='"+
 UID+"'::uuid AND verified_at IS NOT NULL"),"0");
console.log("PASS: simultaneous first-device SQL insert races BOTH denied; no verified trust");
