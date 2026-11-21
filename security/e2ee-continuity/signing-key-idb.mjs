// Local IndexedDB signing keys; NEVER upload a private key.
// Account + exact existing device scope. Never auto-enable server trust.
export function signingKeyVault({indexedDBImpl=globalThis.indexedDB,subtle=crypto.subtle}={}){
 if(!indexedDBImpl)throw new Error('IndexedDB unavailable');
 const DB='bharathlink-signing-continuity-v1',STORE='signing';
 const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
 async function open(){return new Promise((resolve,reject)=>{
  const r=indexedDBImpl.open(DB,1);
  r.onupgradeneeded=()=>{if(!r.result.objectStoreNames.contains(STORE))
    r.result.createObjectStore(STORE);};
  r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);
 });}
 function slot(uid,did){
  if(!UUID.test(uid)||!UUID.test(did))throw new Error('Invalid signing scope');
  return uid+':'+did;
 }
 async function read(db,id){return new Promise((resolve,reject)=>{
  const tx=db.transaction(STORE,'readonly');
  const r=tx.objectStore(STORE).get(id);
  r.onsuccess=()=>resolve(r.result||null);r.onerror=()=>reject(r.error);
 });}
 async function add(db,id,val){return new Promise((resolve,reject)=>{
  const tx=db.transaction(STORE,'readwrite');
  tx.objectStore(STORE).add(val,id);
  tx.oncomplete=()=>resolve();tx.onerror=()=>reject(tx.error);
 });}
 function check(x){
  if(x?.privateKey?.type!=='private'||x.privateKey.extractable!==false||
     x.privateKey.algorithm?.name!=='ECDSA'||
     x.privateKey.algorithm?.namedCurve!=='P-256')
    throw new Error('Local signing key invalid; manual recovery required');
  if(x?.publicJwk?.kty!=='EC'||x.publicJwk.crv!=='P-256'||
     !x.publicJwk.x||!x.publicJwk.y||Object.hasOwn(x.publicJwk,'d'))
    throw new Error('Local public signing key invalid');
  return x;
 }
 async function getOrCreate(userId,deviceId){
  const id=slot(userId,deviceId),db=await open();
  try{
   const existing=await read(db,id);
   if(existing)return check(existing);
   const kp=await subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
   const val={privateKey:kp.privateKey,publicJwk:await subtle.exportKey('jwk',kp.publicKey)};
   try{await add(db,id,val);return check(val);}
   catch(e){if(e?.name==='ConstraintError')return check(await read(db,id));throw e;}
  }finally{db.close();}
 }
 return {getOrCreate};
}
