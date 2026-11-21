// BharathLink TEST integration point. REVIEW ONLY: not yet imported by index.html.
// The TEST Edge Function is hard-disabled; this module also defaults disabled.
// IMPORTANT: Never call the auto-enrollment activation method; read only the existing local key.
import {createDeviceHolderAdapter} from './device-holder-adapter.mjs';
import {proveExistingDevice} from './bootstrap-client.mjs';
import {signingKeyVault} from './signing-key-idb.mjs';
export function createBharathLinkContinuity({Supabase,E2EEBackend,CONFIG,
  releaseEnabled=false,fetchImpl=fetch,indexedDBImpl=globalThis.indexedDB}={}){
 if(!Supabase?.currentAuthUser||!Supabase?.request||
    !E2EEBackend?.getLocal||!E2EEBackend?.rpc||!CONFIG?.SUPABASE_URL)
   throw new Error('BharathLink TEST runtime unavailable');
 const vault=signingKeyVault({indexedDBImpl});
 async function edge(body){
  if(releaseEnabled!==true)throw new Error('SECURITY_HOLD');
  if(!Supabase.accessToken)throw new Error('Authenticated test session required');
  const url=String(CONFIG.SUPABASE_URL).replace(/\/+$/,'')+
    '/functions/v1/bl20-device-continuity';
  const response=await fetchImpl(url,{
   method:'POST',
   headers:Supabase.headers({'Content-Type':'application/json'}),
   body:JSON.stringify(body),
   cache:'no-store'
  });
  if(!response.ok)throw new Error('Continuity endpoint unavailable');
  return response.json();
 }
 return createDeviceHolderAdapter({
  continuityReleaseEnabled:releaseEnabled===true,
  currentUser:()=>Supabase.currentAuthUser(),
  readLocalDevice:userId=>E2EEBackend.getLocal(userId),
  isActiveDevice:deviceId=>E2EEBackend.rpc('is_my_messaging_device_active',
    {p_device_id:deviceId}),
  getSigningKey:(userId,deviceId)=>vault.getOrCreate(userId,deviceId),
  proveExistingDevice,
  getTrustStatus:()=>Supabase.request('/rest/v1/rpc/bl20_my_e2ee_trust_status',
    {method:'POST',body:'{}'}),
  beginChallenge:edge,
  completeChallenge:edge
 });
}
