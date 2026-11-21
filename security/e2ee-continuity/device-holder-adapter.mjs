/**
 * TEST-only existing-device continuity adapter.
 * No automatic enrollment, promotion, revocation, key reset or server release.
 * The runtime must supply reviewed WebCrypto proof and IndexedDB vault modules.
 */
export function createDeviceHolderAdapter({
  currentUser, readLocalDevice, isActiveDevice, getSigningKey,
  proveExistingDevice, getTrustStatus, beginChallenge, completeChallenge,
  continuityReleaseEnabled = false
} = {}) {
  const functions = {currentUser,readLocalDevice,isActiveDevice,getSigningKey,
    proveExistingDevice,getTrustStatus,beginChallenge,completeChallenge};
  for (const [name,fn] of Object.entries(functions))
    if(typeof fn !== 'function') throw new TypeError('Missing dependency: ' + name);
  let running = false;
  const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const isId = v => typeof v === 'string' && UUID.test(v);
  function assertPrivateEcdh(key) {
    if(!key || key.type!=='private' || key.extractable!==false ||
       key.algorithm?.name!=='ECDH' || key.algorithm?.namedCurve!=='P-256')
      throw new Error('Original non-extractable device key unavailable; recovery required');
  }
  async function status() {
    const user=await currentUser();
    if(!isId(user?.id)) throw new Error('Authenticated account required');
    const state=await getTrustStatus();
    if(!state || state.statusOnly!==true || state.releaseState!=='SECURITY_HOLD' ||
       state.deviceApprovalEnabled!==false) throw new Error('Unrecognized trust status');
    return {activeDeviceCount:Number(state.activeDeviceCount)||0,
      verifiedSigningDeviceCount:Number(state.verifiedSigningDeviceCount)||0,
      pendingEnrollmentCount:Number(state.pendingEnrollmentCount)||0,
      releaseState:'SECURITY_HOLD',trustGranted:false};
  }
  async function prove({confirmedByUser=false} = {}) {
    if(running) throw new Error('Verification already in progress');
    if(continuityReleaseEnabled!==true) throw new Error('SECURITY_HOLD: verification not released');
    if(confirmedByUser!==true) throw new Error('Explicit device-holder consent required');
    running=true;
    try {
      const user=await currentUser();
      if(!isId(user?.id)) throw new Error('Authenticated account required');
      const device=await readLocalDevice(user.id);
      if(!device || device.userId!==user.id || !isId(device.deviceId))
        throw new Error('Existing local device unavailable; do not auto-register');
      assertPrivateEcdh(device.privateKey);
      if(!device.publicJwk || device.publicJwk.kty!=='EC' ||
         device.publicJwk.crv!=='P-256' || !device.publicJwk.x || !device.publicJwk.y)
        throw new Error('Original device public key unavailable');
      if(await isActiveDevice(device.deviceId)!==true)
        throw new Error('Original device not active');
      // Only after consent + original device checks request a signer from local vault.
      const signing=await getSigningKey(user.id,device.deviceId);
      if(!signing?.privateKey || !signing?.publicJwk)
        throw new Error('Signing key unavailable');
      const beginning=await beginChallenge({action:'begin',confirmedByUser:true,
        deviceId:device.deviceId,signingPublicJwk:signing.publicJwk});
      const ch=beginning?.challenge;
      if(beginning?.ok!==true || beginning?.trustGranted!==false || !ch ||
         ch.userId!==user.id || ch.deviceId!==device.deviceId ||
         !isId(ch.challengeId) || !Number.isSafeInteger(ch.expiresAt) ||
         ch.expiresAt<=Date.now() || ch.expiresAt>Date.now()+6*60*1000)
        throw new Error('Invalid or cross-account challenge');
      const proof=await proveExistingDevice({authUserId:user.id,deviceId:device.deviceId,
        originalPrivateKey:device.privateKey,originalPublicJwk:device.publicJwk,
        newSigningPrivateKey:signing.privateKey,newSigningPublicJwk:signing.publicJwk,
        challenge:ch,confirmedByUser:true});
      if(!proof || proof.challengeId!==ch.challengeId)
        throw new Error('Invalid proof response');
      const result=await completeChallenge({action:'complete',...proof});
      if(result?.ok!==true || result?.continuityProven!==true ||
         result?.trustGranted!==false || result?.status!=='continuity_proven_not_trusted' ||
         result?.challengeId!==ch.challengeId || result?.deviceId!==device.deviceId)
        throw new Error('Continuity proof not accepted');
      return {continuityProven:true,trustGranted:false,status:'continuity_proven_not_trusted'};
    } finally {running=false;}
  }
  return {status,prove};
}
