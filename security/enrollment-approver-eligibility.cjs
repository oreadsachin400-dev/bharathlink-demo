'use strict';
// Read-only eligibility policy for future server enrollment approval.
// It does not register signing keys or activate a device.
function approverEligibility({request,approver,signingKey,nowSeconds}={}){
 if(!request||!approver||!signingKey||!Number.isSafeInteger(nowSeconds))return false;
 if(request.status!=='pending'||!Number.isSafeInteger(request.expiresAt)
   ||request.expiresAt<=nowSeconds)return false;
 if(typeof request.userId!=='string'||request.userId!==approver.userId
   ||approver.userId!==signingKey.userId)return false;
 if(!approver.deviceId||approver.deviceId!==signingKey.deviceId
   ||approver.deviceId===request.proposedDeviceId)return false;
 if(approver.revokedAt!==null||signingKey.revokedAt!==null)return false;
 if(approver.active!==true||signingKey.active!==true)return false;
 if(!Number.isSafeInteger(signingKey.verifiedAt)
   ||signingKey.verifiedAt<=0||signingKey.verifiedAt>nowSeconds)return false;
 if(!['trusted_device_signature','audited_recovery'].includes(signingKey.verificationMethod))
   return false;
 return true;
}
module.exports={approverEligibility};
