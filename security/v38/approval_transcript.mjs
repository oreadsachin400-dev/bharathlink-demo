// Reference-only canonical approval transcript. No database or production writes.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX=/^[0-9a-f]{64}$/;
function requireField(value, pattern, name) {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error('invalid '+name);
  return value;
}
export function approvalTranscript(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('invalid approval');
  const allowed=['accountId','requestId','candidateDeviceId','approverDeviceId','candidateKeySha256','nonceSha256','expiresAt'];
  if (Object.keys(input).sort().join(',')!==[...allowed].sort().join(',')) throw new Error('unexpected or missing field');
  const account=requireField(input.accountId,UUID,'account');
  const request=requireField(input.requestId,UUID,'request');
  const candidate=requireField(input.candidateDeviceId,UUID,'candidate');
  const approver=requireField(input.approverDeviceId,UUID,'approver');
  if(candidate===approver) throw new Error('self approval');
  const keyHash=requireField(input.candidateKeySha256,HEX,'key hash');
  const nonceHash=requireField(input.nonceSha256,HEX,'nonce hash');
  if (!Number.isSafeInteger(input.expiresAt) || input.expiresAt<=0) throw new Error('invalid expiry');
  return ['BHARATHLINK-DEVICE-APPROVAL-V1',account,request,candidate,approver,keyHash,nonceHash,String(input.expiresAt)].join('\n');
}
