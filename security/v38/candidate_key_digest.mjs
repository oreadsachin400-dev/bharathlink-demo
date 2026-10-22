// Reference only: domain-separated digest binds BOTH enrollment public keys.
// Not a deployed registration or approval endpoint.
import {createHash} from 'node:crypto';
const BASE64URL=/^[A-Za-z0-9_-]+$/;
function decodeKey(value,length,name){
 if(typeof value!=='string'||!BASE64URL.test(value)) throw new Error('invalid '+name);
 const raw=Buffer.from(value,'base64url');
 if(raw.length!==length || raw.toString('base64url')!==value) throw new Error('invalid '+name);
 return raw;
}
export function candidateKeyDigest({signingPublicKey,curve25519PublicKey}){
 const signing=decodeKey(signingPublicKey,32,'signing key');
 const curve=decodeKey(curve25519PublicKey,32,'curve25519 key');
 return createHash('sha256')
  .update(Buffer.from('BHARATHLINK-E2EE-V2-CANDIDATE-KEYS-V1\0','utf8'))
  .update(signing).update(curve).digest('hex');
}
