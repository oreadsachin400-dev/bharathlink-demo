// Disposable worker: separate process races exact same checkpoint and file.
import {readFileSync} from 'node:fs';
import {persistCheckedWitnessCheckpoint}
  from '../../recovery-gate/witness-checkpoint-cas.mjs';
const [dbPath,payloadPath]=process.argv.slice(2);
if(!dbPath||!payloadPath)process.exit(3);
const p=JSON.parse(readFileSync(payloadPath,'utf8'));
const out=await persistCheckedWitnessCheckpoint({
  independentStorePath:dbPath,
  candidateCheckpoint:p.candidateCheckpoint,
  events:p.events,
  checkpointSignatureBase64Url:p.checkpointSignatureBase64Url,
  witnessRegistry:new Map(p.witnessRegistry),
  nowMs:p.nowMs
});
process.stdout.write(JSON.stringify(out)+'\n');
process.exitCode=out.checkpointPersisted?0:2;
