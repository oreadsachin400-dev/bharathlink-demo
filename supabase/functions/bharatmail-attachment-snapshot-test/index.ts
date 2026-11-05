/** Separate TEST snapshot endpoint. Old read-only verifier and inbound webhook untouched. */
import {createSnapshotHandler} from './snapshot-handler.mjs';
Deno.serve(createSnapshotHandler({
  getEnv:(name:string)=>Deno.env.get(name),
  fetchFn:(url:string,options:RequestInit)=>fetch(url,options)
}));
