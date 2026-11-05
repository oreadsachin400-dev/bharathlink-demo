/** Only signed pg_cron requests authenticated by Vault-backed RPC can invoke. */
import {createRetryHandler} from './retry-worker.mjs';
Deno.serve(createRetryHandler({
 getEnv:(name:string)=>Deno.env.get(name),
 fetchFn:(url:string,options:RequestInit)=>fetch(url,options)
}));
