/** BharatMail TEST only — metadata read endpoint, no mail routing writes. */
import {createHandler} from './handler.mjs';
Deno.serve(createHandler({
  getEnv:(name:string)=>Deno.env.get(name),
  fetchFn:(url:string,options:RequestInit)=>fetch(url,options)
}));
