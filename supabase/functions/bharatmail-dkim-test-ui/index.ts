/** BharathLink Mail TEST web page — retired from the Supabase Edge host.
 * Supabase's default *.supabase.co Edge Function gateway explicitly rewrites
 * text/html as text/plain. Returning source-code text is not a working login
 * page. Serve the mobile static frontend from a normal static HTTPS host
 * (e.g. a separate Netlify TEST site). Keep authenticated DKIM API in Supabase.
 *
 * Docs: https://supabase.com/docs/guides/functions/http-methods
 */
Deno.serve((req:Request)=>{
  if(req.method!=="GET")return Response.json({error:"method_not_allowed"},{
    status:405,headers:{"cache-control":"no-store","allow":"GET"}
  });
  return Response.json({
    status:"html_not_supported_on_default_edge_domain",
    message:"This is a read-only notice, NOT a login website.",
    next_step:"Use the standalone BharatLink Mail DKIM TEST static site on a separate HTTPS host.",
    authenticated_api_name:"bharatmail-dkim-check-test",
    raw_email_data_included:false,
    dkim_sender_verified:false,
    production_authorized:false
  },{status:410,headers:{
    "cache-control":"no-store",
    "x-content-type-options":"nosniff",
    "referrer-policy":"no-referrer"
  }});
});
