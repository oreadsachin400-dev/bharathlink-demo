import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {Script} from 'node:vm';
const req=createRequire(import.meta.url);
const engine=req('../attachment-metadata.js');
const code=readFileSync(new URL('../attachment-metadata.js',import.meta.url),'utf8');
const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const demo=readFileSync(new URL('../attachment-demo.html',import.meta.url),'utf8');
const codes=files=>engine.scan(files).reasonCodes;
const sha=x=>createHash('sha256').update(x).digest('base64');
test('Executables, double extensions and scripts trigger caution but never malware verdict',()=>{
 for(const name of ['invoice.pdf.exe','payroll.docx.js','photo.jpg.scr','setup.msi','invoice.pdf.bat','alert.ps1']){
  const r=engine.scan([{filename:name,content_type:'application/octet-stream',size_bytes:1024}]);
  assert.ok(r.reasonCodes.includes('ATTACHMENT_EXECUTABLE_TYPE'),name);
  assert.equal(r.isMalwareProven,false);assert.equal(r.isAttachmentSafe,false);
  assert.equal(r.fileBytesInspected,false);
 }
 assert.ok(codes([{filename:'invoice.pdf.exe',content_type:'application/octet-stream',size_bytes:'33'}]).includes('ATTACHMENT_DOUBLE_EXTENSION'));
});
test('Macro documents and active HTML/SVG are cautions, not proof of malware',()=>{
 for(const name of ['report.docm','budget.xlsm','presentation.pptm','receipt.html','vector.svg']){
  const r=engine.scan([{filename:name,content_type:'application/octet-stream',size_bytes:200}]);
  assert.ok(r.reasonCodes.includes('ATTACHMENT_ACTIVE_CONTENT'),name);
  assert.equal(r.malwareScanned,false);
 }
});
test('MIME mismatch, generic MIME and attachment size are independent metadata indicators',()=>{
 const f=(filename,content_type,size_bytes)=>[{filename,content_type,size_bytes}];
 assert.ok(codes(f('invoice.pdf','image/png',1)).includes('ATTACHMENT_MIME_MISMATCH'));
 assert.ok(!codes(f('invoice.pdf','application/pdf',1)).includes('ATTACHMENT_MIME_MISMATCH'));
 assert.ok(codes(f('invoice.pdf','application/octet-stream',1)).includes('ATTACHMENT_GENERIC_MIME'));
 assert.ok(codes(f('large.pdf','application/pdf',25*1024*1024+1)).includes('ATTACHMENT_LARGE'));
 assert.ok(!codes(f('large.pdf','application/pdf',25*1024*1024)).includes('ATTACHMENT_LARGE'));
});
test('Bidi, zero-width, trailing and Unicode compatibility characters are flagged',()=>{
 for(const name of ['pay\u202eexe.pdf','doc\u200b.pdf','receipt.pdf.','file\u0000.exe','Ｆile.pdf']){
  const r=engine.scan([{filename:name,content_type:'application/pdf',size_bytes:10}]);
  assert.ok(r.reasonCodes.includes('ATTACHMENT_FILENAME_OBFUSCATED'),JSON.stringify(name));
 }
});
test('Missing, malformed and truncated metadata are never declared clean',()=>{
 for(const file of [
  {filename:'',content_type:'application/pdf',size_bytes:1},
  {filename:'file.pdf',content_type:'',size_bytes:1},
  {filename:'file.pdf',content_type:'application/pdf',size_bytes:'999999999999999999999'},
  {filename:'file.pdf',content_type:'application/pdf',size_bytes:-1},
  {filename:'a'.repeat(256)+'.pdf',content_type:'application/pdf',size_bytes:1}
 ])assert.ok(codes([file]).includes('ATTACHMENT_METADATA_INCOMPLETE'));
 const list=Array.from({length:21},(_,i)=>({filename:'file'+i+'.pdf',content_type:'application/pdf',size_bytes:1}));
 const r=engine.scan(list);
 assert.ok(r.reasonCodes.includes('ATTACHMENT_SCAN_INCOMPLETE'));
 assert.equal(r.metadataEntriesInspected,20);
 assert.equal(r.listTruncated,true);
 assert.equal(r.isAttachmentSafe,false);
});
test('No metadata warning and empty list are still NOT a safe-file conclusion',()=>{
 for(const records of [[],[{filename:'photo.jpg',content_type:'image/jpeg',size_bytes:100}]]){
  const r=engine.scan(records);
  assert.equal(r.status,'no_metadata_signals');
  assert.equal(r.isAttachmentSafe,false);
  assert.equal(r.senderIdentityVerified,false);
  assert.equal(r.organizationVerified,false);
  assert.equal(r.fileBytesInspected,false);
 }
 assert.throws(()=>engine.scan(null));
});
test('TEST inbox only invokes JWT-backed provider metadata gateway after explicit click',()=>{
 assert.match(html,/attachmentBtn\.addEventListener\('click',async\(\)=>\{/);
 assert.match(html,/\/functions\/v1\/bharatmail-attachment-metadata-test/);
 assert.match(html,/request\(\s*'\/functions\/v1\/bharatmail-attachment-metadata-test','POST',\s*\{message_id:row\.id\},true\s*\)/);
 assert.match(html,/evidence\.source!=='resend_receiving_attachments_api'/);
 assert.match(html,/evidence\.files_downloaded!==false/);
 assert.match(html,/evidence\.malware_scanned!==false/);
 assert.match(html,/evidence\.verified_sender_badge!==false/);
 assert.match(html,/evidence\.items\.length>20/);
 assert.match(html,/window\.BharatMailAttachmentMetadata\.scan\(evidence\.items\)/);
 assert.match(html,/INCOMPLETE provider metadata/);
 assert.doesNotMatch(html,/\/rest\/v1\/bharatmail_external_attachments\?select=/);
 assert.doesNotMatch(html,/select=[^'"\n]*(?:storage_path|provider_attachment_id|key_b64|iv_b64)/);
 assert.doesNotMatch(code,/\b(?:fetch|XMLHttpRequest|sendBeacon)\s*\(/);
});
test('Six-case synthetic demo and real TEST inbox pin exact attachment JS with CSP/SRI',()=>{
 const script=demo.match(/<script>([\s\S]*?)<\/script>/)?.[1];
 const style=demo.match(/<style>([\s\S]*?)<\/style>/)?.[1];
 const csp=demo.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
 const inboxCsp=html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
 assert.ok(script&&style&&csp&&inboxCsp);
 assert.match(demo,/Try 6 fictional attachment examples/);
 assert.ok(csp.includes('default-src &#x27;none&#x27;'));
 for(const x of [script,style,code])assert.ok(csp.includes('&#x27;sha256-'+sha(x)+'&#x27;'));
 assert.ok(inboxCsp.includes('&#x27;sha256-'+sha(code)+'&#x27;'));
 for(const h of [html,demo])assert.ok(h.includes('src="./attachment-metadata.js" integrity="sha256-'+sha(code)+'"'));
 assert.doesNotMatch(demo,/\bfetch\s*\(|XMLHttpRequest|localStorage|sessionStorage|<input|<textarea|<form/);
 assert.doesNotThrow(()=>new Script(script));
});
