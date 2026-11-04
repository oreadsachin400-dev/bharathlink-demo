import test from 'node:test';
import assert from 'node:assert/strict';
import {MAX_ATTACHMENT_BYTES,inspectAttachmentPreflight as scan} from '../attachment-preflight-offline.mjs';
const u=(...bytes)=>new Uint8Array(bytes);
const png=u(137,80,78,71,13,10,26,10,0,0,0,0);
const pdf=u(37,80,68,70,45,49,46,55,10,0,0,0);
const exe=u(77,90,0,0,0,0,0,0);
const zip=u(80,75,3,4,0,0,0,0);
const check=(result)=>{
 assert.equal(result.verdict,'not_scanned_for_malware');
 assert.equal(result.allowed_to_execute,false);
 assert.equal(result.allowed_to_preview,false);
 assert.equal(result.allowed_to_download_automatically,false);
 assert.equal(result.email_sender_identity,'not_verified');
 assert.equal(result.attachment_safe,false);
 assert.equal(result.production_release_authorized,false);
 assert.ok(Object.isFrozen(result));assert.ok(Object.isFrozen(result.warnings));
};
test('even matching PNG metadata+signature is NOT malware cleared or previewable',()=>{
 const r=scan({filename:'photo.png',mime:'image/png',sizeBytes:png.length,bytes:png});
 check(r);assert.deepEqual(r.warnings,[]);assert.equal(r.byte_preflight_performed,true);
});
test('a signed-looking PDF is never auto-previewed or declared safe',()=>{
 const r=scan({filename:'invoice.pdf',mime:'application/pdf',sizeBytes:pdf.length,bytes:pdf});
 check(r);assert.deepEqual(r.warnings,[]);
});
test('double-extension executable impersonating a PDF is flagged',()=>{
 const r=scan({filename:'invoice.pdf.exe',mime:'application/pdf',sizeBytes:exe.length,bytes:exe});
 check(r);assert.ok(r.warnings.includes('active_or_executable_extension'));assert.ok(r.warnings.includes('double_extension_may_disguise_payload'));assert.ok(r.warnings.includes('executable_or_active_content_signature'));
});
test('fake PNG carrying MZ executable is flagged for both signature and extension',()=>{
 const r=scan({filename:'photo.png',mime:'image/png',sizeBytes:exe.length,bytes:exe});
 check(r);assert.ok(r.warnings.includes('extension_signature_mismatch'));assert.ok(r.warnings.includes('executable_or_active_content_signature'));
});
test('ZIP/Office containers are never unpacked or marked safe',()=>{
 const r=scan({filename:'invoice.docx',mime:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',sizeBytes:zip.length,bytes:zip});
 check(r);assert.ok(r.warnings.includes('archive_or_container_cannot_be_inspected'));assert.ok(r.warnings.includes('container_signature_not_unpacked'));
});
test('suspicious active and macro extensions are flagged even when bytes missing',()=>{
 for(const ext of ['svg','html','ps1','js','apk','docm','xlsm','pptm','lnk','bat','jar']){
  const r=scan({filename:'file.'+ext,mime:'application/octet-stream',sizeBytes:20});
  check(r);assert.ok(r.warnings.includes('active_or_executable_extension'),ext);
  assert.ok(r.warnings.includes('bytes_not_available_for_analysis'),ext);
 }
});
test('malicious filename traversal, bidi overrides and control chars are flagged',()=>{
 for(const name of ['../secret.png','foo\\bad.exe','evil\r\nname.png','...']){
  const r=scan({filename:name,mime:'image/png',sizeBytes:png.length,bytes:png});
  check(r);assert.ok(r.warnings.includes('invalid_filename'),name);
 }
 const bidi=scan({filename:'invoice\u202Egnp.exe',mime:'application/pdf',sizeBytes:exe.length,bytes:exe});
 assert.ok(bidi.warnings.includes('disguised_unicode_filename'));check(bidi);
});
test('size cap, mismatch and negative size fail closed',()=>{
 const huge=scan({filename:'archive.zip',mime:'application/zip',sizeBytes:MAX_ATTACHMENT_BYTES+1,bytes:zip});
 check(huge);assert.ok(huge.warnings.includes('size_unavailable_or_exceeds_cap'));
 const bad=scan({filename:'photo.png',mime:'image/png',sizeBytes:2,bytes:png});
 check(bad);assert.ok(bad.warnings.includes('size_metadata_mismatch'));
 const neg=scan({filename:'photo.png',mime:'image/png',sizeBytes:-5,bytes:png});
 check(neg);assert.ok(neg.warnings.includes('size_unavailable_or_exceeds_cap'));
});
test('unrecognized, extension-MIME mismatch, missing bytes and empty file are never trusted',()=>{
 const mismatch=scan({filename:'report.pdf',mime:'image/png',sizeBytes:pdf.length,bytes:pdf});
 check(mismatch);assert.ok(mismatch.warnings.includes('extension_mime_mismatch'));
 const missing=scan({filename:'report.pdf',mime:'application/pdf',sizeBytes:12});
 check(missing);assert.ok(missing.warnings.includes('bytes_not_available_for_analysis'));
 const empty=scan({filename:'empty.jpg',mime:'image/jpeg',sizeBytes:0,bytes:new Uint8Array()});
 check(empty);assert.ok(empty.warnings.includes('empty_attachment'));
 const unknown=scan({filename:'unknown.xyz',mime:'application/octet-stream',sizeBytes:2,bytes:u(0,0)});
 check(unknown);assert.ok(unknown.warnings.includes('unknown_or_unsupported_extension'));
});
test('no file contents, attachment URLs, OCR or executable payload in returned report',()=>{
 const r=scan({filename:'something.txt',mime:'text/plain',sizeBytes:exe.length,bytes:exe});
 check(r);assert.equal(Object.keys(r).includes('bytes'),false);
 assert.equal(Object.keys(r).includes('url'),false);
 assert.equal(JSON.stringify(r).includes('something.txt'),false);
});
