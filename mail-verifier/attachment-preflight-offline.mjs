/**
 * BharathLink Mail: isolated OFFLINE attachment preflight for future sandboxed
 * receiver integration. Never fetch, unzip, parse active content or execute.
 * Static file type/metadata checks are not malware detection.
 */
const MAX_ATTACHMENT_BYTES=8*1024*1024;
const MAX_FILENAME=255;
const RISKY=new Set([
 'exe','dll','scr','msi','msp','com','bat','cmd','ps1','psm1','vbs','vbe',
 'js','jse','wsf','wsh','hta','lnk','url','reg','jar','apk','aab',
 'sh','bash','py','rb','php','pl','dmg','app','iso','img',
 'docm','xlsm','pptm','xlam','xltm','dotm',
 'html','htm','svg','xhtml'
]);
const CONTAINERS=new Set(['zip','rar','7z','gz','tgz','tar','bz2','xz','cab','docx','xlsx','pptx','odt','ods','odp']);
const MIME_ALLOWED={
 pdf:['application/pdf'],
 png:['image/png'],
 jpg:['image/jpeg'],
 jpeg:['image/jpeg'],
 gif:['image/gif'],
 webp:['image/webp'],
 txt:['text/plain']
};
const EXT=new Set([...RISKY,...CONTAINERS,...Object.keys(MIME_ALLOWED)]);
function push(list,code){if(!list.includes(code))list.push(code);}
function sniff(head){
 if(!(head instanceof Uint8Array)||head.length<4)return 'unknown';
 const prefix=(...bytes)=>bytes.every((v,i)=>head[i]===v);
 if(prefix(0x4d,0x5a))return 'windows_executable';
 if(prefix(0x7f,0x45,0x4c,0x46))return 'elf_executable';
 if(prefix(0x23,0x21))return 'script';
 if(prefix(0x50,0x4b,0x03,0x04)||prefix(0x50,0x4b,0x05,0x06)||prefix(0x50,0x4b,0x07,0x08))return 'zip_container';
 if(prefix(0x25,0x50,0x44,0x46,0x2d))return 'pdf';
 if(prefix(0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a))return 'png';
 if(prefix(0xff,0xd8,0xff))return 'jpeg';
 if(prefix(0x47,0x49,0x46,0x38)&&[0x37,0x39].includes(head[4])&&head[5]===0x61)return 'gif';
 if(prefix(0x52,0x49,0x46,0x46)&&head.length>=12&&
   head[8]===0x57&&head[9]===0x45&&head[10]===0x42&&head[11]===0x50)return 'webp';
 if(prefix(0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1))return 'ole_container';
 if(prefix(0x1f,0x8b))return 'gzip_container';
 if(prefix(0x37,0x7a,0xbc,0xaf,0x27,0x1c))return '7zip_container';
 if(prefix(0x52,0x61,0x72,0x21,0x1a,0x07))return 'rar_container';
 return 'unknown';
}
function inspectAttachmentPreflight({filename,mime,sizeBytes,bytes}={}){
 const warnings=[];
 const name=typeof filename==='string'?filename:'';
 const declared=typeof mime==='string'?mime.trim().toLowerCase():'';
 const b=bytes instanceof Uint8Array?bytes:null;
 const validSize=Number.isSafeInteger(sizeBytes)&&sizeBytes>=0&&sizeBytes<=MAX_ATTACHMENT_BYTES;
 if(!name||name.length>MAX_FILENAME||/[\x00-\x1f\x7f/\\]/.test(name)||
    name==='.'||name==='..'||/^\.+$/.test(name))push(warnings,'invalid_filename');
 if(/[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2060\ufeff]/u.test(name))
  push(warnings,'disguised_unicode_filename');
 const normalized=name.normalize('NFC');
 const parts=normalized.toLowerCase().split('.');
 const ext=parts.length>1?parts.at(-1):'';
 if(!ext||!EXT.has(ext))push(warnings,'unknown_or_unsupported_extension');
 if(RISKY.has(ext))push(warnings,'active_or_executable_extension');
 if(CONTAINERS.has(ext))push(warnings,'archive_or_container_cannot_be_inspected');
 if(parts.length>=3&&RISKY.has(ext))push(warnings,'double_extension_may_disguise_payload');
 if(!validSize)push(warnings,'size_unavailable_or_exceeds_cap');
 if(!b)push(warnings,'bytes_not_available_for_analysis');
 else {
  if(b.length>MAX_ATTACHMENT_BYTES)push(warnings,'content_exceeds_scan_cap');
  if(validSize&&b.length!==sizeBytes)push(warnings,'size_metadata_mismatch');
  const type=sniff(b);
  if(['windows_executable','elf_executable','script','ole_container'].includes(type))
   push(warnings,'executable_or_active_content_signature');
  if(['zip_container','gzip_container','7zip_container','rar_container'].includes(type))
   push(warnings,'container_signature_not_unpacked');
  const expected={pdf:'pdf',png:'png',jpg:'jpeg',jpeg:'jpeg',gif:'gif',webp:'webp'};
  if(Object.hasOwn(expected,ext)&&type!==expected[ext])
   push(warnings,'extension_signature_mismatch');
  if(type==='unknown'&&ext!=='txt')push(warnings,'unrecognized_file_signature');
 }
 if(!declared||declared.length>127||/[\r\n\0]/.test(declared))push(warnings,'declared_mime_missing_or_invalid');
 if(MIME_ALLOWED[ext]&&declared&&declared.length<=127&&!MIME_ALLOWED[ext].includes(declared))
  push(warnings,'extension_mime_mismatch');
 if(b&&b.length===0)push(warnings,'empty_attachment');
 // No attachment is automatically safe; static sniff is not AV/sandboxing.
 // Do not return raw attachment bytes, a preview URL or a trust badge.
 return Object.freeze({
  verdict:'not_scanned_for_malware',
  warnings:Object.freeze(warnings.slice(0,16)),
  byte_preflight_performed:!!b&&b.length<=MAX_ATTACHMENT_BYTES,
  allowed_to_preview:false,allowed_to_execute:false,allowed_to_download_automatically:false,
  email_sender_identity:'not_verified',attachment_safe:false,production_release_authorized:false
 });
}
export {MAX_ATTACHMENT_BYTES,inspectAttachmentPreflight};
