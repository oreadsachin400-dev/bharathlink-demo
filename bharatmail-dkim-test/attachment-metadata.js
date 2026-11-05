/* BharatMail TEST — metadata-only attachment cautions.
 * No file read, file download, decompression, content hashing, URL opening,
 * malware verdict, or sender authentication. Untrusted metadata can lie.
 */
(function(root,factory){
  'use strict';
  const api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  if(root)root.BharatMailAttachmentMetadata=api;
})(typeof window!=='undefined'?window:null,function(){
  'use strict';
  const VERSION='bharatmail-attachment-metadata-v1-2026-11-05';
  const MAX_FILES=20;
  const LARGE_BYTES=25*1024*1024;
  const RISKY_EXT=new Set([
    'exe','com','scr','pif','bat','cmd','ps1','psm1','vbs','vbe',
    'js','jse','wsf','wsh','hta','msi','msp','jar','lnk','iso','img'
  ]);
  const ACTIVE_EXT=new Set(['htm','html','svg','svgz','docm','xlsm','pptm']);
  const MIME=Object.freeze({
    pdf:['application/pdf'],
    png:['image/png'],
    jpg:['image/jpeg'],jpeg:['image/jpeg'],
    gif:['image/gif'],
    webp:['image/webp'],
    txt:['text/plain'],
    csv:['text/csv','application/csv','application/vnd.ms-excel'],
    zip:['application/zip','application/x-zip-compressed'],
    docx:['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    xlsx:['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
    pptx:['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
    docm:['application/vnd.ms-word.document.macroenabled.12'],
    xlsm:['application/vnd.ms-excel.sheet.macroenabled.12'],
    pptm:['application/vnd.ms-powerpoint.presentation.macroenabled.12']
  });
  function sizeValue(raw){
    if(typeof raw==='number' && Number.isSafeInteger(raw)&&raw>=0)return raw;
    if(typeof raw==='string'&&/^(?:0|[1-9]\d{0,15})$/.test(raw)){
      const n=Number(raw);
      if(Number.isSafeInteger(n))return n;
    }
    return null;
  }
  function scan(records){
    if(!Array.isArray(records))throw Error('No trusted metadata list available.');
    const reasons=[];
    const put=(code,severity,reason)=>{
      if(!reasons.some(x=>x.code===code))
        reasons.push(Object.freeze({code,severity,reason}));
    };
    let inspected=0,limited=records.length>MAX_FILES;
    for(const entry of records.slice(0,MAX_FILES)){
      inspected++;
      if(!entry||typeof entry!=='object'||Array.isArray(entry)){
        put('ATTACHMENT_METADATA_INCOMPLETE','medium','Some attachment metadata was unavailable or malformed.');
        continue;
      }
      const raw=entry.filename;
      const mime=typeof entry.content_type==='string'?entry.content_type.trim().toLowerCase():null;
      const size=sizeValue(entry.size_bytes);
      if(typeof raw!=='string'||raw.length<1||raw.length>255||!mime||mime.length>160||
         size===null){
        put('ATTACHMENT_METADATA_INCOMPLETE','medium','Attachment name, MIME type or size is absent, invalid or outside the inspection limit.');
      }
      if(size!==null&&size>LARGE_BYTES){
        put('ATTACHMENT_LARGE','medium','An attachment is larger than the conservative 25 MiB caution threshold.');
      }
      if(typeof raw!=='string'||raw.length>255)continue;
      if(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069\u200b-\u200d\u2060\ufeff]/u.test(raw)||
         raw!==raw.normalize('NFKC')||
         /[. ]$/u.test(raw)){
        put('ATTACHMENT_FILENAME_OBFUSCATED','high',
          'Filename contains control, hidden-direction, compatibility or trailing characters that can disguise its meaning.');
      }
      const name=raw.normalize('NFKC').toLowerCase().trim();
      const suffixes=name.split('.').map(x=>x.trim());
      const ext=suffixes.length>1?suffixes.at(-1):'';
      const preceding=suffixes.length>2?suffixes.at(-2):'';
      if(!ext||ext.length>24||!/^[a-z0-9]+$/.test(ext)){
        put('ATTACHMENT_UNKNOWN_TYPE','medium','Filename extension cannot be confidently classified.');
        continue;
      }
      if(RISKY_EXT.has(ext)){
        put('ATTACHMENT_EXECUTABLE_TYPE','high',
          'The filename has an executable, script or launchable extension. Do not open it.');
        if(preceding&&Object.hasOwn(MIME,preceding)){
          put('ATTACHMENT_DOUBLE_EXTENSION','high',
            'A filename disguises a launchable extension after a document or image extension.');
        }
      }else if(ACTIVE_EXT.has(ext)){
        put('ATTACHMENT_ACTIVE_CONTENT','medium',
          'The extension may contain macros or active web content; verify independently.');
      }
      const expected=MIME[ext];
      if(expected&&mime&&mime.length<=160&&
         !expected.includes(mime.split(';')[0].trim())&&
         mime!=='application/octet-stream'){
        put('ATTACHMENT_MIME_MISMATCH','medium',
          'Declared MIME type differs from the filename extension. Sender-controlled metadata is not proof of file contents.');
      }
      if(mime==='application/octet-stream'){
        put('ATTACHMENT_GENERIC_MIME','info',
          'Generic binary MIME type cannot corroborate a filename extension.');
      }
    }
    if(limited)put('ATTACHMENT_SCAN_INCOMPLETE','medium','Only the first 20 attachment metadata entries were examined.');
    return Object.freeze({
      version:VERSION,status:reasons.length?'caution':'no_metadata_signals',
      reasonCodes:Object.freeze(reasons.map(x=>x.code)),
      reasons:Object.freeze(reasons),metadataEntriesInspected:inspected,
      listTruncated:limited,coverage:'metadata_only',
      fileBytesInspected:false,malwareScanned:false,
      isAttachmentSafe:false,isMalwareProven:false,
      senderIdentityVerified:false,organizationVerified:false
    });
  }
  return Object.freeze({VERSION,scan});
});
