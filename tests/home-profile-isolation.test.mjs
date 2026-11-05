import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Script} from 'node:vm';

const source=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const A='11111111-1111-4111-8111-111111111111';
const B='22222222-2222-4222-8222-222222222222';
const photo='data:image/jpeg;base64,bG9jYWwtdGVzdA==';
function getObject(name){
 const marker='const '+name+' = {',at=source.indexOf(marker);
 assert.ok(at>=0,name+' object missing');
 const close=source.indexOf('\n};',at);
 assert.ok(close>at,name+' object end missing');
 return source.slice(at+('const '+name+' = ').length,close+2);
}
function jwt(uid){
 const payload=Buffer.from(JSON.stringify({sub:uid})).toString('base64url');
 return 'eyJhbGciOiJIUzI1NiJ9.'+payload+'.mock-signature';
}
function harness(media={},prior='',accountId='local-sample'){
 const data=new Map(prior?[['bl_last_auth_user_v1',prior]]:[]);
 const localStorage={
  getItem:k=>data.has(k)?data.get(k):null,
  setItem:(k,v)=>data.set(k,String(v)),
  removeItem:k=>data.delete(k)
 };
 const Store={
  state:{
   account:{accountId},
   profileMedia:{ownerScope:null,photoData:null,photoUpdatedAt:null,status:null,...media}
  },
  persists:0,resets:0,
  update(fn){fn(this.state);this.persists++;},
  reset(){this.resets++;this.state={
    account:null,
    profileMedia:{ownerScope:null,photoData:null,photoUpdatedAt:null,status:null}
   };}
 };
 const Mail={remote:[],composeSeed:null,lastRefreshAt:0,refreshPromise:null};
 const Supabase=new Function('Store','localStorage','Mail','return ('+getObject('Supabase')+');')(Store,localStorage,Mail);
 const ProfileMedia=new Function('Store','Supabase','return ('+getObject('ProfileMedia')+');')(Store,Supabase);
 return {Supabase,ProfileMedia,Store,localStorage};
}
test('Legacy ownerless image cannot be rendered for Nidhi and is cleared at sign-in',()=>{
 const h=harness({photoData:photo},'');
 h.Supabase.setAccessToken(jwt(A));
 assert.equal(h.ProfileMedia.ownedPhoto(),'');
 assert.equal(h.Supabase.isolateLocalStateForAuthenticatedUser(),false);
 assert.equal(h.Store.state.profileMedia.ownerScope,'auth:'+A);
 assert.equal(h.Store.state.profileMedia.photoData,null);
 assert.equal(h.ProfileMedia.ownedPhoto(),'');
 assert.equal(h.ProfileMedia.activeStatus(),null);
 assert.equal(h.localStorage.getItem('bl_last_auth_user_v1'),A);
});
test('Switching authenticated users does not carry the first account photo or status',()=>{
 const h=harness({
  ownerScope:'auth:'+A,photoData:photo,
  status:{text:'Old account story',expiresAt:Date.now()+3600000}
 },A);
 h.Supabase.setAccessToken(jwt(B));
 assert.equal(h.ProfileMedia.ownedPhoto(),'');
 assert.equal(h.ProfileMedia.activeStatus(),null);
 assert.equal(h.Supabase.isolateLocalStateForAuthenticatedUser(),true);
 assert.equal(h.Store.resets,1);
 assert.equal(h.Store.state.profileMedia.ownerScope,'auth:'+B);
 assert.equal(h.Store.state.profileMedia.photoData,null);
 assert.equal(h.Store.state.profileMedia.status,null);
});
test('Same authenticated owner retains their new explicitly assigned photo',()=>{
 const h=harness({ownerScope:'auth:'+A,photoData:photo},A);
 h.Supabase.setAccessToken(jwt(A));
 assert.equal(h.Supabase.isolateLocalStateForAuthenticatedUser(),false);
 assert.equal(h.Store.resets,0);
 assert.equal(h.ProfileMedia.ownedPhoto(),photo);
 h.ProfileMedia.setPhoto('data:image/jpeg;base64,cmVwbGFjZQ==');
 assert.equal(h.Store.state.profileMedia.ownerScope,'auth:'+A);
 assert.equal(h.ProfileMedia.ownedPhoto(),'data:image/jpeg;base64,cmVwbGFjZQ==');
});
test('Local-only demo profile photo cannot carry across different local account IDs',()=>{
 const h=harness();
 h.ProfileMedia.setPhoto(photo);
 assert.equal(h.Store.state.profileMedia.ownerScope,'local:local-sample');
 assert.equal(h.ProfileMedia.ownedPhoto(),photo);
 h.Store.state.account.accountId='another-local-account';
 assert.equal(h.ProfileMedia.ownedPhoto(),'');
});
test('Status media is scoped to current owner and previous user stories are not visible',()=>{
 const h=harness();
 h.Supabase.setAccessToken(jwt(A));
 h.Supabase.isolateLocalStateForAuthenticatedUser();
 h.ProfileMedia.setStatus({text:'Only my status'});
 assert.equal(h.Store.state.profileMedia.ownerScope,'auth:'+A);
 assert.equal(h.ProfileMedia.activeStatus()?.text,'Only my status');
 h.Supabase.setAccessToken(jwt(B));
 assert.equal(h.ProfileMedia.activeStatus(),null);
});
test('No owner identity means no profile-photo assignment',()=>{
 const h=harness({},'',null);
 h.Store.state.account=null;
 assert.throws(()=>h.ProfileMedia.setPhoto(photo),/Account identity unavailable/);
 assert.equal(h.ProfileMedia.ownedPhoto(),'');
});
test('All visible own-profile avatars read scoped photo rather than unbound cached media',()=>{
 const start=source.indexOf('function ProfileAvatar(name, extra');
 const end=source.indexOf('function PeerAvatar(',start);
 const avatar=source.slice(start,end);
 assert.match(avatar,/const photo = ProfileMedia\.ownedPhoto\(\)/);
 assert.doesNotMatch(avatar,/Store\.state\?\.profileMedia\?\.photoData/);
 assert.match(source,/Button\(ProfileMedia\.ownedPhoto\(\) \? 'Change photo' : 'Add profile photo'/);
 assert.match(source,/ProfileMedia\.ownedPhoto\(\) \? Button\('Remove photo'/);
});
test('Cross-account remote profile sync never republishes an unscoped local image',()=>{
 const start=source.indexOf('async syncExistingLocal() {');
 const end=source.indexOf('\n  }\n};',start);
 const body=source.slice(start,end);
 assert.match(body,/const localPhoto=ProfileMedia\.ownedPhoto\(\)/);
 assert.match(body,/const scope=ProfileMedia\.ownerScope\(\)/);
 assert.match(body,/ProfileMedia\.ownerScope\(\)===scope/);
 assert.match(body,/remote\.photo_path\.startsWith\(ownerId\+'\/profile\/'\)/);
 assert.doesNotMatch(body,/const localPhoto = Store\.state\?\.profileMedia\?\.photoData/);
});
test('Existing photo clearing does not erase encrypted chats, email routing, or Supabase auth',()=>{
 const i=source.indexOf('isolateLocalStateForAuthenticatedUser(){');
 const j=source.indexOf('\n  async refreshAccessToken()',i);
 const body=source.slice(i,j);
 assert.match(body,/Store\.state\?\.profileMedia\?\.ownerScope!==scope/);
 assert.match(body,/st\.profileMedia=\{ownerScope:scope,photoData:null,photoUpdatedAt:null,status:null\}/);
 assert.doesNotMatch(body,/delete from|rpc\/|storage\/v1\/object/i);
 assert.match(source,/this\.authSubject\(\)/);
 assert.match(source,/Supabase\.restoreTestSession\(\)/);
});

test('Complete BharatLink browser bundle compiles after account-isolation patch',()=>{
 const match=source.match(/<script>([\s\S]*?)<\/script>/);
 assert.ok(match&&match[1].length>100000);
 assert.doesNotThrow(()=>new Script(match[1],{filename:'bharathlink-root-index-inline.js'}));
});
