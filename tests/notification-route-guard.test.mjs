import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';

const script = readFileSync(new URL('../bharatmail-sw.js', import.meta.url), 'utf8');
const scope = 'https://bharathlink-20-test.netlify.app/app/';
const target = hash => scope + hash;

function makeSW(hasClient=true) {
  const handlers=new Map(), notifications=[], visited=[];
  const self={
    addEventListener:(name,fn)=>handlers.set(name,fn),
    registration:{scope,showNotification:async(title,options)=>{notifications.push({title,options});}},
    clients:{
      matchAll:async()=>hasClient?[{navigate:async u=>{visited.push(u);},focus:async()=>{}}]:[],
      openWindow:async u=>{visited.push(u);}
    },
    skipWaiting(){}
  };
  runInNewContext(script,{self,URL});
  return {
    async push(payload){
      const pending=[];
      handlers.get('push')({data:{json:()=>payload},waitUntil:p=>pending.push(p)});
      await Promise.all(pending);
      return notifications.at(-1).options.data;
    },
    async click(data){
      const pending=[];
      handlers.get('notificationclick')({notification:{data,close(){}},waitUntil:p=>pending.push(p)});
      await Promise.all(pending);
      return visited[0];
    }
  };
}

test('same-scope reminder route accepted',async()=>{
  const sw=makeSW();
  const data=await sw.push({type:'reminder',url:'./#/reminders/item_42'});
  assert.equal(data.url,target('#/reminders/item_42'));
  assert.equal(await sw.click(data),target('#/reminders/item_42'));
});

test('external and ambiguous reminder destinations fail closed',async()=>{
  for(const value of [
    'https://evil.example/', '//evil.example/path', 'javascript:alert(1)',
    'data:text/html,hi', '../#/mail', '/other/#/mail',
    './?token=1#/mail', './#/login', './#//evil.example',
    '#/mail?to=outside@example.org', './#/mail/../../../evil',
    '\u0000https://evil.example'
  ]){
    const sw=makeSW();
    const data=await sw.push({type:'reminder',url:value});
    assert.equal(data.url,target('#/home'),value);
    assert.equal(await sw.click(data),target('#/home'),value);
  }
});

test('forged click data is revalidated even without an existing client',async()=>{
  const sw=makeSW(false);
  assert.equal(await sw.click({type:'message',url:'https://evil.example'}),target('#/chats'));
  const sw2=makeSW(false);
  assert.equal(await sw2.click({type:'bharatmail',url:'javascript:alert(1)'}),target('#/mail'));
});

test('normal E2EE message and mail push routes remain intact',async()=>{
  const a=makeSW(),b=makeSW();
  const dm=await a.push({type:'message',event_id:'ev'});
  const mail=await b.push({type:'bharatmail',mail_id:'id'});
  assert.equal(dm.url,target('#/chats'));
  assert.equal(mail.url,target('#/mail'));
  assert.equal(await a.click(dm),target('#/chats'));
  assert.equal(await b.click(mail),target('#/mail'));
});

test('malformed JSON payload resolves to existing mail fallback',async()=>{
  const sw=makeSW();
  const data=await sw.push(null);
  assert.equal(data.url,target('#/mail'));
});
