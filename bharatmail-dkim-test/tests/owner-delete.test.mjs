import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const sql=readFileSync(new URL('../../supabase/sql/bharatmail_owner_received_inbox_delete_v1.sql',import.meta.url),'utf8');

test('Authenticated RLS deletes only own received inbox row, not sent or other-user rows',()=>{
 assert.match(sql,/alter table public\.bharatmail_external_messages enable row level security/i);
 assert.match(sql,/grant delete on public\.bharatmail_external_messages to authenticated/i);
 assert.match(sql,/for delete to authenticated/i);
 assert.match(sql,/recipient_user_id=\(select auth\.uid\(\)\)/i);
 assert.match(sql,/direction='inbound'/i);
 assert.doesNotMatch(sql,/grant delete on public\.bharatmail_received_attachment_snapshots/i);
 assert.doesNotMatch(sql,/grant delete .* to anon/i);
 assert.doesNotMatch(sql,/security definer/i);
});
test('Manual removal requires TWO actual user decisions; never starts on page load',()=>{
 assert.match(html,/removeBtn\.addEventListener\('click',async\(\)=>\{/);
 assert.match(html,/window\.confirm\('Remove this one email/);
 assert.match(html,/window\.prompt\('Type REMOVE to confirm/);
 assert.match(html,/if\(typed!=='REMOVE'\)/);
 const start=html.indexOf("removeBtn.addEventListener('click'");
 const confirm=html.indexOf('window.confirm(',start);
 const prompt=html.indexOf('window.prompt(',start);
 const deleteRequest=html.indexOf("'DELETE',undefined,true",start);
 assert.ok(start>=0&&confirm>start&&prompt>confirm&&deleteRequest>prompt);
 assert.ok(!html.slice(0,start).includes("request('/rest/v1/bharatmail_external_messages?id=eq."));
});
test('Owner signed-in DELETE is tightly bound to valid ID and inbound direction, returns an exact row',()=>{
 assert.match(html,/if\(method==='DELETE'\)h\.Prefer='return=representation'/);
 assert.match(html,/if\(authorized\)\{if\(!token\)throw Error\('Sign in required\.'\)/);
 assert.match(html,/\/rest\/v1\/bharatmail_external_messages\?id=eq\.'\+encodeURIComponent\(row\.id\)/);
 assert.match(html,/&direction=eq\.inbound&select=id/);
 assert.match(html,/if\(!Array\.isArray\(removed\)\|\|removed\.length!==1\|\|removed\[0\]\?\.id!==row\.id\)/);
 assert.match(html,/if\(!\/\^\[a-f0-9\]\{8\}/);
});
test('Metadata is independently read back after parent deletion; no optimistic success on failure',()=>{
 assert.match(html,/\/rest\/v1\/bharatmail_received_attachment_snapshots\?select=external_message_id/);
 assert.match(html,/if\(!Array\.isArray\(left\)\|\|left\.length!==0\)/);
 assert.match(html,/section\.remove\(\)/);
 assert.match(html,/Removal NOT CONFIRMED\. Refresh inbox to check before retrying/);
 assert.match(html,/setStatus\('One received TEST inbox email and its linked metadata were removed/);
 assert.doesNotMatch(html,/DELETE FROM bharatmail_inbound_events/);
});
test('TEST UI accurately warns signed source events, original provider, backups and bytes persist',()=>{
 assert.match(html,/signed inbound-event record, backups and stored file bytes will NOT be erased/);
 assert.match(html,/Original provider mail, signed event records, backups and any stored file bytes are outside this removal/);
 assert.match(html,/No email will be removed without your confirmation/);
 assert.match(html,/Remove this received TEST email and saved metadata/);
 assert.doesNotMatch(sql,/delete from public\.bharatmail_inbound_events/i);
 assert.doesNotMatch(sql,/delete from storage\.objects/i);
});
test('CSP inline-script hash independently matches changed UI',()=>{
 const content=html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
 const inline=html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
 assert.ok(content&&inline);
 const sha=createHash('sha256').update(inline).digest('base64');
 assert.ok(content.includes('script-src &#x27;sha256-'+sha+'&#x27;'));
});

test('Private stored-file guard fails closed before FK cascade and leaves no storage bytes orphaned',()=>{
 const guard=readFileSync(new URL('../../supabase/sql/bharatmail_received_delete_stored_file_guard_v1.sql',import.meta.url),'utf8');
 assert.match(guard,/create schema if not exists bharatmail_private/);
 assert.match(guard,/revoke all on schema bharatmail_private from public, anon, authenticated/);
 assert.match(guard,/security definer/);
 assert.match(guard,/set search_path=pg_catalog/);
 assert.match(guard,/public\.bharatmail_external_attachments a/);
 assert.match(guard,/a\.external_message_id=old\.id/);
 assert.match(guard,/raise exception 'stored_file_cleanup_required'/);
 assert.match(guard,/before delete on public\.bharatmail_external_messages/);
 assert.match(guard,/revoke all on function bharatmail_private\.prevent_inbox_delete_with_stored_files\(\)/);
 assert.doesNotMatch(guard,/delete from storage\.objects/i);
});
