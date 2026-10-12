-- Vienna Stay Team app — database setup (its OWN Supabase project, separate from
-- the booking site). Paste the whole file into SQL Editor → Run. Safe to run again.
--
-- Design: every ops_* table has RLS ON and NO policies, so nobody can read or
-- write them directly. The app only talks to SECURITY DEFINER functions that
-- check a session token first. Staff get a token from the shared staff
-- password; the manager from the app's own manager username/password.

create extension if not exists pgcrypto;

create table if not exists ops_settings (k text primary key, v text);
create table if not exists ops_sessions (
  token uuid primary key default gen_random_uuid(),
  name text not null, role text not null check (role in ('staff','manager')),
  created_at timestamptz not null default now(), last_seen timestamptz not null default now());
create table if not exists ops_apartments (
  id text primary key, name text not null, location text, kind text not null default 'apartment',
  max_guests int, sort int, active boolean not null default true);
create table if not exists ops_photos (
  id uuid primary key default gen_random_uuid(), mime text not null, data text not null,
  by_name text, at timestamptz not null default now());
create table if not exists ops_items (
  id bigserial primary key, name_he text, name_de text, name_en text, name_ru text,
  category text not null default 'other', qty int not null default 0, min_qty int not null default 0,
  active boolean not null default true, sort int not null default 0, created_at timestamptz not null default now());
create table if not exists ops_moves (
  id bigserial primary key, item_id bigint not null references ops_items(id),
  kind text not null check (kind in ('take','break','return','add','adjust')),
  qty int not null, qty_after int, unit_id text, note text, by_name text not null,
  at timestamptz not null default now());
create table if not exists ops_issues (
  id bigserial primary key, unit_id text, category text not null default 'other',
  title text not null, details text, photo_id uuid references ops_photos(id),
  status text not null default 'open' check (status in ('open','done')),
  reported_by text not null, reported_at timestamptz not null default now(),
  resolved_by text, resolved_at timestamptz, resolution_note text);
create table if not exists ops_messages (
  id bigserial primary key, by_name text not null, body text, photo_id uuid references ops_photos(id),
  issue_id bigint references ops_issues(id), sys text, at timestamptz not null default now());

do $$ declare t text; begin
  foreach t in array array['ops_apartments','ops_settings','ops_sessions','ops_photos','ops_items','ops_moves','ops_issues','ops_messages'] loop
    execute format('alter table %I enable row level security', t);
    execute format('revoke all on %I from anon, authenticated', t);
  end loop;
end $$;

-- ---------- helpers (not callable from the app) ----------
create or replace function ops_sess(p_token uuid, p_need text default 'staff')
returns ops_sessions language plpgsql security definer set search_path = public as $$
declare s ops_sessions;
begin
  select * into s from ops_sessions where token = p_token and last_seen > now() - interval '90 days';
  if s.token is null then raise exception 'ops:auth'; end if;
  if p_need = 'manager' and s.role <> 'manager' then raise exception 'ops:forbidden'; end if;
  if s.last_seen < now() - interval '1 hour' then update ops_sessions set last_seen = now() where token = p_token; end if;
  return s;
end $$;

-- ---------- sign in ----------
create or replace function ops_staff_login(p_name text, p_pass text)
returns uuid language plpgsql security definer set search_path = public as $$
declare h text; t uuid;
begin
  if coalesce(trim(p_name),'') = '' then raise exception 'ops:name'; end if;
  select v into h from ops_settings where k = 'staff_pass';
  if h is null then raise exception 'ops:nopass'; end if;
  if crypt(coalesce(p_pass,''), h) <> h then perform pg_sleep(1.5); raise exception 'ops:badpass'; end if;
  insert into ops_sessions(name, role) values (left(trim(p_name), 40), 'staff') returning token into t;
  return t;
end $$;

drop function if exists ops_manager_login(text);

create or replace function ops_me(p_token uuid)
returns json language plpgsql security definer set search_path = public as $$
declare s ops_sessions := ops_sess(p_token);
begin return json_build_object('name', s.name, 'role', s.role,
  'has_pass', exists(select 1 from ops_settings where k='staff_pass')); end $$;

create or replace function ops_logout(p_token uuid)
returns void language sql security definer set search_path = public as $$
  delete from ops_sessions where token = p_token; $$;

create or replace function ops_set_staff_pass(p_token uuid, p_pass text, p_kick boolean default false)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform ops_sess(p_token, 'manager');
  if length(coalesce(p_pass,'')) < 4 then raise exception 'ops:short'; end if;
  insert into ops_settings(k, v) values ('staff_pass', crypt(p_pass, gen_salt('bf')))
    on conflict (k) do update set v = excluded.v;
  if p_kick then delete from ops_sessions where role = 'staff'; end if;
end $$;

-- ---------- apartments ----------
create or replace function ops_units(p_token uuid)
returns json language plpgsql security definer set search_path = public as $$
begin
  perform ops_sess(p_token);
  return coalesce((select json_agg(json_build_object('id',u.id,'name',u.name,'location',u.location,
     'kind',coalesce(u.kind,'apartment'),'max_guests',u.max_guests,
     'open_issues',(select count(*) from ops_issues i where i.unit_id=u.id and i.status='open'))
     order by u.location, u.sort nulls last, u.name) from ops_apartments u where u.active), '[]'::json);
end $$;

-- ---------- warehouse ----------
create or replace function ops_items(p_token uuid)
returns json language plpgsql security definer set search_path = public as $$
begin
  perform ops_sess(p_token);
  return coalesce((select json_agg(row_to_json(i) order by i.category, i.sort, i.id) from (
    select it.*, (select coalesce(sum(m.qty),0) from ops_moves m where m.item_id=it.id and m.kind='break'
                   and m.at > now() - interval '30 days') as broken_30d
    from ops_items it where it.active) i), '[]'::json);
end $$;

create or replace function ops_item_save(p_token uuid, p jsonb)
returns bigint language plpgsql security definer set search_path = public as $$
declare s ops_sessions := ops_sess(p_token, 'manager'); nid bigint; old int;
begin
  if coalesce(p->>'id','') = '' then
    insert into ops_items(name_he,name_de,name_en,name_ru,category,qty,min_qty)
    values (p->>'name_he',p->>'name_de',p->>'name_en',p->>'name_ru',coalesce(p->>'category','other'),
            coalesce((p->>'qty')::int,0),coalesce((p->>'min_qty')::int,0)) returning id into nid;
    insert into ops_moves(item_id,kind,qty,qty_after,by_name,note) values (nid,'adjust',coalesce((p->>'qty')::int,0),coalesce((p->>'qty')::int,0),s.name,'new item');
    return nid;
  end if;
  nid := (p->>'id')::bigint;
  select qty into old from ops_items where id = nid for update;
  update ops_items set name_he=p->>'name_he', name_de=p->>'name_de', name_en=p->>'name_en', name_ru=p->>'name_ru',
    category=coalesce(p->>'category',category), min_qty=coalesce((p->>'min_qty')::int,min_qty),
    qty=coalesce((p->>'qty')::int,qty) where id = nid;
  if (p->>'qty') is not null and (p->>'qty')::int <> old then
    insert into ops_moves(item_id,kind,qty,qty_after,by_name,note) values (nid,'adjust',(p->>'qty')::int - old,(p->>'qty')::int,s.name,'count corrected');
  end if;
  return nid;
end $$;

-- Soft delete: the item disappears from the list but its history stays in the reports.
create or replace function ops_item_delete(p_token uuid, p_id bigint)
returns void language plpgsql security definer set search_path = public as $$
begin perform ops_sess(p_token, 'manager'); update ops_items set active = false where id = p_id; end $$;

-- take = out of the warehouse, return = back in, break = broken (logged, warehouse unchanged),
-- add = purchase arrived (manager).
create or replace function ops_move(p_token uuid, p_item bigint, p_kind text, p_qty int, p_unit text, p_note text)
returns int language plpgsql security definer set search_path = public as $$
declare s ops_sessions := ops_sess(p_token); q int;
begin
  if p_kind not in ('take','break','return','add') then raise exception 'ops:kind'; end if;
  if p_kind = 'add' and s.role <> 'manager' then raise exception 'ops:forbidden'; end if;
  if coalesce(p_qty,0) <= 0 or p_qty > 10000 then raise exception 'ops:qty'; end if;
  select qty into q from ops_items where id = p_item and active for update;
  if q is null then raise exception 'ops:item'; end if;
  q := q + case p_kind when 'take' then -p_qty when 'break' then 0 else p_qty end;
  if q < 0 then raise exception 'ops:notenough'; end if;
  update ops_items set qty = q where id = p_item;
  insert into ops_moves(item_id,kind,qty,qty_after,unit_id,note,by_name)
    values (p_item,p_kind,p_qty,q,nullif(p_unit,''),nullif(left(p_note,500),''),s.name);
  return q;
end $$;

create or replace function ops_moves_list(p_token uuid, p_from date, p_to date)
returns json language plpgsql security definer set search_path = public as $$
begin
  perform ops_sess(p_token);
  return coalesce((select json_agg(row_to_json(m) order by m.at desc) from (
    select m.*, u.name as unit_name from ops_moves m left join ops_apartments u on u.id = m.unit_id
    where m.at >= p_from and m.at < p_to + 1 order by m.at desc limit 2000) m), '[]'::json);
end $$;

-- ---------- photos (stored compressed, ~100-200 KB each) ----------
create or replace function ops_photo_put(p_token uuid, p_mime text, p_data text)
returns uuid language plpgsql security definer set search_path = public as $$
declare s ops_sessions := ops_sess(p_token); nid uuid;
begin
  if p_mime not in ('image/jpeg','image/png','image/webp') then raise exception 'ops:mime'; end if;
  if length(p_data) > 1500000 then raise exception 'ops:big'; end if;
  insert into ops_photos(mime,data,by_name) values (p_mime,p_data,s.name) returning id into nid;
  return nid;
end $$;

create or replace function ops_photo_get(p_token uuid, p_id uuid)
returns json language plpgsql security definer set search_path = public as $$
begin perform ops_sess(p_token);
  return (select json_build_object('mime',mime,'data',data) from ops_photos where id = p_id); end $$;

-- ---------- issues ----------
create or replace function ops_issue_new(p_token uuid, p_unit text, p_cat text, p_title text, p_details text, p_photo uuid)
returns bigint language plpgsql security definer set search_path = public as $$
declare s ops_sessions := ops_sess(p_token); nid bigint;
begin
  if coalesce(trim(p_title),'') = '' then raise exception 'ops:title'; end if;
  insert into ops_issues(unit_id,category,title,details,photo_id,reported_by)
    values (nullif(p_unit,''),coalesce(p_cat,'other'),left(trim(p_title),200),nullif(left(p_details,2000),''),p_photo,s.name)
    returning id into nid;
  insert into ops_messages(by_name,body,photo_id,issue_id,sys) values (s.name,left(trim(p_title),200),p_photo,nid,'issue_new');
  return nid;
end $$;

create or replace function ops_issue_set(p_token uuid, p_id bigint, p_done boolean, p_note text)
returns void language plpgsql security definer set search_path = public as $$
declare s ops_sessions := ops_sess(p_token); t text;
begin
  if p_done then
    update ops_issues set status='done', resolved_by=s.name, resolved_at=now(), resolution_note=nullif(left(p_note,1000),'')
      where id = p_id and status = 'open' returning title into t;
    if t is not null then insert into ops_messages(by_name,body,issue_id,sys) values (s.name,t,p_id,'issue_done'); end if;
  else
    update ops_issues set status='open', resolved_by=null, resolved_at=null, resolution_note=null
      where id = p_id and status = 'done' returning title into t;
    if t is not null then insert into ops_messages(by_name,body,issue_id,sys) values (s.name,t,p_id,'issue_reopen'); end if;
  end if;
end $$;

create or replace function ops_issues_list(p_token uuid)
returns json language plpgsql security definer set search_path = public as $$
begin
  perform ops_sess(p_token);
  return coalesce((select json_agg(row_to_json(i) order by i.status desc, i.reported_at desc) from (
    select i.*, u.name as unit_name, u.location as unit_location from ops_issues i left join ops_apartments u on u.id = i.unit_id
    where i.status = 'open' or i.reported_at > now() - interval '365 days') i), '[]'::json);
end $$;

-- ---------- group chat ----------
create or replace function ops_msg_send(p_token uuid, p_body text, p_photo uuid)
returns bigint language plpgsql security definer set search_path = public as $$
declare s ops_sessions := ops_sess(p_token); nid bigint;
begin
  if coalesce(trim(p_body),'') = '' and p_photo is null then raise exception 'ops:empty'; end if;
  insert into ops_messages(by_name,body,photo_id) values (s.name,nullif(left(trim(p_body),4000),''),p_photo) returning id into nid;
  return nid;
end $$;

create or replace function ops_msgs(p_token uuid, p_after bigint)
returns json language plpgsql security definer set search_path = public as $$
begin
  perform ops_sess(p_token);
  return coalesce((select json_agg(row_to_json(m) order by m.id) from (
    select * from ops_messages where id > coalesce(p_after,0) order by id desc limit 300) m), '[]'::json);
end $$;

-- ---------- grants: the app may call only these ----------
revoke execute on function ops_sess(uuid,text) from public, anon, authenticated;
do $$ declare f text; begin
  foreach f in array array[
    'ops_staff_login(text,text)','ops_me(uuid)','ops_logout(uuid)',
    'ops_set_staff_pass(uuid,text,boolean)','ops_units(uuid)','ops_items(uuid)','ops_item_save(uuid,jsonb)',
    'ops_item_delete(uuid,bigint)','ops_move(uuid,bigint,text,int,text,text)','ops_moves_list(uuid,date,date)',
    'ops_photo_put(uuid,text,text)','ops_photo_get(uuid,uuid)','ops_issue_new(uuid,text,text,text,text,uuid)',
    'ops_issue_set(uuid,bigint,boolean,text)','ops_issues_list(uuid)','ops_msg_send(uuid,text,uuid)','ops_msgs(uuid,bigint)'] loop
    execute 'revoke execute on function ' || f || ' from public';
    execute 'grant execute on function ' || f || ' to anon, authenticated';
  end loop;
end $$;

-- ---------- starter warehouse list (only if empty) — edit freely in the app ----------
insert into ops_items(name_he,name_de,name_en,name_ru,category,qty,min_qty,sort)
select * from (values
 ('כוסות שתייה','Trinkgläser','Drinking glasses','Стаканы','kitchen',0,50,1),
 ('כוסות יין','Weingläser','Wine glasses','Бокалы для вина','kitchen',0,30,2),
 ('ספלי קפה','Kaffeetassen','Coffee mugs','Кофейные кружки','kitchen',0,40,3),
 ('צלחות גדולות','Teller groß','Dinner plates','Большие тарелки','kitchen',0,40,4),
 ('צלחות קטנות','Teller klein','Side plates','Маленькие тарелки','kitchen',0,40,5),
 ('קערות','Schüsseln','Bowls','Миски','kitchen',0,30,6),
 ('מזלגות','Gabeln','Forks','Вилки','kitchen',0,50,7),
 ('סכינים','Messer','Knives','Ножи','kitchen',0,50,8),
 ('כפות','Löffel','Spoons','Ложки','kitchen',0,50,9),
 ('כפיות','Teelöffel','Teaspoons','Чайные ложки','kitchen',0,50,10),
 ('סירים','Kochtöpfe','Pots','Кастрюли','kitchen',0,10,11),
 ('מחבתות','Pfannen','Frying pans','Сковородки','kitchen',0,10,12),
 ('סדיני מיטה','Bettlaken','Bed sheets','Простыни','linen',0,60,20),
 ('ציפות לשמיכה','Bettbezüge','Duvet covers','Пододеяльники','linen',0,60,21),
 ('ציפיות','Kissenbezüge','Pillowcases','Наволочки','linen',0,100,22),
 ('מגבות גדולות','Badetücher','Bath towels','Банные полотенца','linen',0,80,23),
 ('מגבות ידיים','Handtücher','Hand towels','Полотенца для рук','linen',0,80,24),
 ('שטיחוני אמבטיה','Badematten','Bath mats','Коврики для ванной','linen',0,30,25),
 ('נייר טואלט','Toilettenpapier','Toilet paper','Туалетная бумага','consumables',0,200,30),
 ('סבון ידיים','Handseife','Hand soap','Жидкое мыло','consumables',0,40,31),
 ('שמפו','Shampoo','Shampoo','Шампунь','consumables',0,40,32),
 ('ג׳ל רחצה','Duschgel','Shower gel','Гель для душа','consumables',0,40,33),
 ('שקיות זבל','Müllsäcke','Bin bags','Мешки для мусора','consumables',0,100,34),
 ('קפסולות קפה','Kaffeekapseln','Coffee capsules','Кофейные капсулы','consumables',0,200,35),
 ('נוזל כלים','Spülmittel','Dish soap','Средство для посуды','cleaning',0,20,40),
 ('טבליות למדיח','Geschirrspültabs','Dishwasher tabs','Таблетки для посудомойки','cleaning',0,100,41),
 ('ספוגים','Schwämme','Sponges','Губки','cleaning',0,50,42),
 ('חומר ניקוי כללי','Allzweckreiniger','All-purpose cleaner','Универсальное чистящее средство','cleaning',0,20,43),
 ('נורות','Glühbirnen','Light bulbs','Лампочки','other',0,20,50),
 ('סוללות','Batterien','Batteries','Батарейки','other',0,20,51)
) v where not exists (select 1 from ops_items);

-- Tell the API layer to pick up the new functions right away.
notify pgrst, 'reload schema';

-- Vienna Stay Team — step 2: the team app's own manager username + password.
-- The username/password themselves are set by the manager inside the app
-- (Settings → Manager sign-in); only a bcrypt hash is stored.

create or replace function ops_set_manager_login(p_token uuid, p_user text, p_pass text)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform ops_sess(p_token, 'manager');
  if length(trim(coalesce(p_user,''))) < 3 then raise exception 'ops:name'; end if;
  if length(coalesce(p_pass,'')) < 8 then raise exception 'ops:short8'; end if;
  insert into ops_settings(k, v) values ('mgr_user', lower(trim(p_user)))
    on conflict (k) do update set v = excluded.v;
  insert into ops_settings(k, v) values ('mgr_pass', crypt(p_pass, gen_salt('bf')))
    on conflict (k) do update set v = excluded.v;
end $$;

create or replace function ops_manager_pass_login(p_user text, p_pass text, p_name text)
returns uuid language plpgsql security definer set search_path = public as $$
declare u text; h text; t uuid;
begin
  select v into u from ops_settings where k = 'mgr_user';
  select v into h from ops_settings where k = 'mgr_pass';
  if u is null or h is null then raise exception 'ops:nomgr'; end if;
  if lower(trim(coalesce(p_user,''))) <> u or crypt(coalesce(p_pass,''), h) <> h then
    perform pg_sleep(1.5); raise exception 'ops:badpass';
  end if;
  insert into ops_sessions(name, role) values (coalesce(nullif(left(trim(p_name),40),''),'Manager'), 'manager') returning token into t;
  return t;
end $$;

-- First-run only: creates the manager login while none exists yet; closed after that.
create or replace function ops_status()
returns json language sql security definer set search_path = public as $$
  select json_build_object('has_manager', exists(select 1 from ops_settings where k='mgr_pass')); $$;

create or replace function ops_manager_setup(p_user text, p_pass text, p_name text)
returns uuid language plpgsql security definer set search_path = public as $$
declare t uuid;
begin
  perform pg_advisory_xact_lock(4711);
  if exists(select 1 from ops_settings where k='mgr_pass') then raise exception 'ops:hasmgr'; end if;
  if length(trim(coalesce(p_user,''))) < 3 then raise exception 'ops:name'; end if;
  if length(coalesce(p_pass,'')) < 8 then raise exception 'ops:short8'; end if;
  insert into ops_settings(k, v) values ('mgr_user', lower(trim(p_user)));
  insert into ops_settings(k, v) values ('mgr_pass', crypt(p_pass, gen_salt('bf')));
  insert into ops_sessions(name, role) values (coalesce(nullif(left(trim(p_name),40),''),'Manager'), 'manager') returning token into t;
  return t;
end $$;

create or replace function ops_me(p_token uuid)
returns json language plpgsql security definer set search_path = public as $$
declare s ops_sessions := ops_sess(p_token);
begin return json_build_object('name', s.name, 'role', s.role,
  'has_pass', exists(select 1 from ops_settings where k='staff_pass'),
  'mgr_user', case when s.role='manager' then (select v from ops_settings where k='mgr_user') end); end $$;

revoke execute on function ops_set_manager_login(uuid,text,text) from public;
revoke execute on function ops_manager_pass_login(text,text,text) from public;
grant execute on function ops_set_manager_login(uuid,text,text) to anon, authenticated;
grant execute on function ops_manager_pass_login(text,text,text) to anon, authenticated;

revoke execute on function ops_status() from public;
revoke execute on function ops_manager_setup(text,text,text) from public;
grant execute on function ops_status() to anon, authenticated;
grant execute on function ops_manager_setup(text,text,text) to anon, authenticated;

-- ---------- the 80 apartments + garages, copied once from the apartment list ----------
insert into ops_apartments(id,name,location,kind,max_guests,sort) values

 ('rpd-402-double-kueche','RPD 402 Double Kueche','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,63),
 ('rpd-408-double-kueche','RPD 408 Double Kueche','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,64),
 ('rpd-501-double-superior','RPD 501 Double Superior','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,65),
 ('rpd-503-double-superior','RPD 503 Double Superior','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,66),
 ('rpd-504-double-superior','RPD 504 Double Superior','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,67),
 ('rpd-505-double-superior','RPD 505 Double Superior','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,68),
 ('rpd-506-double-superior','RPD 506 Double Superior','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,69),
 ('4f','4F | Belvedere Cream','Belvederegasse 42, 1040 Wien','apartment',2,48),
 ('c1','C1 | Castellez Special','Castellezgasse 18, 1020 Wien','apartment',2,33),
 ('c2','C2 | Castellez Silver','Castellezgasse 18, 1020 Wien','apartment',2,34),
 ('gar-garage-spot-1','Garage Spot 1 | Garage 1','Castellezgasse 18, 1020 Wien','garage',0,70),
 ('gar-garage-spot-2','Garage Spot 2 | Garage 2','Castellezgasse 18, 1020 Wien','garage',0,71),
 ('gar-garage-spot-3','Garage Spot 3 | Garage 3','Castellezgasse 18, 1020 Wien','garage',0,72),
 ('gar-garage-spot-4','Garage Spot 4 | Garage 4','Castellezgasse 18, 1020 Wien','garage',0,73),
 ('gar-garage-spot-5','Garage Spot 5 | Garage 5','Castellezgasse 18, 1020 Wien','garage',0,74),
 ('gar-garage-spot-6','Garage Spot 6 | Garage 6','Castellezgasse 18, 1020 Wien','garage',0,75),
 ('gar-garage-spot-7','Garage Spot 7 | Garage 7','Castellezgasse 18, 1020 Wien','garage',0,76),
 ('gar-garage-1-linzerstrasse','Garage 1 Linzerstrasse','Linzerstrasse 430, 1140 Wien','garage',0,77),
 ('gar-garage-2-linzerstrasse','Garage 2 Linzerstrasse','Linzerstrasse 430, 1140 Wien','garage',0,78),
 ('gar-garage-3-linzerstrasse','Garage 3 Linzerstrasse','Linzerstrasse 430, 1140 Wien','garage',0,79),
 ('gar-garage-4-linzerstrasse','Garage 4 Linzerstrasse','Linzerstrasse 430, 1140 Wien','garage',0,80),
 ('c3','C3 | Castellez Flair','Castellezgasse 18, 1020 Wien','apartment',2,35),
 ('c11','C11 | Castellez Dream','Castellezgasse 18, 1020 Wien','apartment',2,36),
 ('c12','C12 | Castellez Energy','Castellezgasse 18, 1020 Wien','apartment',2,37),
 ('t59-7','T59/7 | Tabor Diamond','Taborstrasse 59, 1020 Wien','apartment',2,29),
 ('t59-8','T59/8 | Tabor Opal','Taborstrasse 59, 1020 Wien','apartment',2,30),
 ('t59-13','T59/13 | Tabor Supreme','Taborstrasse 59, 1020 Wien','apartment',2,31),
 ('t59-19','T59/19 | Tabor Pearl','Taborstrasse 59, 1020 Wien','apartment',2,32),
 ('c14','C14 | Castellez Chillout','Castellezgasse 18, 1020 Wien','apartment',2,38),
 ('p3','P3 | Pezzl Cosy','Pezzlgasse 57, 1170 Wien','apartment',2,39),
 ('p15','P15 | Pezzl Comfort','Pezzlgasse 57, 1170 Wien','apartment',2,40),
 ('p8','P8 | Pezzl Forest','Pezzlgasse 57, 1170 Wien','apartment',2,41),
 ('p14','P14 | Pezzl Ivory','Pezzlgasse 57, 1170 Wien','apartment',2,42),
 ('p21','P21 | Pezzl White','Pezzlgasse 57, 1170 Wien','apartment',2,43),
 ('p28','P28 | Pezzl Fly','Pezzlgasse 57, 1170 Wien','apartment',2,44),
 ('p29','P29 | Pezzl Rooftop','Pezzlgasse 57, 1170 Wien','apartment',2,45),
 ('p10-11','P10-11 | Pezzl Green','Pezzlgasse 57, 1170 Wien','apartment',2,46),
 ('p18-20','P18-20 | Pezzl Supreme','Pezzlgasse 57, 1170 Wien','apartment',2,47),
 ('5f','5F | Belvedere Comfort','Belvederegasse 42, 1040 Wien','apartment',2,49),
 ('linzerstrasse-top-6a','Linzerstrasse Top 6A','Linzerstrasse 430, 1140 Wien','apartment',2,50),
 ('linzerstrasse-top-6b','Linzerstrasse Top 6B','Linzerstrasse 430, 1140 Wien','apartment',2,51),
 ('linzerstrasse-top-6c','Linzerstrasse Top 6C','Linzerstrasse 430, 1140 Wien','apartment',2,52),
 ('rpd-1-2','RPD 1-2','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,53),
 ('rpd-7-8','RPD 7-8','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,54),
 ('rpd-9','RPD 9','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,56),
 ('rpd-10','RPD 10','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,57),
 ('t5','T5 | Tabor Yellow (4er)','Taborstrasse 41, 1020 Wien','apartment',4,1),
 ('t6','T6 | Tabor Classic (4er)','Taborstrasse 41, 1020 Wien','apartment',4,2),
 ('t7','T7 | Tabor Red (4 er)','Taborstrasse 41, 1020 Wien','apartment',4,3),
 ('t8','T8 | Tabor Cream (4 er)','Taborstrasse 41, 1020 Wien','apartment',4,4),
 ('t9','T9 | Tabor River (4 er)','Taborstrasse 41, 1020 Wien','apartment',4,5),
 ('t10','T10 | Tabor Dream (4 er)','Taborstrasse 41, 1020 Wien','apartment',4,6),
 ('t11','T11 | Tabor Purple (4 er)','Taborstrasse 41, 1020 Wien','apartment',4,7),
 ('t12','T12 | Tabor Forest (4 er)','Taborstrasse 41, 1020 Wien','apartment',4,8),
 ('t15','T15 | Tabor Ivory(4 er)','Taborstrasse 41, 1020 Wien','apartment',4,9),
 ('t16','T16 | Tabor Cashmere (4 er)','Taborstrasse 41, 1020 Wien','apartment',4,10),
 ('t17','T17 | Tabor Maple (4 er)','Taborstrasse 41, 1020 Wien','apartment',4,11),
 ('t23','T23 | Tabor Sun (4 er)','Taborstrasse 41, 1020 Wien','apartment',4,12),
 ('t25','T25 | Tabor Orange Comfort(4 er)','Taborstrasse 41, 1020 Wien','apartment',4,13),
 ('t28','T28 | Tabor Champagner(4 er)','Taborstrasse 41, 1020 Wien','apartment',4,14),
 ('t31','T31 | Tabor Pumpkin(4 er)','Taborstrasse 41, 1020 Wien','apartment',4,15),
 ('t33','T33 | Tabor Cloud (4 er)','Taborstrasse 41, 1020 Wien','apartment',4,16),
 ('t37','T37 | Tabor Legacy (4 er)','Taborstrasse 41, 1020 Wien','apartment',4,17),
 ('t26-27','T26-27 | Tabor Blue Sky (10 er)','Taborstrasse 41, 1020 Wien','apartment',10,18),
 ('t13','T13 | Tabor Ocean Blue(10er)','Taborstrasse 41, 1020 Wien','apartment',10,19),
 ('t21-22','T21-22 | Tabor Premium(10 er)','Taborstrasse 41, 1020 Wien','apartment',10,20),
 ('t19','T19 | Tabor Caramel(6 er)','Taborstrasse 41, 1020 Wien','apartment',6,21),
 ('t29','T29 | Tabor View (6 er)','Taborstrasse 41, 1020 Wien','apartment',6,22),
 ('t30','T30 | Tabor Emotion (6 er)','Taborstrasse 41, 1020 Wien','apartment',6,23),
 ('t32','T32 | Tabor Score (6 er)','Taborstrasse 41, 1020 Wien','apartment',6,24),
 ('t34','T34 | Tabor Rose (6er)','Taborstrasse 41, 1020 Wien','apartment',6,25),
 ('t35','T35 | Tabor Levi (6 er)','Taborstrasse 41, 1020 Wien','apartment',6,26),
 ('t36','T36 | Tabor Penthouse (6 er)','Taborstrasse 41, 1020 Wien','apartment',6,27),
 ('t38','T38 | Tabor Superior (6 er)','Taborstrasse 41, 1020 Wien','apartment',6,28),
 ('rpd-405-two-double','RPD 405 Two Double','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',4,55),
 ('rpd-502-two-single','RPD 502 two Single','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,58),
 ('rpd-406-two-single','RPD 406 two Single','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,59),
 ('rpd-403-double','RPD 403 Double','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,60),
 ('rpd-407-double','RPD 407 Double','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,61),
 ('rpd-401-double-kueche','RPD 401 Double Kueche','Reinprechtsdorferstrasse 14, 1050 Wien','apartment',2,62)
on conflict (id) do nothing;

notify pgrst, 'reload schema';
