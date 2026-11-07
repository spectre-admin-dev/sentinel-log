create extension if not exists pgcrypto;

create table if not exists public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);
alter table public.admins enable row level security;

create table if not exists public.members (
  user_id  uuid primary key references auth.users(id) on delete cascade,
  role     text not null check (role in ('viewer','uploader')),
  label    text check (char_length(label) <= 64),
  added_at timestamptz not null default now()
);
alter table public.members enable row level security;

create or replace function public.is_admin()
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;

create or replace function public.can_read()
returns boolean
language sql stable security definer set search_path = public
as $$
  select public.is_admin()
      or exists (select 1 from public.members where user_id = auth.uid() and role = 'viewer');
$$;

create or replace function public.can_upload()
returns boolean
language sql stable security definer set search_path = public
as $$
  select public.can_read()
      or exists (select 1 from public.members where user_id = auth.uid() and role = 'uploader');
$$;

create or replace function public.my_role()
returns text
language sql stable security definer set search_path = public
as $$
  select case
    when public.is_admin() then 'owner'
    else (select role from public.members where user_id = auth.uid())
  end;
$$;

revoke execute on function public.is_admin(), public.can_read(), public.can_upload(), public.my_role() from public, anon;
grant  execute on function public.is_admin(), public.can_read(), public.can_upload(), public.my_role() to authenticated;

create table if not exists public.sightings (
  id          uuid primary key default gen_random_uuid(),
  ts          timestamptz not null default now(),
  kind        text not null check (kind in ('WiFi','BLE')),
  mac         text not null check (mac ~ '^[0-9A-F]{2}(:[0-9A-F]{2}){5}$'),
  oui         text,
  random_mac  boolean not null default false,
  name        text check (char_length(name) <= 64),
  category    text not null default 'Unknown' check (category in (
                'Flock','ALPR','Axon','Police / fleet router','IP camera','Ring','Blink',
                'AirTag','Tile','SmartTag','Smart glasses','Drone','Skimmer',
                'Flipper / hacking tool','Deauth attack','iBeacon','Govee / smart home',
                'Hotspot','Unknown')),
  confidence  text not null default 'unverified' check (confidence in ('unverified','suspected','confirmed')),
  rssi        smallint check (rssi between -120 and 0),
  channel     text check (char_length(channel) <= 24),
  vendor      text check (char_length(vendor) <= 64),
  source      text check (char_length(source) <= 24),
  location    text check (char_length(location) <= 120),
  lat         double precision check (lat between -90 and 90),
  lng         double precision check (lng between -180 and 180),
  notes       text check (char_length(notes) <= 500),
  hidden      boolean not null default false,
  created_at  timestamptz not null default now()
);

alter table public.sightings add column if not exists accuracy_m real check (accuracy_m >= 0);
alter table public.sightings add column if not exists uploaded_by uuid references auth.users(id) on delete set null;

create index if not exists sightings_ts_idx  on public.sightings (ts desc);
create index if not exists sightings_mac_idx on public.sightings (mac);
create index if not exists sightings_oui_idx on public.sightings (oui);
create index if not exists sightings_geo_idx on public.sightings (lat, lng) where lat is not null;

create table if not exists public.rate_hits (
  k  text not null,
  at timestamptz not null default now()
);
create index if not exists rate_hits_k_at_idx on public.rate_hits (k, at);
alter table public.rate_hits enable row level security;

create or replace function public.sightings_before_insert()
returns trigger
language plpgsql security definer set search_path = public
as $$
declare
  m      text;
  v_key  text;
  v_hits int;
begin
  m := upper(regexp_replace(coalesce(new.mac,''), '[^0-9A-Fa-f]', '', 'g'));
  if length(m) <> 12 then
    raise exception 'mac must contain 12 hex digits';
  end if;
  new.mac := substr(m,1,2)||':'||substr(m,3,2)||':'||substr(m,5,2)||':'||
             substr(m,7,2)||':'||substr(m,9,2)||':'||substr(m,11,2);
  new.oui := substr(new.mac,1,8);
  new.random_mac := ((('x'||substr(m,1,2))::bit(8))::int & 2) = 2;

  if new.ts is null or new.ts > now() + interval '1 day' then new.ts := now(); end if;
  new.created_at  := now();
  new.uploaded_by := auth.uid();

  if not public.is_admin() then
    new.hidden := false;
    v_key := coalesce(auth.uid()::text, 'none');
    insert into public.rate_hits (k) values (v_key);
    select count(*) into v_hits from public.rate_hits
      where rate_hits.k = v_key and rate_hits.at > now() - interval '10 minutes';
    if v_hits > 2000 then
      raise exception 'rate limit: too many sightings from this account, try again in a few minutes';
    end if;
    if random() < 0.01 then
      delete from public.rate_hits where at < now() - interval '1 day';
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists sightings_before_insert on public.sightings;
create trigger sightings_before_insert
  before insert on public.sightings
  for each row execute function public.sightings_before_insert();

alter table public.sightings enable row level security;

revoke all on public.sightings from anon;
revoke all on public.sightings from public;
grant select, insert, update, delete on public.sightings to authenticated;
revoke all on public.admins, public.members, public.rate_hits from anon, authenticated;

drop policy if exists "anyone reads visible sightings" on public.sightings;
drop policy if exists "anyone adds sightings"          on public.sightings;
drop policy if exists "admins edit sightings"          on public.sightings;
drop policy if exists "admins delete sightings"        on public.sightings;
drop policy if exists "readers read sightings"   on public.sightings;
drop policy if exists "uploaders add sightings"  on public.sightings;
drop policy if exists "owner edits sightings"    on public.sightings;
drop policy if exists "owner deletes sightings"  on public.sightings;

create policy "readers read sightings" on public.sightings
  for select to authenticated
  using (public.can_read() and (hidden = false or public.is_admin()));

create policy "uploaders add sightings" on public.sightings
  for insert to authenticated
  with check (public.can_upload());

create policy "owner edits sightings" on public.sightings
  for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

create policy "owner deletes sightings" on public.sightings
  for delete to authenticated
  using (public.is_admin());

do $$
begin
  alter publication supabase_realtime add table public.sightings;
exception when duplicate_object then null;
end $$;
