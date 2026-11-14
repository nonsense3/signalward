-- SignalWard schema. Every table is owned by one auth user and protected by row-level security.
-- The API calls PostgREST with the user's own access token; no service-role key is used.

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text check (char_length(display_name) <= 60),
  organization text check (char_length(organization) <= 80),
  title text check (char_length(title) <= 60),
  avatar_hue smallint check (avatar_hue between 0 and 359),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.reports (
  id text primary key check (id ~ '^rpt_[A-Za-z0-9_-]{6,32}$'),
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  kind text not null check (kind in ('repository', 'message', 'url')),
  verdict text not null check (verdict in ('pass', 'block', 'incomplete', 'low_risk', 'suspicious', 'high_risk', 'inconclusive')),
  findings_count integer not null default 0,
  high_count integer not null default 0,
  summary text not null default '',
  report jsonb not null,
  receipt jsonb not null,
  brief jsonb,
  created_at timestamptz not null default now()
);
create index if not exists reports_user_created on public.reports (user_id, created_at desc);

-- Indicators are stored only as per-user HMAC tags; raw phone numbers, wallets and links never reach the database.
create table if not exists public.indicator_sightings (
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  tag text not null check (char_length(tag) <= 80),
  count integer not null default 0,
  last_seen timestamptz not null default now(),
  primary key (user_id, tag)
);

create table if not exists public.blocklist (
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  tag text not null check (char_length(tag) <= 80),
  type text not null check (char_length(type) <= 20),
  display text not null check (char_length(display) <= 160),
  report_id text not null,
  added_at timestamptz not null default now(),
  primary key (user_id, tag)
);

alter table public.profiles enable row level security;
alter table public.reports enable row level security;
alter table public.indicator_sightings enable row level security;
alter table public.blocklist enable row level security;

drop policy if exists "own profile" on public.profiles;
create policy "own profile" on public.profiles for all to authenticated
  using (id = (select auth.uid())) with check (id = (select auth.uid()));

drop policy if exists "own reports read" on public.reports;
create policy "own reports read" on public.reports for select to authenticated using (user_id = (select auth.uid()));
drop policy if exists "own reports insert" on public.reports;
create policy "own reports insert" on public.reports for insert to authenticated with check (user_id = (select auth.uid()));
drop policy if exists "own reports delete" on public.reports;
create policy "own reports delete" on public.reports for delete to authenticated using (user_id = (select auth.uid()));
-- Reports are evidence: no update policy, so a stored report cannot be edited after signing.

drop policy if exists "own sightings" on public.indicator_sightings;
create policy "own sightings" on public.indicator_sightings for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

drop policy if exists "own blocklist" on public.blocklist;
create policy "own blocklist" on public.blocklist for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

revoke all on public.profiles, public.reports, public.indicator_sightings, public.blocklist from anon;

-- Increment sightings for the calling user only. Runs with the caller's privileges, so RLS still applies.
create or replace function public.record_sightings(p_tags text[])
returns void
language sql
security invoker
set search_path = ''
as $$
  insert into public.indicator_sightings (user_id, tag, count, last_seen)
  select auth.uid(), t, 1, now() from unnest(p_tags[1:50]) as t
  on conflict (user_id, tag) do update set count = public.indicator_sightings.count + 1, last_seen = now();
$$;
revoke all on function public.record_sightings(text[]) from public, anon;
grant execute on function public.record_sightings(text[]) to authenticated;

create or replace function public.touch_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin new.updated_at = now(); return new; end;
$$;
drop trigger if exists profiles_touch on public.profiles;
create trigger profiles_touch before update on public.profiles for each row execute function public.touch_updated_at();

-- Create a profile row when a user signs up.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, display_name, avatar_hue)
  values (new.id, left(coalesce(new.raw_user_meta_data ->> 'display_name', split_part(new.email, '@', 1)), 60), floor(random() * 360)::smallint)
  on conflict (id) do nothing;
  return new;
end;
$$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();
