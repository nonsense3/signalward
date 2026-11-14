-- A scan can emit at most 50 indicators under the active key and 3 retained keys.
create or replace function public.record_sightings(p_tags text[])
returns void
language sql
security invoker
set search_path = ''
as $$
  insert into public.indicator_sightings (user_id, tag, count, last_seen)
  select auth.uid(), t, 1, now() from unnest(p_tags[1:200]) as t
  on conflict (user_id, tag) do update set count = public.indicator_sightings.count + 1, last_seen = now();
$$;
revoke all on function public.record_sightings(text[]) from public, anon;
grant execute on function public.record_sightings(text[]) to authenticated;
