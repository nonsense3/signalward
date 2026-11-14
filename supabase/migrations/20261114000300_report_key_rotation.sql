-- Allows the application to re-encrypt an immutable report with a replacement key.
-- Callers can only rewrite their own rows; ordinary report access remains under RLS.
create or replace function public.rotate_encrypted_report(
  p_id text,
  p_summary text,
  p_report jsonb,
  p_receipt jsonb,
  p_brief jsonb
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.reports
  set summary = p_summary,
      report = p_report,
      receipt = p_receipt,
      brief = p_brief
  where id = p_id
    and user_id = (select auth.uid())
    and payload_encrypted = true;
  return found;
end;
$$;
revoke all on function public.rotate_encrypted_report(text, text, jsonb, jsonb, jsonb) from public, anon;
grant execute on function public.rotate_encrypted_report(text, text, jsonb, jsonb, jsonb) to authenticated;
