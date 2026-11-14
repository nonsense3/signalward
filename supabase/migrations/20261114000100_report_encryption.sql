-- Marks report payloads encrypted by the application with AES-256-GCM.
-- Existing rows remain readable as legacy plaintext until the application rewrites them.
alter table public.reports
  add column if not exists payload_encrypted boolean not null default false;

comment on column public.reports.payload_encrypted is
  'When true, report, receipt, brief, and summary JSON/text fields are AES-256-GCM envelopes encrypted by the application.';

-- One-way envelope migration for old reports. The function can only update the caller's
-- own legacy row and only writes the application-provided ciphertext fields.
create or replace function public.encrypt_legacy_report(
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
      brief = p_brief,
      payload_encrypted = true
  where id = p_id
    and user_id = (select auth.uid())
    and payload_encrypted = false;
  return found;
end;
$$;
revoke all on function public.encrypt_legacy_report(text, text, jsonb, jsonb, jsonb) from public, anon;
grant execute on function public.encrypt_legacy_report(text, text, jsonb, jsonb, jsonb) to authenticated;
