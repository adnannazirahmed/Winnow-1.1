create table public.analysis_runs (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  source text not null,
  source_name text,
  account_id text,
  status text not null check (status in ('complete', 'partial')),
  finding_count integer not null check (finding_count >= 0),
  identity_count integer not null check (identity_count >= 0),
  path_count integer not null check (path_count >= 0),
  payload jsonb not null
);

create index analysis_runs_user_recent on public.analysis_runs (user_id, id desc);

alter table public.analysis_runs enable row level security;

create policy analysis_runs_owner on public.analysis_runs
  for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

revoke all on public.analysis_runs from anon;
grant select, insert, update, delete on public.analysis_runs to authenticated;
grant usage, select on sequence public.analysis_runs_id_seq to authenticated;
