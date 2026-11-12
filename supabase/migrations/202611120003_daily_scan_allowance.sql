create table if not exists public.daily_scan_allowance (
  user_id uuid not null references auth.users(id) on delete cascade,
  day date not null,
  used integer not null check (used between 1 and 5),
  primary key (user_id, day)
);

alter table public.daily_scan_allowance enable row level security;
revoke all on public.daily_scan_allowance from public, anon, authenticated;

create or replace function public.claim_scan_allowance()
returns boolean language plpgsql security definer set search_path = '' as $$
declare claimed integer;
begin
  if auth.uid() is null then return false; end if;
  insert into public.daily_scan_allowance (user_id, day, used)
  values (auth.uid(), (now() at time zone 'utc')::date, 1)
  on conflict (user_id, day) do update
    set used = public.daily_scan_allowance.used + 1
    where public.daily_scan_allowance.used < 5
  returning used into claimed;
  return claimed is not null;
end;
$$;
revoke all on function public.claim_scan_allowance() from public, anon;
grant execute on function public.claim_scan_allowance() to authenticated;

