create table public.ai_allowance (
  user_id uuid not null references auth.users(id) on delete cascade,
  day date not null,
  used integer not null default 0 check (used >= 0),
  primary key (user_id, day)
);

alter table public.ai_allowance enable row level security;
revoke all on public.ai_allowance from anon, authenticated;

create function public.claim_ai_allowance(daily_limit integer)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  claimed integer;
begin
  if auth.uid() is null or daily_limit < 1 or daily_limit > 100 then
    return false;
  end if;
  insert into public.ai_allowance (user_id, day, used)
  values (auth.uid(), (now() at time zone 'utc')::date, 1)
  on conflict (user_id, day) do update
    set used = public.ai_allowance.used + 1
    where public.ai_allowance.used < daily_limit
  returning used into claimed;
  return claimed is not null;
end;
$$;

revoke all on function public.claim_ai_allowance(integer) from public, anon;
grant execute on function public.claim_ai_allowance(integer) to authenticated;
