create or replace function public.claim_ai_allowance(daily_limit integer)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  today_utc date := (now() at time zone 'utc')::date;
  global_used integer;
  claimed integer;
begin
  if auth.uid() is null or daily_limit < 1 or daily_limit > 100 then
    return false;
  end if;

  -- Serialize claims across users so concurrent requests cannot exceed the cap.
  perform pg_catalog.pg_advisory_xact_lock(524021, today_utc - date '2000-01-01');
  select coalesce(sum(used), 0) into global_used
    from public.ai_allowance where day = today_utc;
  if global_used >= 25 then
    return false;
  end if;

  insert into public.ai_allowance (user_id, day, used)
  values (auth.uid(), today_utc, 1)
  on conflict (user_id, day) do update
    set used = public.ai_allowance.used + 1
    where public.ai_allowance.used < daily_limit
  returning used into claimed;
  return claimed is not null;
end;
$$;
