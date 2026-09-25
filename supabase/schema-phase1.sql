-- KetemuTerus NFC Review Card - Phase 1
-- Run this script in Supabase SQL Editor.

create extension if not exists pgcrypto;

create table if not exists public.cards (
  id uuid primary key default gen_random_uuid(),
  card_code text not null unique,
  status text not null default 'AVAILABLE'
    check (status in ('AVAILABLE','ACTIVE','SUSPENDED')),
  created_at timestamptz not null default now(),
  activated_at timestamptz,
  updated_at timestamptz not null default now()
);

create table if not exists public.businesses (
  id uuid primary key default gen_random_uuid(),
  business_name text not null,
  place_id text not null,
  review_url text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.card_assignments (
  id uuid primary key default gen_random_uuid(),
  card_id uuid not null references public.cards(id) on delete cascade,
  business_id uuid not null references public.businesses(id) on delete cascade,
  pin_hash text,
  status text not null default 'ACTIVE'
    check (status in ('ACTIVE','REVOKED')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists one_active_assignment_per_card
  on public.card_assignments(card_id)
  where status = 'ACTIVE';

create index if not exists cards_card_code_idx on public.cards(card_code);
create index if not exists card_assignments_card_id_idx on public.card_assignments(card_id);

create or replace function public.resolve_card(p_card_code text)
returns table (
  card_code text,
  status text,
  business_name text,
  review_url text
)
language sql
security definer
set search_path = public
as $$
  select c.card_code, c.status, b.business_name, b.review_url
  from public.cards c
  left join public.card_assignments ca
    on ca.card_id = c.id and ca.status = 'ACTIVE'
  left join public.businesses b on b.id = ca.business_id
  where upper(c.card_code) = upper(trim(p_card_code))
  limit 1;
$$;

create or replace function public.activate_card(
  p_card_code text,
  p_business_name text,
  p_place_id text,
  p_pin text
)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  v_card public.cards%rowtype;
  v_business_id uuid;
  v_review_url text;
begin
  if trim(p_card_code) = '' then raise exception 'Kode kartu wajib diisi'; end if;
  if trim(p_business_name) = '' then raise exception 'Nama bisnis wajib diisi'; end if;
  if trim(p_place_id) = '' then raise exception 'Google Place ID wajib diisi'; end if;
  if p_pin !~ '^[0-9]{4}$' then raise exception 'PIN harus 4 digit'; end if;

  select * into v_card
  from public.cards
  where upper(card_code) = upper(trim(p_card_code))
  for update;

  if not found then raise exception 'Kode kartu tidak ditemukan'; end if;
  if v_card.status <> 'AVAILABLE' then raise exception 'Kartu sudah aktif atau tidak tersedia'; end if;

  v_review_url := 'https://search.google.com/local/writereview?placeid=' || trim(p_place_id);

  insert into public.businesses (business_name, place_id, review_url)
  values (trim(p_business_name), trim(p_place_id), v_review_url)
  returning id into v_business_id;

  insert into public.card_assignments (card_id, business_id, pin_hash)
  values (v_card.id, v_business_id, crypt(p_pin, gen_salt('bf')));

  update public.cards
  set status = 'ACTIVE', activated_at = now(), updated_at = now()
  where id = v_card.id;

  return json_build_object(
    'card_code', v_card.card_code,
    'status', 'ACTIVE',
    'business_name', trim(p_business_name),
    'review_url', v_review_url
  );
end;
$$;

create or replace function public.generate_cards(p_quantity integer, p_prefix text default 'KT')
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  i integer;
begin
  if p_quantity is null or p_quantity < 1 or p_quantity > 10000 then
    raise exception 'Jumlah kartu harus 1 sampai 10000';
  end if;

  for i in 1..p_quantity loop
    insert into public.cards(card_code)
    select upper(trim(p_prefix)) || lpad(
      (coalesce(max(
        case
          when card_code ~ ('^' || upper(trim(p_prefix)) || '[0-9]+$')
          then substring(card_code from '[0-9]+$')::integer
          else 0
        end
      ), 0) + 1)::text,
      6, '0'
    )
    from public.cards
    where card_code like upper(trim(p_prefix)) || '%';
  end loop;
  return p_quantity;
end;
$$;

alter table public.cards enable row level security;
alter table public.businesses enable row level security;
alter table public.card_assignments enable row level security;

revoke all on public.cards from anon, authenticated;
revoke all on public.businesses from anon, authenticated;
revoke all on public.card_assignments from anon, authenticated;

grant execute on function public.resolve_card(text) to anon, authenticated;
grant execute on function public.activate_card(text,text,text,text) to anon, authenticated;
grant execute on function public.generate_cards(integer,text) to authenticated;
