-- Rendements des agents : tables partagées (à exécuter une fois dans Supabase > SQL Editor)
create table if not exists public.rendements_demandes (
  n text primary key,
  d text not null,
  s text,
  a text,
  w text,
  dt date,
  ha numeric not null default 0,
  p text not null default 'c' check (p in ('t','e','c')),
  r text not null default 'c' check (r in ('t','e','c')),
  updated_at timestamptz not null default now()
);
create index if not exists rendements_demandes_w_idx on public.rendements_demandes (w);

create or replace function public.rendements_touch() returns trigger
language plpgsql set search_path = public as $$
begin new.updated_at := now(); return new; end $$;
drop trigger if exists rendements_touch on public.rendements_demandes;
create trigger rendements_touch before insert or update on public.rendements_demandes
  for each row execute function public.rendements_touch();

alter table public.rendements_demandes enable row level security;
drop policy if exists rend_select on public.rendements_demandes;
drop policy if exists rend_insert on public.rendements_demandes;
drop policy if exists rend_update on public.rendements_demandes;
create policy rend_select on public.rendements_demandes for select to anon using (true);
create policy rend_insert on public.rendements_demandes for insert to anon with check (true);
create policy rend_update on public.rendements_demandes for update to anon using (true) with check (true);
-- pas de policy delete : personne ne peut supprimer depuis le lien public
