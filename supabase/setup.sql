-- Rendements des agents : tables + accès par code personnel (Supabase > SQL Editor)
create table if not exists public.rendements_demandes (
  n text primary key, d text not null, s text, a text, w text, dt date,
  ha numeric not null default 0,
  p text not null default 'c' check (p in ('t','e','c')),
  r text not null default 'c' check (r in ('t','e','c')),
  updated_at timestamptz not null default now()
);
create index if not exists rendements_demandes_w_idx on public.rendements_demandes (w);
create or replace function public.rendements_touch() returns trigger language plpgsql set search_path = public as $$
begin new.updated_at := now(); return new; end $$;
drop trigger if exists rendements_touch on public.rendements_demandes;
create trigger rendements_touch before insert or update on public.rendements_demandes for each row execute function public.rendements_touch();
alter table public.rendements_demandes enable row level security;
drop policy if exists rend_select on public.rendements_demandes;
drop policy if exists rend_insert on public.rendements_demandes;
drop policy if exists rend_update on public.rendements_demandes;
-- aucune policy : la table n'est accessible que par les fonctions ci-dessous

create table if not exists public.rendements_acces (
  id uuid primary key default gen_random_uuid(),
  nom text not null,
  role text not null check (role in ('admin','agent','lecteur')),
  dep text,                       -- agent : département obligatoire (BUYO, SOUBRE, MEAGUI) ; envoie seulement ses demandes
  code_hash text not null unique, -- sha256 du code : le code lui-même n'est jamais stocké
  actif boolean not null default true,
  cree_le timestamptz not null default now(),
  dernier_acces timestamptz
);
alter table public.rendements_acces enable row level security;

create or replace function public.rend_auth(p_code text) returns public.rendements_acces
language plpgsql security definer set search_path = public as $$
declare u public.rendements_acces;
begin
  select * into u from public.rendements_acces
   where code_hash = encode(sha256(convert_to(upper(trim(coalesce(p_code,''))),'utf8')),'hex') and actif;
  if not found then raise exception 'ACCES_REFUSE'; end if;
  update public.rendements_acces set dernier_acces = now() where id = u.id;
  return u;
end $$;
revoke all on function public.rend_auth(text) from public, anon, authenticated;

create or replace function public.rend_whoami(p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u public.rendements_acces;
begin u := public.rend_auth(p_code);
  return jsonb_build_object('nom',u.nom,'role',u.role,'dep',u.dep); end $$;

create or replace function public.rend_pull(p_code text, p_offset int default 0, p_limit int default 1000) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u public.rendements_acces; res jsonb;
begin u := public.rend_auth(p_code);
  select coalesce(jsonb_agg(to_jsonb(t)),'[]'::jsonb) into res from (
    select n,d,s,a,w,dt,ha,p,r from public.rendements_demandes order by n offset greatest(p_offset,0) limit least(greatest(p_limit,1),2000)) t;
  return res; end $$;

create or replace function public.rend_push(p_code text, p_rows jsonb) returns int
language plpgsql security definer set search_path = public as $$
declare u public.rendements_acces; k int;
begin u := public.rend_auth(p_code);
  if u.role = 'lecteur' then raise exception 'LECTURE_SEULE'; end if;
  insert into public.rendements_demandes(n,d,s,a,w,dt,ha,p,r)
  select x.n,x.d,x.s,x.a,x.w,x.dt,coalesce(x.ha,0),coalesce(x.p,'c'),coalesce(x.r,'c')
    from jsonb_to_recordset(p_rows) as x(n text,d text,s text,a text,w text,dt date,ha numeric,p text,r text)
   where x.n is not null and x.d is not null and (u.role = 'admin' or x.d = u.dep)
  on conflict (n) do update set d=excluded.d,s=excluded.s,a=excluded.a,w=excluded.w,dt=excluded.dt,ha=excluded.ha,p=excluded.p,r=excluded.r;
  get diagnostics k = row_count; return k; end $$;

create or replace function public.rend_admin_list(p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u public.rendements_acces;
begin u := public.rend_auth(p_code);
  if u.role <> 'admin' then raise exception 'ADMIN_REQUIS'; end if;
  return (select coalesce(jsonb_agg(jsonb_build_object('id',id,'nom',nom,'role',role,'dep',dep,'actif',actif,'cree_le',cree_le,'dernier_acces',dernier_acces) order by cree_le),'[]'::jsonb) from public.rendements_acces); end $$;

create or replace function public.rend_admin_add(p_code text, p_nom text, p_role text, p_dep text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u public.rendements_acces; c text; i uuid; d text;
begin u := public.rend_auth(p_code);
  if u.role <> 'admin' then raise exception 'ADMIN_REQUIS'; end if;
  d := nullif(upper(trim(coalesce(p_dep,''))),'');
  if p_role not in ('admin','agent','lecteur') or coalesce(trim(p_nom),'') = '' then raise exception 'PARAMETRES_INVALIDES'; end if;
  if p_role = 'agent' and d is null then raise exception 'DEP_REQUIS'; end if;
  c := 'RDT-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,6)) || '-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,6));
  insert into public.rendements_acces(nom,role,dep,code_hash)
  values (trim(p_nom),p_role,case when p_role = 'agent' then d else null end,encode(sha256(convert_to(c,'utf8')),'hex')) returning id into i;
  return jsonb_build_object('id',i,'code',c); end $$;

create or replace function public.rend_admin_reset(p_code text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u public.rendements_acces; c text;
begin u := public.rend_auth(p_code);
  if u.role <> 'admin' then raise exception 'ADMIN_REQUIS'; end if;
  c := 'RDT-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,6)) || '-' || upper(substr(replace(gen_random_uuid()::text,'-',''),1,6));
  update public.rendements_acces set code_hash = encode(sha256(convert_to(c,'utf8')),'hex'), actif = true where id = p_id;
  if not found then raise exception 'INTROUVABLE'; end if;
  return jsonb_build_object('id',p_id,'code',c); end $$;

create or replace function public.rend_admin_set(p_code text, p_id uuid, p_actif boolean) returns void
language plpgsql security definer set search_path = public as $$
declare u public.rendements_acces;
begin u := public.rend_auth(p_code);
  if u.role <> 'admin' then raise exception 'ADMIN_REQUIS'; end if;
  if p_id = u.id and not p_actif then raise exception 'AUTO_DESACTIVATION'; end if;
  update public.rendements_acces set actif = p_actif where id = p_id; end $$;

grant execute on function public.rend_whoami(text), public.rend_pull(text,int,int), public.rend_push(text,jsonb),
  public.rend_admin_list(text), public.rend_admin_add(text,text,text,text), public.rend_admin_reset(text,uuid), public.rend_admin_set(text,uuid,boolean) to anon;

-- Premier administrateur (à exécuter une fois, en remplaçant VOTRE-CODE) :
-- insert into public.rendements_acces(nom,role,code_hash) values ('Administrateur','admin', encode(sha256(convert_to(upper('VOTRE-CODE'),'utf8')),'hex'));
