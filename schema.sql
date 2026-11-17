-- 1) Run this whole file once in Supabase > SQL Editor
create extension if not exists pgcrypto with schema extensions;
create table profiles(id uuid primary key references auth.users on delete cascade,email text,name text,role text not null default 'member' check(role in('admin','coordinator','leader','member')),comp int);
create table members(id text primary key,comp int not null,name text not null,role text,gender text,yr text,phone text,trained boolean default false,lead boolean default false);
create table assignments(comp int,r int,c int,member_id text references members(id) on delete cascade,primary key(comp,r,c));
create table kv(k text primary key,v jsonb);
create function is_admin() returns boolean language sql security definer stable as $$select exists(select 1 from profiles where id=auth.uid() and role='admin')$$;
create function can_edit(cid int) returns boolean language sql security definer stable as $$select is_admin() or exists(select 1 from profiles where id=auth.uid() and role in('coordinator','leader') and comp=cid)$$;
create function new_user() returns trigger language plpgsql security definer as $$begin insert into profiles(id,email,name) values(new.id,new.email,split_part(new.email,'@',1));return new;end$$;
create trigger on_signup after insert on auth.users for each row execute function new_user();
alter table profiles enable row level security;alter table members enable row level security;alter table assignments enable row level security;alter table kv enable row level security;
create policy p_sel on profiles for select using(id=auth.uid() or is_admin());
create policy p_upd on profiles for update using(is_admin());
create policy m_sel on members for select to authenticated using(true);
create policy m_all on members for all using(can_edit(comp)) with check(can_edit(comp));
create policy a_sel on assignments for select to authenticated using(true);
create policy a_all on assignments for all using(can_edit(comp)) with check(can_edit(comp));
create policy k_sel on kv for select to authenticated using(true);
create policy k_all on kv for all using(is_admin() or exists(select 1 from profiles where id=auth.uid() and role in('coordinator','leader'))) with check(true);

-- Account management (the website calls these; username "x" becomes login x@react-forum.app)
create function _mk_user(p_user text,p_pass text,p_name text,p_role text,p_comp int) returns void language plpgsql security definer set search_path=public,extensions,auth as $$
declare uid uuid:=gen_random_uuid(); em text:=lower(trim(p_user))||'@react-forum.app';
begin
 insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at,confirmation_token,email_change,email_change_token_new,recovery_token)
 values('00000000-0000-0000-0000-000000000000',uid,'authenticated','authenticated',em,crypt(p_pass,gen_salt('bf')),now(),'{"provider":"email","providers":["email"]}','{}',now(),now(),'','','','');
 insert into auth.identities(id,user_id,provider_id,identity_data,provider,last_sign_in_at,created_at,updated_at)
 values(gen_random_uuid(),uid,uid::text,jsonb_build_object('sub',uid::text,'email',em),'email',now(),now(),now());
 update profiles set name=p_name,role=p_role,comp=p_comp where id=uid;
end$$;
revoke all on function _mk_user(text,text,text,text,int) from public,anon,authenticated;
create function create_account(p_user text,p_pass text,p_name text,p_role text,p_comp int) returns void language plpgsql security definer set search_path=public,extensions,auth as $$
begin if not is_admin() then raise exception 'Admins only'; end if; perform _mk_user(p_user,p_pass,p_name,p_role,p_comp); end$$;
create function set_password(p_user text,p_pass text) returns void language plpgsql security definer set search_path=public,extensions,auth as $$
begin if not is_admin() then raise exception 'Admins only'; end if; update auth.users set encrypted_password=crypt(p_pass,gen_salt('bf')) where email=lower(trim(p_user))||'@react-forum.app'; end$$;
create function delete_account(p_id uuid) returns void language plpgsql security definer set search_path=public,auth as $$
begin if not is_admin() then raise exception 'Admins only'; end if; delete from auth.users where id=p_id and id<>auth.uid(); end$$;
