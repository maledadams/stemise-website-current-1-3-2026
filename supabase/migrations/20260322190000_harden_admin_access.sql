create table if not exists public.admin_allowlist (
  email text primary key,
  created_at timestamptz not null default timezone('utc', now())
);

alter table public.admin_allowlist enable row level security;

create or replace function public.current_user_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public, auth
as $$
  with current_email as (
    select lower(
      trim(
        coalesce(
          nullif(auth.jwt() ->> 'email', ''),
          (select email from auth.users where id = auth.uid()),
          ''
        )
      )
    ) as email
  )
  select exists (
    select 1
    from public.admin_allowlist
    where lower(email) = (select email from current_email)
  );
$$;

revoke all on function public.current_user_is_admin() from public;
grant execute on function public.current_user_is_admin() to authenticated;

drop policy if exists "Authenticated manage site content state" on public.site_content_state;
drop policy if exists "Admin allowlist manage site content state" on public.site_content_state;
create policy "Admin allowlist manage site content state"
on public.site_content_state
for all
using (public.current_user_is_admin())
with check (public.current_user_is_admin());

drop policy if exists "Authenticated can read form submissions" on public.form_submissions;
drop policy if exists "Admin allowlist can read form submissions" on public.form_submissions;
create policy "Admin allowlist can read form submissions"
on public.form_submissions
for select
using (public.current_user_is_admin());

drop policy if exists "Authenticated upload site assets" on storage.objects;
drop policy if exists "Admin allowlist upload site assets" on storage.objects;
create policy "Admin allowlist upload site assets"
on storage.objects
for insert
to authenticated
with check (
  bucket_id = 'site-assets'
  and public.current_user_is_admin()
);

drop policy if exists "Authenticated update site assets" on storage.objects;
drop policy if exists "Admin allowlist update site assets" on storage.objects;
create policy "Admin allowlist update site assets"
on storage.objects
for update
to authenticated
using (
  bucket_id = 'site-assets'
  and public.current_user_is_admin()
)
with check (
  bucket_id = 'site-assets'
  and public.current_user_is_admin()
);

drop policy if exists "Authenticated delete site assets" on storage.objects;
drop policy if exists "Admin allowlist delete site assets" on storage.objects;
create policy "Admin allowlist delete site assets"
on storage.objects
for delete
to authenticated
using (
  bucket_id = 'site-assets'
  and public.current_user_is_admin()
);
