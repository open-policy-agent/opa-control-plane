# The Migrations README

This document collects notes around migrations, and the choices we've had in the process.

version | notes
---|---
v0.1.0 | first release with migrations, initial setup and some additions
v0.2.0 | minor changes
v0.3.0 | multi-tenancy, named constraints

## The early days (pre-v0.1.0)

Initially, all we had was the `sqlTable` array, and it was applied on startup.
That works fine with in-memory SQLite instances, or with fresh PG/MySQL installs, but not
wouldn't be a workable approach if someone deploys OCP (say, in K8s), and tries to update
it without throwing away all database contents. So we've introduced a migrations framework:
https://github.com/golang-migrate/migrate

We're still using the `sqlTable` array, but it's rendered into an in-memory `fs.FS` for the
database dialect that is needed.

Smaller migrations are put into `fs.FS` instances with files containing just single SQL
statements.

Changes to the migrations that are contained in released versions (v0.1.0 onwards) are to
be handled with care, since they would only run on new installs, not on upgrades.


## Multi-Tenancy

When we decided that using unique human-friendly _names_ for our entities was a problem for
a likely multi-tenant future of OCP, we went all-in and

1. made all relation tables (`bundles_requirements` etc) refer to their relatees via `id` (not
   `name`),
2. referring to a `tenants` table via `tenant_id`,
3. re-created the entity tables (like `bundles`) without uniquness on names,
4. but with uniqueness on `(tenant_id, name)`.

So far, only a "default" tenant exists. It's ID depends on the database system, because we're
using auto-incrementing integers, and MySQL starts with 1 while PG uses 0 (or vice-versa).

The migration for this is pretty huge: based on a second array of `sqlTable` instances, all
old contents are moved into the new tables. This is because we couldn't predict constraint
names across all three supported databases.


## CockroachDB, named constraints

When we added support for CockroachDB, the constraint name problem came up again! The approach
taken for the huge multi-tenant migration, i.e.

1. RENAME existing -> old,
2. CREATE new,
3. COPY old -> new,
4. REMOVE old

would not work for CockroachDB because of its special ways to handle schema changes. The only
robust way to do it was to drop and recreate the constraints, which we -- see earlier -- can't
do uniformly across all our database systems.

As a way out, the introduction of CockroachDB in our migrations took a special entry: It's
"fast forwarding" -- since all tables are recreated in the multi-tenant change (see above),
a CockroachDB migration run will SKIP anything before that, and only create the latest iteration
of our tables as we want them to be. This required creating a table just for CRDB, "tokens", the
only table not migrated for multi-tenancy.

To ensure that we're not painting ourselves into a corner, the migrations have been adapted in
such a way that going forward, all constraints have names we control.
