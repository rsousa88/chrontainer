# Migration Guide: v0.4.x → v1.0

## Overview
v1.0 is a breaking-change release that introduces a new architecture, a Vue.js frontend, and API versioning under `/api/v1`.

## Key Changes
- New `/api/v1` endpoints (legacy `/api` deprecated)
- Frontend rebuilt as Vue.js SPA
- Documentation consolidated under `docs/`
- Internal docs moved to `INTERNAL_NOTES.md` (gitignored)

## Migration Steps
1. Back up your database (`/data/chrontainer.db`).
2. Update to the new container image (v1.0.0).
3. Review environment variable changes in the new `config.py`.
4. If using API clients, update URLs to `/api/v1`.
5. Verify hosts/schedules/tags after first boot.

## Deprecated
- Server-side templates (removed)
- Old `/api` endpoints (deprecated with warnings)

## Rollback
If needed, restore the previous image and your database backup.

