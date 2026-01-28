# API Reference (v1)

## Base URL
`/api/v1`

## Notes
- v1 introduces breaking changes.
- Legacy `/api/*` endpoints are deprecated and will emit warnings.

## Endpoints (Planned)

### Containers
- `GET /containers`
- `POST /containers/{id}/restart`
- `POST /containers/{id}/start`
- `POST /containers/{id}/stop`
- `POST /containers/{id}/pause`
- `POST /containers/{id}/unpause`
- `POST /containers/{id}/update`
- `POST /containers/{id}/rename`
- `POST /containers/{id}/clone`
- `POST /containers/{id}/delete`
- `GET /containers/{id}/inspect`
- `GET /containers/{id}/logs`
- `GET /containers/{id}/stats`

### Images
- `GET /images`
- `POST /images/pull`
- `POST /images/prune`
- `DELETE /images/{id}`

### Schedules
- `POST /schedules`
- `DELETE /schedules/{id}`
- `POST /schedules/{id}/toggle`

### Hosts
- `GET /hosts`
- `POST /hosts`
- `PUT /hosts/{id}`
- `DELETE /hosts/{id}`
- `POST /hosts/{id}/test`

### Settings
- `GET /settings`
- `POST /settings/discord`
- `POST /settings/discord/test`
- `POST /settings/ntfy`

