# light_inv

Inventory and bus-fleet management for a transport operator: products, categories, parts, buses, orders, fuel logs, expenditure and activity history, with role-based access and charted reports.

Flask + SQLAlchemy on MySQL, server-rendered Jinja templates, charts drawn with matplotlib/seaborn.

## Features

- **Inventory**: products and categories with stock, pricing and reorder levels
- **Fleet**: buses, parts, parts assigned to buses
- **Orders**: create orders, view details, move them through statuses
- **Fuel**: fuel logs and per-bus consumption, mileage reports
- **Reports**: sales, expenditure and fuel charts (`/reports`, `/api/chart-data`)
- **Bulk upload**: CSV import per entity type, plus downloadable samples
- **Users and roles**: `ADMIN`, `MANAGER`, `SUPERVISOR`, `USER`, enforced by `admin_required` / `manager_required` / `supervisor_required`
- **Audit trail**: every change recorded in `UserActivity` (`/user-activity`)

## Requirements

- Python 3.9+ (the Dockerfile uses `python:3.9-slim`)
- MySQL 8
- `mysqlclient`, which needs MySQL client headers. On Debian/Ubuntu: `default-libmysqlclient-dev build-essential pkg-config`. On Windows the easiest path is to run it through Docker.

## Setup

1. Create the database and load the schema:

   ```sh
   mysql -u root -p -e "CREATE DATABASE inventory_db CHARACTER SET utf8mb4"
   mysql -u root -p inventory_db < schema.txt
   ```

   `schema.txt` and `sql.txt` are the same MySQL Workbench DDL export (no data).

2. Install dependencies:

   ```sh
   python -m venv .venv
   . .venv/bin/activate          # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Point the app at the database and set a session secret:

   ```sh
   export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
   export DATABASE_URL="mysql://root:password@localhost/inventory_db"
   ```

   Or set `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE` instead of `DATABASE_URL`.

4. Run it:

   ```sh
   python app.py            # http://localhost:5000
   ```

5. Create the first accounts. On an empty database, open `/add_users` once. Passwords come from `SEED_ADMIN_PASSWORD` and `SEED_USER_PASSWORD`; if those are not set, random passwords are generated and printed to the console. After the first account exists, `/add_users` requires an admin login.

### Docker

```sh
docker compose up --build
```

This starts MySQL 8 on host port 3307 and the app on 5000. The app reads the `MYSQL_*` variables that compose sets. Tables are created automatically on startup (`db.create_all()`), so a fresh volume works without importing `schema.txt`.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | — | full SQLAlchemy URL; wins over `MYSQL_*` |
| `MYSQL_HOST` / `MYSQL_USER` / `MYSQL_PASSWORD` / `MYSQL_DATABASE` | — / `root` / empty / `inventory_db` | used when `DATABASE_URL` is unset |
| `SECRET_KEY` | random per start | session signing key; set it so sessions survive restarts |
| `SEED_ADMIN_PASSWORD` / `SEED_USER_PASSWORD` | random, printed once | passwords for `/add_users` |
| `FLASK_DEBUG` | `0` | set `1` to enable the Flask debugger (never in production) |
| `PORT` | `5000` | HTTP port |

## Pages

| Route | What |
|---|---|
| `/login`, `/logout` | sign in / out |
| `/dashboard` | stock and sales overview |
| `/products`, `/categories` | inventory lists and add/edit/delete |
| `/orders`, `/orders/<id>/details` | orders and status changes |
| `/buses`, `/manage-buses`, `/assign-parts` | fleet |
| `/fuel-logs`, `/fuel-consumption`, `/fuel-reports` | fuel |
| `/reports`, `/api/chart-data` | charts (JSON for the dashboard) |
| `/users`, `/user-activity` | accounts and audit trail |
| `/bulk-upload`, `/download-sample/<type>` | CSV import and templates |

## Notes on this repository

- `app0.py` is an older 1.4k-line copy of the app that is no longer used; `templates/app.py` is a stray copy of `app.py` inside the templates folder. Both are kept for history only.
- `static/*.png` are chart files written at runtime; they are committed by accident.

## Known limits

- No CSRF protection (Flask-WTF is not used) and no automated tests.
- Chart images are written into `static/`, which is not safe for concurrent users.
- The database password used to be hardcoded in `app.py` and `/add_users` used to be an open GET endpoint with known passwords. Both are fixed; **if you deployed this before, rotate the MySQL password and the seeded accounts**.
