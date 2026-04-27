# dht44.com deployment

Production stack for `dht44.com` and `analytics.dht44.com`.

## Topology

```
Cloudflare (DNS + edge)
        │ HTTPS
        ▼
 VPS  ─┬─ web        nginx 1.27 alpine (TLS, static, /api proxy)
       ├─ umami      ghcr.io/umami-software/umami:postgresql-latest
       ├─ umami-db   postgres:16-alpine    (back-net only)
       └─ certbot    certbot/certbot       (renew every 12h)
        │ proxy_pass /api/* and /stream over Tailscale
        ▼
 Home box (ds1621)  ── dht44 daemon --crawl --web
                       127.0.0.1:8877 reachable via tailscale
```

The C daemon stays on the residential box because peers blacklist
known datacenter ASN ranges; a VPS-hosted node sees a much smaller
slice of the network. nginx in the `web` container proxies `/api/`
and `/stream` over Tailscale.

## DNS (Cloudflare)

Three records, all proxied (orange cloud):

| Type | Name | Target |
|---|---|---|
| A | `dht44.com` | (VPS public IPv4) |
| A | `www` | (VPS public IPv4) |
| A | `analytics` | (VPS public IPv4) |

CAA: `letsencrypt.org` for `dht44.com` (so only Let's Encrypt can
issue certs for the zone).

SSL/TLS mode: **Full (strict)** — Cloudflare ↔ VPS leg uses the
Let's Encrypt cert, browser ↔ Cloudflare leg uses Cloudflare's edge
cert.

## First-time setup on the VPS

Prereqs: VPS with Docker + Docker Compose, ports 80/443 open,
Tailscale installed and able to reach `ds1621.tail7aed4e.ts.net`.

```sh
git clone https://github.com/01BTC10/dht44.git
cd dht44
git checkout crawler

# Generate Umami secrets
cd deploy
cp umami/.env.example umami/.env
sed -i "s/changeme-32-bytes-of-random-hex/$(openssl rand -hex 24)/" umami/.env
sed -i "s/changeme-64-bytes-of-random-hex/$(openssl rand -hex 32)/" umami/.env

# Bring up the database first so certbot's DNS-side dance has somewhere to be
docker compose --env-file umami/.env up -d umami umami-db

# Issue certs (one-shot). The certbot service then renews every 12h.
docker compose run --rm certbot certonly --webroot \
    -w /var/www/certbot \
    -d dht44.com -d www.dht44.com -d analytics.dht44.com \
    --agree-tos -m you@example.com --no-eff-email

# Bring up nginx + the renewal loop
docker compose --env-file umami/.env up -d web certbot
```

In Umami's UI at `https://analytics.dht44.com`:

1. Log in (default `admin` / `umami`, change immediately).
2. Settings → Websites → **Add website** → name `dht44`, domain `dht44.com`.
3. Copy the website-id; this becomes `VITE_UMAMI_WEBSITE_ID` for the
   frontend build.

Set the env vars and rebuild the web container so the Umami beacon
ships in the bundle:

```sh
echo "VITE_UMAMI_WEBSITE_ID=<paste id>" >> umami/.env
echo "VITE_UMAMI_ORIGIN=https://analytics.dht44.com" >> umami/.env
docker compose build web
docker compose --env-file umami/.env up -d web
```

Cloudflare Web Analytics: Cloudflare dashboard → Analytics → Web
Analytics → **Add a site** → `dht44.com`. Enable automatic
injection — no code change needed since it runs at the edge.

## Day-to-day deploys

```sh
ssh vps
cd ~/bep44_dht
git pull
cd deploy
docker compose build web
docker compose --env-file umami/.env up -d web
```

The other containers don't need to roll for a content/UI change.

## Cert renewals

Handled automatically by the `certbot` container (`renew` every 12h).
Manual force:

```sh
docker compose run --rm certbot renew --force-renewal
docker compose exec web nginx -s reload
```

## Troubleshooting

- `502 Bad Gateway` on `/api/*` → `tailscale ping ds1621` from the
  VPS. If that fails the daemon is unreachable, not the web stack.
- `502` on `analytics.dht44.com` → `docker compose logs umami` (check
  for DB connect errors).
- Cert renewal failing → `docker compose logs certbot`. Usually
  means the ACME challenge can't reach `/.well-known/acme-challenge/`,
  i.e. Cloudflare is in "DNS only" mode AND the firewall blocks :80.
- Umami pageviews not arriving → DevTools network tab, look for
  `script.js` and `send` requests to `analytics.dht44.com`. If
  blocked, it's almost always an adblocker (the script path can be
  customized in Umami settings to bypass).
