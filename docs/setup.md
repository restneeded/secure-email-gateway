# Setting up secure-email-gateway from scratch

This walks through a full free-tier deployment on a small VPS (or an old PC on your LAN behind a UniFi/similar router). Adjust hostnames for your domain.

## What you'll have when you're done

- `portal.yourdomain.com` — the web portal recipients sign into to read secure messages
- `smtp.yourdomain.com:587` — SMTP intake where your mail provider forwards outbound
- Everything encrypted at rest with AES-256-GCM, sessions on a `__Host-` cookie, 2-step login on every sign-in

## 1. Domain + DNS

Pick two hostnames on a domain you own. Common shape:

- `portal.yourdomain.com` A/CNAME → wherever the portal will be reachable (Cloudflare Tunnel target, or your public IP)
- `smtp.yourdomain.com` A → the public IP of the box running the gateway. If you're behind a router, this is your WAN IP with port 587 forwarded.

If you're on Cloudflare DNS: keep the SMTP record **grey-cloud** (proxy off). Cloudflare's orange-cloud proxy is HTTP only, it won't carry SMTP.

## 2. The box

Any Linux with Docker. 1 vCPU / 1 GB RAM is fine for a small org. If HIPAA or similar applies to you, own the box or make sure your VPS provider will sign a BAA.

```bash
# Rocky/RHEL/Fedora example
sudo dnf install -y docker docker-compose-plugin git
sudo systemctl enable --now docker
```

## 3. TLS cert for smtp.yourdomain.com

You need a real cert on the SMTP endpoint because Zoho, Google, Microsoft and friends will insist on STARTTLS.

If you can open port 80 briefly:

```bash
sudo certbot certonly --standalone -d smtp.yourdomain.com
```

If you can't (port 80 blocked), use the DNS challenge. Cloudflare example:

```bash
sudo dnf install -y python3-certbot-dns-cloudflare
echo "dns_cloudflare_api_token = YOUR_CF_TOKEN" | sudo tee /etc/letsencrypt/cloudflare.ini
sudo chmod 600 /etc/letsencrypt/cloudflare.ini
sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
    -d smtp.yourdomain.com
```

The compose file mounts `/etc/letsencrypt` read-only into the container. Make sure the container user can read the archive:

```bash
sudo chmod o+rx /etc/letsencrypt/archive /etc/letsencrypt/live
sudo chmod o+r  /etc/letsencrypt/archive/smtp.yourdomain.com/*.pem
```

Drop this into `/etc/letsencrypt/renewal-hooks/deploy/perms.sh` so renewals keep the perms:

```sh
#!/bin/sh
chmod o+rx /etc/letsencrypt/archive /etc/letsencrypt/live
chmod o+r  /etc/letsencrypt/archive/*/*.pem
```

## 4. Portal HTTPS: Cloudflare Tunnel (recommended, no ports opened)

```bash
# install cloudflared, login, create a named tunnel
cloudflared tunnel login
cloudflared tunnel create seg
```

`~/.cloudflared/config.yml`:

```yaml
tunnel: seg
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json

ingress:
  - hostname: portal.yourdomain.com
    service: http://127.0.0.1:3010
  - service: http_status:404
```

```bash
cloudflared tunnel route dns seg portal.yourdomain.com
sudo cloudflared service install
```

Now `portal.yourdomain.com` reaches your box's port 3010 without opening anything on your router.

## 5. Outbound relay

You need something to actually deliver the notification emails and (for pass-through mail) the original outbound. Any of these work:

- ZeptoMail: sign up, verify your domain, publish the SPF + DKIM records they give you. Free tier is generous. Their SMTP is `smtp.zeptomail.com:587`, username `emailapikey`, password is the token they give you.
- Postmark, SES, Mailgun, or your own Postfix work equally well.

You'll enter the credentials in the admin panel (`/admin/mail-settings`), not in the `.env`.

## 6. Env

```bash
git clone https://github.com/restneeded/secure-email-gateway.git
cd secure-email-gateway
cp .env.example .env
```

Edit `.env`:

- `SESSION_SECRET` — 32+ random bytes, `openssl rand -hex 32`
- `MESSAGE_KEY_HEX` — 32 random bytes, `openssl rand -hex 32`. If you lose this, every stored message is unreadable. Back it up somewhere real.
- `PORTAL_ORIGIN` — `https://portal.yourdomain.com`
- `INITIAL_ADMIN_EMAIL` — bootstraps the first admin account on first run
- `SMTP_TLS_CERT` / `SMTP_TLS_KEY` — paths inside the container to your Let's Encrypt cert files (mounted read-only)

## 7. Bring it up

```bash
docker compose up -d
docker compose logs -f app
```

You should see the portal listening on `:3010` and the gateway listening on `:2525` (mapped to `:587` on the host).

## 8. First admin sign-in

Visit `https://portal.yourdomain.com/admin/login`. Sign in with the email you set as `INITIAL_ADMIN_EMAIL`; the bootstrap password is written to `/app/prisma/.admin-bootstrap.log` inside the container (`docker exec seg-app cat /app/prisma/.admin-bootstrap.log`). Change it immediately.

Then go to `/admin/mail-settings` and enter your outbound relay creds. Save. Hit "Test send" to make sure it works.

## 9. Wire your mail provider to route through the gateway

Google Workspace: Admin → Apps → Google Workspace → Gmail → Routing → Outbound gateway → `smtp.yourdomain.com:587`, no auth, STARTTLS.

Zoho Mail: Admin console → Mail settings → Outbound gateway → same shape.

Microsoft 365: Exchange Admin Center → Mail flow → Connectors → new outbound connector pointing at `smtp.yourdomain.com`.

Most providers require you to allowlist their outbound IPs on your firewall for port 587. Look up the ranges your provider uses (or watch the accept log on your gateway to discover them) and lock 587 down to those.

## 10. Firewall lockdown

If your gateway is publicly reachable on 587, restrict it to just your mail provider's outbound IPs. On UniFi that's a port forward with an "allowed source IPs" list. On plain Linux it's:

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp   # or your management port
for cidr in <provider CIDRs>; do
  sudo ufw allow from "$cidr" to any port 587 proto tcp comment "outbound relay"
done
sudo ufw enable
```

## 11. Send a test

From any account routed through your gateway, send a message with `[secure]` in the subject. The recipient should get a "you have a secure message" notification with a link to `portal.yourdomain.com`. They sign up, get a 6-digit code by email, and can read the message and any attachments.

Send another one without `[secure]` in the subject to a different address. That one should just be delivered normally by your relay.

## Common issues

**No STARTTLS advertised on 587.** Container can't read the cert files. `sudo chmod o+rx /etc/letsencrypt/archive /etc/letsencrypt/live && sudo chmod o+r /etc/letsencrypt/archive/*/*.pem`.

**Verification email from your mail provider says "destination not accepting".** Cert or STARTTLS is broken, or the provider's IPs aren't in your allowlist yet. Watch `docker logs seg-app` while you retry.

**Messages send but pass-through delivery doesn't work.** Check `docker logs seg-app` for `[gateway] RELAY` lines. Common cause is the outbound-relay creds aren't set correctly in `/admin/mail-settings`.
