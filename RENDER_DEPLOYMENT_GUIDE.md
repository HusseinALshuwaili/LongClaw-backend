# Deploying SENTINEL_AGENTS backend to Render

This is the simpler, predictable-pricing alternative to AWS: one always-on web service (~$7/mo) plus one small Postgres instance (~$7/mo), both managed by Render. No IAM roles, no ECR, no Secrets Manager — Render's dashboard handles secrets and TLS for you.

You'll need: a GitHub account with this repo pushed to it, and a Render account (render.com — sign up with GitHub, no credit card needed to start, only to go off the free tier).

---

## 0. Push the code to GitHub

If it isn't already in a repo:

```bash
cd backend
git init
git add .
git commit -m "Backend ready for deploy"
git branch -M main
git remote add origin <your-github-repo-url>
git push -u origin main
```

Make sure `.env` (if you have one locally) is in `.gitignore` — never commit real secrets. `.env.example` is fine to commit; it has no real values.

---

## 1. Easiest path: one-click Blueprint deploy

This repo already includes `backend/render.yaml`, which describes both the web service and the database. In the Render dashboard:

1. **New** → **Blueprint**
2. Connect your GitHub repo, point it at this repo, branch `main`
3. Render reads `render.yaml` and shows you a preview: one web service (`sentinel-backend`) and one Postgres database (`sentinel-db`)
4. Click **Apply**

It'll build the Docker image, provision the database, and wire `DATABASE_URL` together automatically (that's what `fromDatabase` in `render.yaml` does).

You'll be prompted to fill in the env vars marked `sync: false` in `render.yaml` — these are the ones Render won't auto-generate, you provide them by hand in the dashboard, encrypted at rest:

- `OPENAI_API_KEY` — your real key, or leave blank for Triage's mock mode
- `ALLOWED_ORIGINS` — your real frontend domain, e.g. `https://sentinel-agents.io`
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` — see step 2 below

---

## 2. AWS credentials for Config Audit (since Render has no IAM-role mechanism)

Config Audit still needs to reach into an AWS account to check S3 buckets and security groups — that part of the product is inherently AWS-specific even though the *backend* itself now lives on Render. Create a dedicated, least-privilege IAM user just for this:

```bash
aws iam create-user --user-name sentinel-config-audit

aws iam attach-user-policy --user-name sentinel-config-audit \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

aws iam attach-user-policy --user-name sentinel-config-audit \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess

aws iam create-access-key --user-name sentinel-config-audit
```

The last command prints an `AccessKeyId` and `SecretAccessKey` — copy both into Render's env var fields for `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`. This is the only place these credentials live; they're encrypted in Render's secret store and never appear in your code or git history.

This user can only *read* S3 bucket ACLs and EC2 security groups — it can't modify anything, matching exactly what `config_audit.py` actually calls.

---

## 3. Manual path (if you'd rather not use the Blueprint)

1. **New** → **PostgreSQL** → name it `sentinel-db`, pick the Starter plan → Create. Copy the **Internal Connection String** once it's up.
2. **New** → **Web Service** → connect your repo → Render should detect the Dockerfile (`backend/Dockerfile`). If it asks for a root directory, set it to `backend`.
3. Plan: **Starter** (the free plan spins down after 15 minutes idle, which breaks the 10-minute background sweep — don't use it for this).
4. **Health Check Path:** `/health`
5. Environment variables (Settings → Environment):
   - `DATABASE_URL` → the internal connection string from step 1
   - `OPENAI_API_KEY` → your key, or blank
   - `OPENAI_MODEL` → `gpt-4o-mini`
   - `ALLOWED_ORIGINS` → your real frontend domain
   - `SCAN_INTERVAL_MINUTES` → `10`
   - `ENABLE_SCHEDULER` → `true`
   - `ENV` → `production`
   - `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION` → from step 2
6. Create Web Service. First deploy takes a few minutes to build the Docker image.

---

## 4. Verify it's live

```bash
curl https://<your-service>.onrender.com/health
# {"status":"ok","time":"..."}

curl https://<your-service>.onrender.com/docs
# Swagger UI should load
```

Then register a real asset you own, run DNS TXT verification against it, and confirm `run-all` actually scans it.

---

## Cost recap

- Web service (Starter, always-on): **~$7/month**
- Postgres (Starter): **~$7/month**
- Total: **~$14/month**, flat — no metering surprises, unlike AWS App Runner's per-vCPU-hour billing.

## Known gaps, same as the AWS path

1. **No auth yet** on the API — fine for internal testing, not for public launch.
2. **Single instance by design** — the sweep runs inside the API process. If you ever scale to multiple instances, set `ENABLE_SCHEDULER=false` on all but one.
3. **DNS TXT verification needs a real domain you control** — can't be tested from a sandbox with no outbound DNS.
4. **Config Audit's AWS credentials are a single static IAM user**, not per-customer role assumption — fine while you're auditing your own AWS account or a handful of trusted pilot customers' accounts; per-customer STS AssumeRole is still Phase 2b if you ever want customers to grant scoped access without sharing keys with you directly.
