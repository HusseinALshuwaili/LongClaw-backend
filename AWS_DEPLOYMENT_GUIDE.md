# Deploying SENTINEL_AGENTS backend to AWS

This guide walks through the simplest reliable AWS path for the MVP backend: **App Runner** (the container service) in front of **RDS Postgres** (the database), with **Secrets Manager** for credentials and an **IAM task role** for the Config Audit agent. No EC2 or Kubernetes — App Runner builds and runs your container, gives you HTTPS automatically, and scales to zero-effort.

Everything below assumes you already have an AWS account and the `aws` CLI installed and configured (`aws configure`) with an IAM user that has admin or near-admin permissions for setup. You'll run these commands yourself from your own machine — I can't reach your AWS account from here.

---

## 0. What you're deploying

- `backend/Dockerfile` — builds the FastAPI app behind gunicorn+uvicorn, single worker, non-root user.
- `backend/app/` — the actual application (Triage, Network Recon, Vuln Scanner, Config Audit, the orchestration runner, and the 10-minute background sweep).
- Needs: a Postgres database, an `OPENAI_API_KEY` (optional — Triage degrades to mock mode without one), and for Config Audit to do anything beyond mock mode, an IAM role with read-only access to S3 and EC2 in the account being audited.

---

## 1. Database — RDS Postgres

```bash
aws rds create-db-instance \
  --db-instance-identifier sentinel-db \
  --db-instance-class db.t4g.micro \
  --engine postgres \
  --engine-version 16 \
  --master-username sentinel \
  --master-user-password '<CHOOSE-A-STRONG-PASSWORD>' \
  --allocated-storage 20 \
  --publicly-accessible false \
  --db-name sentinel
```

This takes a few minutes to come up. Once available, grab the endpoint:

```bash
aws rds describe-db-instances --db-instance-identifier sentinel-db \
  --query 'DBInstances[0].Endpoint.Address' --output text
```

Your `DATABASE_URL` will be:
```
postgresql://sentinel:<password>@<endpoint>:5432/sentinel
```

`db.t4g.micro` is enough for an MVP — resize later if needed.

---

## 2. Secrets — Secrets Manager

Don't put the database password or OpenAI key directly in App Runner's plaintext env vars. Store them as secrets:

```bash
aws secretsmanager create-secret --name sentinel/database-url \
  --secret-string "postgresql://sentinel:<password>@<endpoint>:5432/sentinel"

aws secretsmanager create-secret --name sentinel/openai-api-key \
  --secret-string "<your-openai-key-or-leave-blank-string>"
```

---

## 3. IAM role for Config Audit (S3 + EC2 read-only)

This is the role App Runner's container will assume so the Config Audit agent can actually check for public S3 buckets and open security groups, instead of running in mock mode.

```bash
cat > trust-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "tasks.apprunner.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role --role-name sentinel-config-audit-role \
  --assume-role-policy-document file://trust-policy.json

aws iam attach-role-policy --role-name sentinel-config-audit-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

aws iam attach-role-policy --role-name sentinel-config-audit-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess
```

**Important, read this before you assume Config Audit is "live":** the current `config_audit.py` has a stubbed `_get_boto3_session()` that always returns `None` — it deliberately runs in mock mode until real STS role-assumption is wired up (it's commented in the code as "Phase 2b"). Attaching this IAM role to App Runner is necessary but not sufficient. If you want Config Audit doing real S3/security-group checks instead of saying "[MOCK MODE]" in its findings, that function needs an actual `boto3.Session()` built from the attached role's credentials — happy to wire that up next if you want it before launch.

---

## 4. Build and push the container to ECR

```bash
aws ecr create-repository --repository-name sentinel-backend

aws ecr get-login-password --region <your-region> | \
  docker login --username AWS --password-stdin \
  <account-id>.dkr.ecr.<your-region>.amazonaws.com

cd backend
docker build -t sentinel-backend .
docker tag sentinel-backend:latest \
  <account-id>.dkr.ecr.<your-region>.amazonaws.com/sentinel-backend:latest
docker push <account-id>.dkr.ecr.<your-region>.amazonaws.com/sentinel-backend:latest
```

---

## 5. App Runner service

Easiest done in the console (Services → Create service → Container registry → ECR → pick the image you just pushed), but here's the gist of what to set:

- **Port:** `8000`
- **Instance role:** `sentinel-config-audit-role` (from step 3) — this is what lets boto3 pick up credentials automatically with zero static keys.
- **Environment variables (plaintext):**
  - `ALLOWED_ORIGINS` → your real frontend domain, e.g. `https://sentinel-agents.io`
  - `SCAN_INTERVAL_MINUTES` → `10`
  - `ENABLE_SCHEDULER` → `true`
  - `ENV` → `production`
- **Environment variables (secrets, reference the ARNs from step 2):**
  - `DATABASE_URL` → `sentinel/database-url`
  - `OPENAI_API_KEY` → `sentinel/openai-api-key`
- **Health check path:** `/health`

App Runner gives you an HTTPS URL immediately (`https://xxxx.us-east-1.awsapprunner.com`). Point your frontend's API calls at that URL once it's up, and update `ALLOWED_ORIGINS` to match your real domain.

If you'd rather skip the console and do this from the CLI, say so and I'll write the `aws apprunner create-service` JSON config — it's just more verbose to get right by hand.

---

## 6. Verify it's actually live

```bash
curl https://<your-app-runner-url>/health
# {"status":"ok","time":"..."}

curl https://<your-app-runner-url>/docs
# Swagger UI should load
```

Then register a real asset you own, run its DNS TXT verification, and confirm a manual `run-all` actually scans it (this is the same flow already tested locally — see backend/app/agents/runner.py and the verification.py DNS check).

---

## Known gaps to flag honestly

1. **Config Audit is mock-mode until STS role assumption is wired up** (see step 3 note above).
2. **No auth yet** — anything hitting `/assets`, `/ingest`, etc. is unauthenticated. Fine for an internal MVP test, not fine for a public launch. This was flagged separately as the next priority after hosting.
3. **Single worker / single instance by design** — the 10-minute sweep lives inside the API process. If you scale App Runner to >1 instance, set `ENABLE_SCHEDULER=false` on all but one, or the sweep runs once per instance and you'll get duplicate alerts. A proper fix later is moving the sweep to its own scheduled job (e.g. EventBridge + Lambda) instead of in-process APScheduler.
4. **DNS TXT verification needs a real domain you control** — can't be tested from a sandboxed dev environment with no outbound DNS, only from production.
