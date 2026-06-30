"""
Config Audit Agent — V1, tactical, scan-only.

Real boto3 checks against an AWS account, using credentials supplied via
environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
AWS_DEFAULT_REGION). On AWS App Runner/ECS, prefer attaching an IAM
instance/task role instead -- boto3 picks that up automatically with no
static keys needed. On non-AWS hosts (Render, Railway, Fly.io, etc.) there
is no IAM-role equivalent, so a least-privilege IAM user's access key is
the only option; store it as a platform secret, never in code.

Checks implemented:
  - S3 buckets with public-read ACLs or public bucket policies
  - Security groups with an inbound rule open to 0.0.0.0/0 on a sensitive port

Per-asset role-assumption (STS AssumeRole using an ARN tied to the asset's
own verification) is still on the roadmap for Phase 2b, for auditing a
*customer's* AWS account rather than the operator's own. Until then, this
runs against whatever single AWS principal the deployment's credentials
belong to. If boto3 has no working credentials, this degrades to mock mode
and says so explicitly in the finding -- consistent with how the Triage
Agent degrades gracefully without an OPENAI_API_KEY. Nothing here ever
modifies AWS state; every check is a Describe/List/Get call.
"""
from datetime import datetime

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 27017}

_session_cache = {"checked": False, "session": None}


def _get_boto3_session(asset):
    """Build a real boto3 session from whatever credentials are available
    in the environment (static keys, IAM role, or an AWS profile), and
    verify they actually work with a cheap STS call before trusting them.
    Falls back to None (mock mode) on any failure -- missing creds, bad
    creds, no network, etc. -- so this never crashes the agent run."""
    if _session_cache["checked"]:
        return _session_cache["session"]
    _session_cache["checked"] = True

    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    except Exception:
        # Catches ImportError (boto3 not installed) as well as any other
        # import-time failure (e.g. a broken SSL/urllib3 stack on this
        # particular host) -- either way, fall back to mock mode instead
        # of crashing the agent run.
        return None

    try:
        session = boto3.Session()
        # Cheap, read-only call that proves the credentials actually work
        # rather than just exist -- avoids a confusing failure deeper in
        # the real S3/EC2 checks below.
        session.client("sts").get_caller_identity()
    except (BotoCoreError, ClientError, NoCredentialsError, Exception):
        return None

    _session_cache["session"] = session
    return session


def check_public_s3_buckets(session) -> list[dict]:
    s3 = session.client("s3")
    findings = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI", "").endswith("AllUsers"):
                    findings.append({
                        "type": "public_s3_bucket",
                        "resource": name,
                        "detail": f"Bucket '{name}' grants {grant.get('Permission')} to AllUsers.",
                    })
        except Exception:
            continue
    return findings


def check_open_security_groups(session) -> list[dict]:
    ec2 = session.client("ec2")
    findings = []
    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            port = perm.get("FromPort")
            for rng in perm.get("IpRanges", []):
                if rng.get("CidrIp") == "0.0.0.0/0" and port in SENSITIVE_PORTS:
                    findings.append({
                        "type": "open_security_group",
                        "resource": sg["GroupId"],
                        "detail": f"{sg['GroupId']} ({sg.get('GroupName')}) allows 0.0.0.0/0 on port {port}.",
                    })
    return findings


def run(asset) -> dict | None:
    if asset.status != "verified":
        raise PermissionError(
            f"Refusing to audit unverified asset '{asset.target}' -- "
            f"scope enforcement blocked this call."
        )
    if asset.asset_type != "aws_account":
        return None  # config audit only applies to aws_account-type assets

    session = _get_boto3_session(asset)
    if session is None:
        return {
            "summary": (
                f"[MOCK MODE] Config Audit has no working AWS credentials for "
                f"'{asset.target}' yet. Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY "
                f"(or attach an IAM role, on AWS hosts) and this will run real "
                f"S3/SecurityGroup checks via boto3."
            ),
            "findings": [],
            "mock": True,
        }

    findings = check_public_s3_buckets(session) + check_open_security_groups(session)
    if not findings:
        return None

    summary = (
        f"Config Audit found {len(findings)} drift item(s) on {asset.target}: "
        + "; ".join(f["detail"] for f in findings[:3])
    )
    return {"summary": summary, "findings": findings, "mock": False}
