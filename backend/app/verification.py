"""
Asset verification — the authorization gate every tactical agent depends on.

An asset only becomes scannable once its owner proves control of it. V1
supports DNS TXT record verification: the customer is asked to create a TXT
record at `_longclaw-verify.<target>` containing the token we generated when
they registered the asset. IAM-role verification (signed AWS STS assume-role)
is stubbed for now -- real implementation in Phase 2b once a cloud target
customer is on the roadmap.
"""
import dns.resolver


def verify_dns_txt(target: str, expected_token: str) -> tuple[bool, str]:
    record_name = f"_longclaw-verify.{target}"
    try:
        answers = dns.resolver.resolve(record_name, "TXT", lifetime=5)
    except dns.resolver.NXDOMAIN:
        return False, f"No TXT record found at {record_name}."
    except dns.resolver.NoAnswer:
        return False, f"{record_name} exists but has no TXT records."
    except Exception as e:
        return False, f"DNS lookup failed: {e}"

    for rdata in answers:
        value = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        if value.strip() == expected_token:
            return True, "Token matched."
    return False, "TXT record found but token did not match."


def verify_iam_role(target: str, expected_token: str) -> tuple[bool, str]:
    # Placeholder for Phase 2b: verify by attempting sts:AssumeRole on a
    # customer-provided role ARN and checking a tagged external-id matches
    # expected_token. Not implemented yet.
    return False, "IAM role verification is not yet implemented."
