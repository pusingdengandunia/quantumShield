from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from qshield.risk import DEFAULT_SETTINGS, assess, classify
from qshield.scanners import pki

NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


def name(text):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def make_cert(subject, issuer=None, signer=None, key=None, ca=False, sans=(), days=365, past=False):
    key = key or ec.generate_private_key(ec.SECP256R1())
    start = NOW - timedelta(days=400) if past else NOW - timedelta(days=1)
    builder = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer or subject))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(start).not_valid_after(start + timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    cert = builder.sign(signer or key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def output_for(*pems, verification="Verification: OK", code="0 (ok)"):
    return "\n".join([*pems, "Peer signature type: ecdsa_secp256r1_sha256", verification, f"Verify return code: {code}",
                      "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"])


def codes(report):
    return {driver["code"] for driver in report["drivers"]}


def test_full_chain_is_read_with_roles_and_weakest_link():
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    middle_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = make_cert("Root", key=root_key, ca=True)
    middle = make_cert("WR2", issuer="Root", signer=root_key, key=middle_key, ca=True)
    leaf = make_cert("mail.google.com", issuer="WR2", signer=middle_key, sans=["mail.google.com"])
    report = pki.analyze(output_for(leaf, middle, root), "mail.google.com", now=NOW)
    chain = report["pki"]["chain"]
    assert [entry["role"] for entry in chain] == ["leaf", "intermediate", "root"]
    assert report["pki"]["auth_status"] == "classic"
    assert report["pki"]["weakest_link"] == "RSA-2048 (intermediate)"
    assert report["pki"]["negotiated_signature"] == "ecdsa_secp256r1_sha256"
    assert report["pki"]["trust"] == {"verified": True, "code": "0 (ok)", "hostname_match": True}
    assert codes(report) == {"auth_classic"}


def test_hostname_rules():
    wildcard = make_cert("x", sans=["*.google.com"])
    assert pki.hostname_matches(wildcard, "mail.google.com")
    assert not pki.hostname_matches(wildcard, "a.b.google.com")
    assert not pki.hostname_matches(wildcard, "google.com")
    assert not pki.hostname_matches(make_cert("mail.google.com"), "mail.google.com"), "CN alone is not enough"


def test_problems_become_drivers_and_findings():
    weak = make_cert("a", key=rsa.generate_private_key(public_exponent=65537, key_size=1024), sans=["a"])
    report = pki.analyze(output_for(weak), "a", now=NOW)
    assert "cert_weak" in codes(report)

    expired = make_cert("a", sans=["a"], days=10, past=True)
    assert "cert_expired" in codes(pki.analyze(output_for(expired), "a", now=NOW))

    soon = make_cert("a", sans=["a"], days=11)
    report = pki.analyze(output_for(soon), "a", now=NOW)
    assert "cert_expired" not in codes(report)
    assert any("kedaluwarsa dalam" in finding["text"] for finding in report["findings"])

    other = make_cert("a", sans=["other"])
    mismatch = pki.analyze(output_for(other), "a", now=NOW)
    assert "hostname_mismatch" in codes(mismatch)
    # The dashboard's phishing warning names the hosts the certificate really covers.
    assert mismatch["pki"]["chain"][0]["names"] == ["other"]
    assert mismatch["pki"]["trust"]["hostname_match"] is False

    untrusted = pki.analyze(output_for(make_cert("a", sans=["a"]), verification="Verification error: self-signed certificate",
                                       code="18 (self-signed certificate)"), "a", now=NOW)
    assert "cert_untrusted" in codes(untrusted)
    assert untrusted["pki"]["trust"]["verified"] is False


def test_trust_is_unknown_without_a_verification_line():
    pem = make_cert("a", sans=["a"])
    report = pki.analyze(pem, "a", now=NOW)
    assert report["pki"]["trust"]["verified"] is None
    assert "cert_untrusted" not in codes(report)


def test_missing_certificate_is_not_trusted():
    report = pki.analyze("New, TLSv1.3, Cipher is X", "a", now=NOW)
    assert report["pki"] is None
    assert "cert_untrusted" in codes(report)


def test_pqc_oid_table_covers_nist_and_falcon():
    assert pki.PQC_OIDS["2.16.840.1.101.3.4.3.18"] == ("ML-DSA-65", 3)
    assert pki.PQC_OIDS["2.16.840.1.101.3.4.3.31"][0] == "SLH-DSA-SHAKE-256f"
    assert pki.PQC_OIDS["1.3.9999.3.11"][0] == "Falcon-512"


def result(items, drivers, sensitivity="rahasia", exposure="internet", migration="gateway"):
    assessment = assess(items, sensitivity, exposure, migration, DEFAULT_SETTINGS, drivers=drivers)
    return {"reachable": True, "items": items, "assessment": assessment}


HYBRID = {"role": "kex", "quantum": "safe"}
CLASSIC = {"role": "kex", "quantum": "vulnerable"}


def test_regression_mail_google_com_is_no_longer_protected():
    """Hybrid key exchange, TLS 1.0/1.1 active, classic certificate: used to score 0.0, Terlindungi."""
    row = result([HYBRID], [{"code": "tls_legacy"}, {"code": "auth_classic"}])
    assert row["assessment"]["risk"] == 65.8
    assert classify(row) == "vulnerable"
    assert row["assessment"]["mosca_vulnerable"] is False, "hybrid key exchange still blocks harvesting"
    assert [d["code"] for d in row["assessment"]["drivers"]] == ["tls_legacy", "auth_classic"]

    public = result([HYBRID], [{"code": "tls_legacy"}, {"code": "auth_classic"}], sensitivity="publik")
    assert public["assessment"]["risk"] == 46.9


def test_status_mapping():
    assert classify(result([HYBRID], [])) == "protected"
    assert classify(result([HYBRID], [{"code": "auth_classic"}])) == "partial"
    assert classify(result([HYBRID], [{"code": "direct_open"}])) == "partial"
    assert classify(result([HYBRID], [{"code": "cert_untrusted"}])) == "vulnerable"
    assert classify(result([CLASSIC], [])) == "high"
    assert classify(result([CLASSIC], [], sensitivity="publik", exposure="lan")) == "vulnerable"
    assert classify({"reachable": False, "items": [], "assessment": {"risk": 0, "A": 0}}) == "unknown"


def test_low_severity_without_hybrid_is_never_partial():
    """AES-128 alone must not read as protected when no post-quantum key exchange was seen."""
    row = result([{"role": "kex", "quantum": "vulnerable"}, {"role": "cipher", "quantum": "weakened"}], [])
    assert classify(row) in {"high", "vulnerable"}
