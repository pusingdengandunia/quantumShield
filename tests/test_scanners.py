import socket
import struct
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from qshield.scanners import ssh, tls
from qshield.scanners.code import scan_code


def kexinit_packet(kex: str, host_keys: str) -> bytes:
    payload = bytes([20]) + b"\0" * 16
    for names in (kex, host_keys):
        payload += struct.pack(">I", len(names)) + names.encode()
    padding = 8
    body = bytes([padding]) + payload + b"\0" * padding
    return struct.pack(">I", len(body)) + body


def fake_ssh_server(kex: str, host_keys: str) -> int:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def serve():
        connection, _ = server.accept()
        connection.sendall(b"SSH-2.0-Fake\r\n" + kexinit_packet(kex, host_keys))
        connection.recv(64)
        connection.close()
        server.close()

    threading.Thread(target=serve, daemon=True).start()
    return server.getsockname()[1]


def test_ssh_classic_server_is_flagged():
    port = fake_ssh_server("curve25519-sha256,kex-strict-s-v00@openssh.com", "ecdsa-sha2-nistp256")
    result = ssh.scan_ssh("127.0.0.1", port)
    assert result["reachable"] and not result["hybrid"]
    assert result["banner"] == "SSH-2.0-Fake"
    kex = next(item for item in result["items"] if item["role"] == "kex")
    assert kex["algorithm"] == "curve25519-sha256"
    assert kex["quantum"] == "vulnerable"


def test_ssh_hybrid_server_is_recognised():
    port = fake_ssh_server("mlkem768x25519-sha256,curve25519-sha256", "ssh-ed25519")
    result = ssh.scan_ssh("127.0.0.1", port)
    assert result["hybrid"]
    assert next(item for item in result["items"] if item["role"] == "kex")["quantum"] == "safe"


def test_ssh_garbage_server_is_not_reachable():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        connection, _ = server.accept()
        connection.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        connection.close()

    threading.Thread(target=serve, daemon=True).start()
    assert ssh.scan_ssh("127.0.0.1", port)["reachable"] is False
    server.close()


def test_kexinit_rejects_other_message_types():
    with pytest.raises(ValueError):
        ssh.parse_kexinit(bytes([21]) + b"\0" * 40)


# Real s_client lines captured from OpenSSL 3.5.
HYBRID_OUTPUT = "Negotiated TLS1.3 group: X25519MLKEM768\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
CLASSIC_OUTPUT = "Peer Temp Key: X25519, 253 bits\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
ECDH_OUTPUT = "Peer Temp Key: ECDH, prime256v1, 256 bits\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n"
FAILED_OUTPUT = "Negotiated TLS1.3 group: <NULL>\nNew, (NONE), Cipher is (NONE)\n"


def test_handshake_output_parsing():
    assert tls._kex_item(HYBRID_OUTPUT, "TLS_AES_256_GCM_SHA384", "TLSv1.3")["quantum"] == "safe"
    assert tls._kex_item(CLASSIC_OUTPUT, "TLS_AES_256_GCM_SHA384", "TLSv1.3")["algorithm"] == "X25519"
    assert tls._kex_item(ECDH_OUTPUT, "ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2")["algorithm"] == "prime256v1"
    assert tls._kex_item("", "AES256-GCM-SHA384", "TLSv1.2")["algorithm"] == "RSA key transport"
    assert tls.succeeded(HYBRID_OUTPUT) and not tls.succeeded(FAILED_OUTPUT)


def test_open_port_without_tls_never_counts_as_protected(monkeypatch):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    monkeypatch.setattr(tls, "handshake", lambda *args, **kwargs: FAILED_OUTPUT)
    result = tls.scan_tls("127.0.0.1", server.getsockname()[1])
    server.close()
    assert result["reachable"] is False


def test_certificate_description():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    info = tls.describe_certificate(cert.public_bytes(serialization.Encoding.PEM).decode())
    assert (info["algorithm"], info["size"], info["subject"]) == ("RSA", 2048, "CN=lab")


def test_code_scanner_finds_usage_with_location(tmp_path):
    (tmp_path / "app.py").write_text("import x\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    (tmp_path / "Client.java").write_text('KeyPairGenerator.getInstance("EC");\n')
    (tmp_path / "nginx.conf").write_text("ssl_protocols TLSv1 TLSv1.2;\nssl_ecdh_curve X25519MLKEM768:X25519;\n")
    result = scan_code(tmp_path)
    locations = {(item["location"], item.get("line")) for item in result["items"]}
    assert ("app.py", 2) in locations
    assert ("Client.java", 1) in locations
    assert ("nginx.conf", 1) in locations
    assert ("nginx.conf", 2) not in locations, "a hybrid curve list must not be flagged"


def test_modern_tls_line_is_not_flagged_as_legacy(tmp_path):
    (tmp_path / "nginx.conf").write_text("ssl_protocols TLSv1.2 TLSv1.3;\n")
    assert scan_code(tmp_path)["items"] == []


def test_code_scanner_never_stores_key_material(tmp_path):
    secret = "TOPSECRETKEYMATERIAL"
    (tmp_path / "id.pem").write_text(f"-----BEGIN RSA PRIVATE KEY-----\n{secret}\n-----END RSA PRIVATE KEY-----\n")
    result = scan_code(tmp_path)
    assert result["items"][0]["algorithm"] == "RSA"
    assert secret not in repr(result)


def test_code_scanner_skips_dependency_folders(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text('crypto.createECDH("x");\n')
    assert scan_code(tmp_path)["items"] == []


def test_missing_repo_is_not_reachable(tmp_path):
    assert scan_code(tmp_path / "absent")["reachable"] is False
