"""LDAPS certificate checks against a real TLS listener.

On the acceptance stand every TLS failure surfaced as "service bind failed
(check LDAP_BIND_DN / LDAP_BIND_PASSWORD)"; on Python 3.13 (Debian 13) the
default context's VERIFY_X509_STRICT rejects a DC certificate without an
Authority Key Identifier (what Samba generates for itself).
"""
import datetime
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import config
from auth import ldap_auth

INVALID_CREDENTIALS = 49


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_pki(directory, *, authority_key_id=True):
    """A CA plus a certificate for "localhost" signed by it; returns file paths."""
    now = datetime.datetime.now(datetime.timezone.utc)
    valid = {"not_valid_before": now - datetime.timedelta(days=1), "not_valid_after": now + datetime.timedelta(days=30)}
    ca_key = ec.generate_private_key(ec.SECP256R1())
    usage = x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                          encipher_only=False, decipher_only=False)
    ca = (x509.CertificateBuilder(**valid).subject_name(_name("Test Directory CA")).issuer_name(_name("Test Directory CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(usage, critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (x509.CertificateBuilder(**valid).subject_name(_name("localhost")).issuer_name(ca.subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False))
    if authority_key_id:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                                        critical=False)
    leaf = builder.sign(ca_key, hashes.SHA256())
    directory.mkdir(parents=True, exist_ok=True)
    paths = {name: directory / f"{name}.pem" for name in ("ca", "cert", "key")}
    paths["ca"].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths["cert"].write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    paths["key"].write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    return paths


def _message_id(request: bytes) -> bytes:
    """The messageID INTEGER (tag, length, value) of a BER-encoded LDAPMessage.
    ldap3 numbers messages process-wide, so it is not always one byte long."""
    i = 2 + (request[1] & 0x7F if request[1] & 0x80 else 0)
    return request[i:i + 2 + request[i + 1]]


def bind_response(message_id: bytes, result_code: int) -> bytes:
    """LDAPMessage { messageID, BindResponse { resultCode, "", "" } }."""
    body = message_id + bytes([0x61, 0x07, 0x0A, 0x01, result_code, 0x04, 0x00, 0x04, 0x00])
    return bytes([0x30, len(body)]) + body


class FakeDirectory:
    """LDAPS listener that answers every bind with one result code."""

    def __init__(self, cert, key, bind_result=INVALID_CREDENTIALS):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(cert), str(key))
        self.bind_result = bind_result
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._answer, args=(raw,), daemon=True).start()

    def _answer(self, raw):
        try:
            with self.context.wrap_socket(raw, server_side=True) as tls:
                tls.sendall(bind_response(_message_id(tls.recv(4096)), self.bind_result))
                tls.recv(4096)
        except (OSError, ssl.SSLError, IndexError):
            pass
        finally:
            raw.close()

    def close(self):
        self.sock.close()


@pytest.fixture
def python_313_defaults(monkeypatch):
    """What ssl.create_default_context() does since Python 3.13 (Debian 13)."""
    real = ssl.create_default_context

    def strict(*args, **kwargs):
        context = real(*args, **kwargs)
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        return context

    monkeypatch.setattr(ssl, "create_default_context", strict)


@pytest.fixture
def ldaps(tmp_path, monkeypatch):
    started = []

    def start(*, authority_key_id=True, trusted=True):
        pki = make_pki(tmp_path / "directory", authority_key_id=authority_key_id)
        server = FakeDirectory(pki["cert"], pki["key"])
        started.append(server)
        ca = pki["ca"] if trusted else make_pki(tmp_path / "unrelated")["ca"]
        for name, value in {
            "LDAP_ENABLED": True, "LDAP_URL": f"ldaps://localhost:{server.port}", "LDAP_CA_FILE": str(ca),
            "LDAP_START_TLS": False, "LDAP_BIND_DN": "cn=svc,dc=corp", "LDAP_BIND_PASSWORD": "svc-pw",
            "LDAP_USER_BASE_DN": "dc=corp", "LDAP_TIMEOUT": 3,
        }.items():
            monkeypatch.setattr(config, name, value)
        return server

    yield start
    for server in started:
        server.close()


def test_tls_context_follows_ldap_tls_strict(monkeypatch, python_313_defaults):
    monkeypatch.setattr(config, "LDAP_CA_FILE", "")
    monkeypatch.setattr(config, "LDAP_TLS_STRICT", True)
    strict = ldap_auth.tls_context()
    assert strict.verify_flags & ssl.VERIFY_X509_STRICT
    assert strict.verify_mode == ssl.CERT_REQUIRED
    monkeypatch.setattr(config, "LDAP_TLS_STRICT", False)
    relaxed = ldap_auth.tls_context()
    assert not relaxed.verify_flags & ssl.VERIFY_X509_STRICT
    assert relaxed.verify_mode == ssl.CERT_REQUIRED


def test_certificate_rejected_by_strict_checks_is_reported_as_tls(ldaps, monkeypatch, python_313_defaults):
    ldaps(authority_key_id=False)
    monkeypatch.setattr(config, "LDAP_TLS_STRICT", True)
    result = ldap_auth.test_connection()
    assert result["ok"] is False and result["code"] == "tls"
    assert "certificate verify failed" in result["detail"] and "LDAP_TLS_STRICT" in result["detail"]
    assert "LDAP_BIND_PASSWORD" not in result["detail"]


def test_ldap_tls_strict_false_accepts_that_certificate(ldaps, monkeypatch, python_313_defaults):
    ldaps(authority_key_id=False)
    monkeypatch.setattr(config, "LDAP_TLS_STRICT", False)
    result = ldap_auth.test_connection()
    # TLS got through; the (fake) directory refused the password.
    assert result["code"] == "bind" and "LDAP_BIND_PASSWORD" in result["detail"]


def test_certificate_from_an_unknown_ca_is_reported_as_tls(ldaps, monkeypatch):
    ldaps(trusted=False)
    monkeypatch.setattr(config, "LDAP_TLS_STRICT", False)
    result = ldap_auth.test_connection()
    assert result["code"] == "tls" and "certificate verify failed" in result["detail"]


def test_conforming_certificate_passes_strict_checks(ldaps, monkeypatch, python_313_defaults):
    ldaps(authority_key_id=True)
    monkeypatch.setattr(config, "LDAP_TLS_STRICT", True)
    assert ldap_auth.test_connection()["code"] == "bind"
