# app/crypto/pki.py
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
import binascii


class BadCertificate(Exception):
    """Raised when certificate validation fails."""
    pass


def load_cert_pem_bytes(pem_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_bytes)


def load_cert_from_file(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    fp = cert.fingerprint(hashes.SHA256())
    return binascii.hexlify(fp).decode()


# ----------------------------------------------------------------------
#   VALIDITY CHECK
# ----------------------------------------------------------------------
def check_cert_validity(cert: x509.Certificate) -> None:
    """
    Ensure certificate is not expired, not-before has passed, and times are UTC.
    """
    now = datetime.now(timezone.utc)

    not_before = cert.not_valid_before
    not_after = cert.not_valid_after

    # Normalize timezone-naive values to UTC
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)

    if now < not_before:
        raise BadCertificate(f"Certificate not yet valid (NotBefore={not_before})")

    if now > not_after:
        raise BadCertificate(f"Certificate expired (NotAfter={not_after})")


# ----------------------------------------------------------------------
#   VERIFY CERT IS SIGNED BY THE CA
# ----------------------------------------------------------------------
def verify_cert_signed_by(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    """
    Verifies the signature on the certificate using CA's public key.
    Raises BadCertificate on failure.
    """
    ca_pub = ca_cert.public_key()

    try:
        ca_pub.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise BadCertificate(f"Signature verification failed: {e}")


# ----------------------------------------------------------------------
#   HOSTNAME VALIDATION (CN / SAN)
# ----------------------------------------------------------------------
def match_hostname_cn_or_san(cert: x509.Certificate, expected_hostname: str) -> bool:
    """
    Try SAN first (recommended). Then fallback to CN.
    """
    # --- SAN DNS Names ---
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
        if expected_hostname in sans:
            return True
    except x509.ExtensionNotFound:
        pass

    # --- Fallback CN ---
    cn_list = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_list:
        cn = cn_list[0].value
        if cn == expected_hostname:
            return True

    return False


# ----------------------------------------------------------------------
#   COMPLETE CERTIFICATE VALIDATION
# ----------------------------------------------------------------------
def verify_certificate_chain(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_hostname: str = None
) -> None:
    """
    High-level certificate validation required by assignment:
      ✔ Validity period
      ✔ Signature chain (cert signed by CA)
      ✔ CN/SAN hostname match
    Raises BadCertificate on any failure.
    """

    # 1. Expiry / validity
    check_cert_validity(cert)

    # 2. Must be signed by CA
    verify_cert_signed_by(cert, ca_cert)

    # 3. Hostname required in assignment (server.local / client.local)
    if expected_hostname:
        if not match_hostname_cn_or_san(cert, expected_hostname):
            raise BadCertificate(
                f"Hostname/CN mismatch: expected '{expected_hostname}'"
            )
