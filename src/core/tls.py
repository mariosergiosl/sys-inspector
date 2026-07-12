# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/tls.py
# DESCRIPTION: TLS helper for the Sys-Inspector dashboard.
#              Generates a self-signed certificate/key pair on demand so the
#              Web UI can serve HTTPS without any manual PKI setup.
#
# NOTES: This is a self-signed certificate for transport encryption on trusted
#        networks. Browsers will warn about the unknown issuer; that is expected
#        for a self-signed cert. For production PKI, provide your own cert/key
#        in the configured paths and they will be used instead of generating one.
#
# DEPENDENCIES: cryptography (already required by the project).
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def ensure_self_signed_cert(cert_path, key_path, common_name="sys-inspector", days=825):
    """Ensure a TLS certificate/key pair exists at the given paths.

    If both files already exist, nothing is done (an operator-provided cert is
    honored). If either is missing, a fresh self-signed pair is generated.

    Args:
        cert_path (str): Destination path for the PEM certificate.
        key_path (str): Destination path for the PEM private key.
        common_name (str): CN/SAN hostname for the certificate.
        days (int): Validity period in days.

    Returns:
        bool: True if a new pair was generated, False if existing files were kept.
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return False

    # Ensure the destination directory exists with restrictive permissions.
    for path in (cert_path, key_path):
        parent = os.path.dirname(path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, mode=0o750, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sys-Inspector"),
    ])

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Write the private key first (restricted), then the certificate.
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_path, 0o644)

    return True
