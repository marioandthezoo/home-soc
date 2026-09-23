"""Self-signed certificates for Lens (SPEC addendum B3).

Browsers only hand out the camera (``getUserMedia``) in a secure context. ``localhost``
is exempt; ``https://192.168.x.x`` is not. So Lens needs TLS, and a home network has no
certificate authority — hence a certificate this module generates itself, covering every
address the phone might use, which the owner accepts once on the phone.

The ``cryptography`` package is the only thing that can build such a certificate without
a toolchain, and Home SOC's dependency list is deliberately three packages long, so it is
an **optional** extra (``pip install homesoc[lens]``) imported lazily inside the one
function that needs it. Everything else here — the paths, the fingerprint the owner
compares on the phone — works with the standard library alone, so ``lens cert`` can still
explain the situation on an install without it.

Threat notes: the private key is written with owner-only permissions where the platform
supports them, never logged, and never leaves the machine. The fingerprint is the only
thing that proves the phone reached *this* server rather than something on the same
Wi-Fi impersonating it, so it is printed next to the pairing QR.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import ipaddress
import logging
import os
import re
import stat
from pathlib import Path
from typing import Any, Iterable

from homesoc import paths

logger = logging.getLogger(__name__)

CERT_NAME = "cert.pem"
KEY_NAME = "key.pem"
#: Default lifetime. 825 days is the longest a public CA may issue for and the longest
#: Apple's platforms accept, which makes it a safe ceiling for a private certificate too.
DEFAULT_DAYS = 825
#: Regenerate rather than reuse when the certificate expires within this many days.
RENEW_WITHIN_DAYS = 30
#: Always present in the SAN list: the browser exemption that lets the dashboard work
#: on this machine even when the LAN address changes.
ALWAYS_HOSTS: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")

_INSTALL_HINT = (
    "Lens needs the optional 'cryptography' package to create its HTTPS certificate.\n"
    "  Install it:   python -m pip install cryptography\n"
    "                (or: python -m pip install homesoc[lens])\n"
    "  Or skip certificates entirely by putting Home SOC behind Tailscale Serve, which\n"
    "  supplies a genuinely trusted certificate and needs nothing installed on the phone\n"
    "  - see docs/LENS_SETUP.md."
)

_PEM_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.DOTALL
)


class TlsUnavailable(RuntimeError):
    """Raised when a TLS operation needs ``cryptography`` and it is not importable."""


def _cryptography() -> Any:
    """Import the pieces of ``cryptography`` we need, or explain how to get them.

    Imported here rather than at module scope on purpose: ``homesoc.web`` is imported by
    the dashboard on every start, and Home SOC must run normally without this package.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as exc:
        raise TlsUnavailable(_INSTALL_HINT) from exc
    return x509, hashes, serialization, ec, ExtendedKeyUsageOID, NameOID


def available() -> bool:
    """True when a certificate can be generated on this install."""
    try:
        _cryptography()
    except TlsUnavailable:
        return False
    return True


# ------------------------------------------------------------------ paths


def tls_dir() -> Path:
    path = paths.data_dir() / "tls"
    path.mkdir(parents=True, exist_ok=True)
    return path


def cert_paths() -> tuple[Path, Path]:
    """``(cert.pem, key.pem)`` under ``data/tls``. Neither file need exist yet."""
    directory = tls_dir()
    return directory / CERT_NAME, directory / KEY_NAME


# ------------------------------------------------------------------ hosts


def normalise_hosts(hosts: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split the requested names into (DNS names, IP addresses), de-duplicated.

    ``0.0.0.0``/``::`` mean "every interface" to a socket but nothing to a certificate,
    so they are dropped in favour of the concrete addresses the caller passes alongside.
    """
    names: list[str] = []
    addresses: list[str] = []
    for raw in list(hosts) + list(ALWAYS_HOSTS):
        host = str(raw or "").strip().strip("[]")
        if not host or host in ("0.0.0.0", "::", "*"):
            continue
        host = host.split("%", 1)[0]  # drop an IPv6 zone index
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            lowered = host.lower()
            if lowered not in names:
                names.append(lowered)
            continue
        text = str(address)
        if text not in addresses:
            addresses.append(text)
    return names, addresses


# ------------------------------------------------------------------ generation


def ensure_cert(hosts: list[str], *, days: int = DEFAULT_DAYS, force: bool = False) -> tuple[Path, Path]:
    """Return the certificate and key, generating them when needed.

    Idempotent: an existing certificate is reused unless ``force`` is set, it expires
    within :data:`RENEW_WITHIN_DAYS`, or it does not already cover every host in
    ``hosts`` (moving Home SOC to a new address must not silently serve a certificate
    for the old one). Raises :class:`TlsUnavailable` when a new certificate is needed
    and ``cryptography`` is not installed.
    """
    cert_path, key_path = cert_paths()
    reason = _regeneration_reason(cert_path, key_path, hosts, force=force)
    if reason is None:
        exposed = _key_exposure(key_path)
        if exposed is None:
            logger.debug("reusing existing certificate %s", cert_path)
            return cert_path, key_path
        # The key sat in a folder whose ACL other local accounts inherit (a copy under C:\ gives
        # BUILTIN\Users read and Authenticated Users modify). Anyone who read it can impersonate
        # this server to a paired phone with the very fingerprint the owner verified, and anyone
        # who replaced it chose that fingerprint. Neither is fixed by tightening the ACL now.
        try:
            logger.warning("replacing the Lens certificate: %s", exposed)
            _generate(cert_path, key_path, hosts, days=days)
        except TlsUnavailable:
            logger.warning("cannot regenerate without 'cryptography'; restricting the existing key to this account")
            _protect_windows_file(key_path)
            _protect_windows_file(cert_path)
        return cert_path, key_path
    logger.info("generating Lens certificate (%s)", reason)
    _generate(cert_path, key_path, hosts, days=days)
    return cert_path, key_path


def _regeneration_reason(cert_path: Path, key_path: Path, hosts: Iterable[str], *, force: bool) -> str | None:
    if force:
        return "forced"
    if not cert_path.is_file() or not key_path.is_file():
        return "no certificate yet"
    try:
        info = cert_info(cert_path)
    except TlsUnavailable:
        # Without cryptography we cannot inspect it, but we also cannot replace it;
        # reusing what is there is the only useful answer.
        logger.debug("cannot inspect %s without cryptography; reusing it", cert_path)
        return None
    except ValueError as exc:
        return f"existing certificate is unreadable ({exc})"
    if info["days_left"] <= RENEW_WITHIN_DAYS:
        return f"expires in {info['days_left']} day(s)"
    wanted_names, wanted_addresses = normalise_hosts(hosts)
    covered = {str(s).lower() for s in info["sans"]}
    missing = [h for h in wanted_names + wanted_addresses if h.lower() not in covered]
    if missing:
        return "does not cover " + ", ".join(missing)
    return None


def _generate(cert_path: Path, key_path: Path, hosts: Iterable[str], *, days: int) -> None:
    x509, hashes, serialization, ec, ExtendedKeyUsageOID, NameOID = _cryptography()
    names, addresses = normalise_hosts(hosts)
    if not names and not addresses:  # pragma: no cover - ALWAYS_HOSTS prevents this
        raise ValueError("no usable host names or addresses for the certificate")

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, names[0] if names else addresses[0]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Home SOC"),
    ])
    alt_names: list[Any] = [x509.DNSName(name) for name in names]
    alt_names += [x509.IPAddress(ipaddress.ip_address(address)) for address in addresses]
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # An hour of slack absorbs a phone whose clock is a few minutes behind.
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=max(1, int(days))))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=True, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    certificate = builder.sign(private_key=key, algorithm=hashes.SHA256())

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _write_private(key_path, key_bytes)
    # The certificate is public, but it must not be replaceable: the fingerprint the owner checks
    # on the phone is whatever this file says, so another account swapping in its own pair (the
    # key file is re-created above, the certificate would not be) would pass that check.
    _write_private(cert_path, certificate.public_bytes(serialization.Encoding.PEM))
    logger.info(
        "wrote %s (%d name(s), %d address(es), valid %d days, SHA-256 %s)",
        cert_path, len(names), len(addresses), days, cert_fingerprint_sha256(cert_path),
    )


def _write_private(path: Path, data: bytes) -> None:
    """Write the file so only this account can read or change it.

    POSIX: mode 0600. Windows: ``os.open``'s mode and ``chmod`` only toggle the read-only
    attribute, so the file would otherwise keep whatever ACL the folder hands down — private
    under the user profile, but readable by every local account in a copy under ``C:\\``. The
    empty file gets an explicit, non-inherited ACL (this account and SYSTEM) *before* the key
    bytes go into it, so there is no moment at which another account could read them.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    handle = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        if os.name == "nt" and not _protect_windows_file(path):
            raise OSError(f"could not restrict {path} to this account; refusing to write a private key into it")
        os.write(handle, data)
    except BaseException:
        os.close(handle)
        handle = -1
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        if handle != -1:
            os.close(handle)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:  # pragma: no cover - platform dependent
        logger.debug("could not restrict permissions on %s: %s", path, exc)


# ------------------------------------------------------------------ Windows ACLs


def _system32(tool: str) -> str:
    """Absolute path of a System32 tool, so a planted ``icacls.exe`` in the CWD or PATH never runs."""
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / tool)


def _current_user_sid() -> str | None:
    from homesoc import util

    rc, out, _err = util.run_cmd([_system32("whoami.exe"), "/user", "/fo", "csv", "/nh"], timeout=15)
    if rc != 0:
        return None
    sids = re.findall(r"S-1-[0-9-]+", out)
    return sids[-1] if sids else None


def _protect_windows_file(path: Path) -> bool:
    """Replace ``path``'s inherited ACL with full control for this account and SYSTEM only.

    True on success, and always True off Windows (the POSIX mode already did the job). SIDs,
    not account names, so it works on every Windows display language.
    """
    if os.name != "nt":
        return True
    sid = _current_user_sid()
    if not sid:
        logger.warning("cannot determine the current account's SID; %s keeps its inherited permissions", path)
        return False
    from homesoc import util

    rc, _out, err = util.run_cmd(
        [_system32("icacls.exe"), str(path), "/inheritance:r", "/grant:r", f"*{sid}:F", "/grant:r", "*S-1-5-18:F"],
        timeout=30,
    )
    if rc != 0:
        logger.warning("could not restrict %s to this account (icacls rc=%d): %s", path, rc, err.strip())
        return False
    return True


def _inside_user_profile(path: Path) -> bool:
    profile = os.environ.get("USERPROFILE", "").strip()
    if not profile:
        return False
    try:
        path.resolve().relative_to(Path(profile).resolve())
    except (ValueError, OSError):
        return False
    return True


def _key_exposure(key_path: Path) -> str | None:
    """Why an existing key can no longer be trusted, or ``None`` when it can.

    A key this module wrote carries an explicit ACL (no ``(I)`` entries in ``icacls``). One that
    still inherits its permissions came from an older release or from someone else; outside the
    user profile the folder it inherited from was readable by every local account, so the key
    must be treated as disclosed. Language-independent: ``(I)`` is not translated.
    """
    if os.name != "nt" or not key_path.is_file():
        return None
    from homesoc import util

    rc, out, _err = util.run_cmd([_system32("icacls.exe"), str(key_path)], timeout=30)
    if rc != 0 or "(I)" not in out:
        return None
    if _inside_user_profile(key_path):
        _protect_windows_file(key_path)  # private already; make it explicit so it stays that way
        return None
    return (f"{key_path} inherited its permissions from a folder outside your user profile, so other "
            "accounts on this PC could read or replace it; phones must accept the new certificate once")


# ------------------------------------------------------------------ inspection


def certificate_der(cert: Path | str) -> bytes:
    """The DER bytes of the first certificate in a PEM file (standard library only)."""
    raw = Path(cert).read_bytes()
    match = _PEM_BLOCK.search(raw)
    if match is None:
        raise ValueError(f"{cert} does not contain a PEM certificate")
    try:
        return base64.b64decode(b"".join(match.group(1).split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{cert} is not valid base64: {exc}") from None


def cert_fingerprint_sha256(cert: Path | str) -> str:
    """``AA:BB:...`` uppercase SHA-256 of the certificate, the form browsers show.

    Deliberately free of ``cryptography``: the owner must be able to compare this against
    what the phone shows even on an install that cannot generate certificates.
    """
    digest = hashlib.sha256(certificate_der(cert)).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def cert_info(cert: Path | str) -> dict[str, Any]:
    """``{subject, sans, not_before, not_after, fingerprint, days_left}`` for a certificate."""
    x509, _hashes, _serialization, _ec, _eku, _oid = _cryptography()
    try:
        certificate = x509.load_der_x509_certificate(certificate_der(cert))
    except Exception as exc:  # cryptography raises several unrelated types here
        raise ValueError(f"cannot parse {cert}: {exc}") from None
    sans: list[str] = []
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        logger.warning("%s has no subjectAltName; browsers will reject it", cert)
    else:
        sans = [str(value) for value in extension.value.get_values_for_type(x509.DNSName)]
        sans += [str(value) for value in extension.value.get_values_for_type(x509.IPAddress)]
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    remaining = not_after - dt.datetime.now(dt.timezone.utc)
    return {
        "subject": certificate.subject.rfc4514_string(),
        "sans": sans,
        "not_before": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fingerprint": cert_fingerprint_sha256(cert),
        "days_left": int(remaining.days),
    }


def describe(cert: Path | str | None = None) -> dict[str, Any]:
    """Everything the CLI and the pairing page want to say about the current certificate.

    Never raises: a missing file, a missing package and an unreadable certificate each
    come back as a state with a ``note`` the user can act on.
    """
    cert_path = Path(cert) if cert is not None else cert_paths()[0]
    key_path = cert_paths()[1]
    out: dict[str, Any] = {
        "path": str(cert_path),
        "key_path": str(key_path),
        "exists": cert_path.is_file(),
        "cryptography": available(),
        "fingerprint": None,
        "note": "",
    }
    if not out["exists"]:
        out["note"] = ("No certificate yet - run 'python -m homesoc lens cert --regenerate'."
                       if out["cryptography"] else _INSTALL_HINT)
        return out
    try:
        out["fingerprint"] = cert_fingerprint_sha256(cert_path)
    except (OSError, ValueError) as exc:
        out["note"] = f"certificate cannot be read: {exc}"
        return out
    try:
        out.update(cert_info(cert_path))
    except TlsUnavailable:
        out["note"] = "Install 'cryptography' to see the expiry date and the names it covers."
    except (OSError, ValueError) as exc:
        out["note"] = f"certificate cannot be parsed: {exc}"
    else:
        if out["days_left"] <= 0:
            out["note"] = "The certificate has expired; regenerate it."
        elif out["days_left"] <= RENEW_WITHIN_DAYS:
            out["note"] = f"The certificate expires in {out['days_left']} days; regenerate it soon."
    return out


__all__ = [
    "CERT_NAME",
    "KEY_NAME",
    "DEFAULT_DAYS",
    "RENEW_WITHIN_DAYS",
    "ALWAYS_HOSTS",
    "TlsUnavailable",
    "available",
    "tls_dir",
    "cert_paths",
    "normalise_hosts",
    "ensure_cert",
    "certificate_der",
    "cert_fingerprint_sha256",
    "cert_info",
    "describe",
]
