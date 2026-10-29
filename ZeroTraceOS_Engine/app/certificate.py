"""Ed25519-signed sanitization certificate generation and verification."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any
from io import BytesIO

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, Image
from reportlab.lib import colors

try:
    import qrcode
except ImportError:  # pragma: no cover
    qrcode = None


def _canonical_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load_or_create_keys(directory: Path) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / "ed25519_private.pem"
    public_path = directory / "ed25519_public.pem"
    if private_path.exists() and public_path.exists():
        private = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        public = serialization.load_pem_public_key(public_path.read_bytes())
        if not isinstance(private, Ed25519PrivateKey) or not isinstance(public, Ed25519PublicKey):
            raise ValueError("Stored signing keys are not Ed25519 keys")
        return private, public

    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    private_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    try:
        private_path.chmod(0o600)
    except OSError:
        pass
    return private, public


def _public_key_b64(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def generate_certificate(audit_path: Path, output_dir: Path | None = None) -> tuple[Path, Path]:
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    if not audit.get("certificate_ready"):
        raise ValueError("Audit record is not certificate-ready; sanitization must be verified first.")

    output_dir = output_dir or Path("certificates")
    output_dir.mkdir(parents=True, exist_ok=True)
    keys_dir = output_dir / "keys"
    private, public = _load_or_create_keys(keys_dir)

    device = audit["device_before"]
    execution = audit["execution"]
    verification = audit["post_verification"]
    plan = audit["sanitization_plan"]

    certificate_body: dict[str, Any] = {
        "certificate_version": "1.0",
        "certificate_type": "ZeroTrace-OS Sanitization Certificate",
        "standard_reference": "NIST SP 800-88 Rev. 2 / applicable approved sanitization technique",
        "device": {
            "path": device.get("path"),
            "model": device.get("model"),
            "serial": device.get("serial"),
            "size_bytes": device.get("size_bytes"),
            "media_type": device.get("device_type"),
            "transport": device.get("transport"),
        },
        "sanitization": {
            "method": plan.get("method"),
            "utility": plan.get("utility"),
            "command": execution.get("command"),
            "started_at": execution.get("started_at"),
            "completed_at": execution.get("completed_at"),
            "return_code": execution.get("return_code"),
        },
        "verification": verification,
        "reusability_score": device.get("reusability_score"),
    }

    canonical = _canonical_bytes(certificate_body)
    digest = hashlib.sha256(canonical).hexdigest()
    signature = private.sign(canonical)

    certificate = {
        **certificate_body,
        "integrity": {
            "canonical_sha256": digest,
            "signature_algorithm": "Ed25519",
            "signature_base64": base64.b64encode(signature).decode("ascii"),
            "public_key_base64": _public_key_b64(public),
        },
    }

    json_path = output_dir / "sanitization_certificate.json"
    pdf_path = output_dir / "sanitization_certificate.pdf"
    json_path.write_text(json.dumps(certificate, indent=2), encoding="utf-8")
    _write_pdf(pdf_path, certificate)
    return json_path, pdf_path


def _write_pdf(path: Path, certificate: dict[str, Any]) -> None:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=16*mm, leftMargin=16*mm,
                            topMargin=15*mm, bottomMargin=15*mm)
    story = [Paragraph("ZeroTrace-OS — Certificate of Sanitization", styles["Title"]), Spacer(1, 6*mm)]

    d = certificate["device"]
    s = certificate["sanitization"]
    v = certificate["verification"]
    rows = [
        ["Model", d.get("model") or "Unavailable"],
        ["Serial", d.get("serial") or "Unavailable"],
        ["Media type", d.get("media_type")],
        ["Size", str(d.get("size_bytes")) + " bytes"],
        ["Transport", d.get("transport") or "Unknown"],
        ["Sanitization method", s.get("method")],
        ["Utility", s.get("utility")],
        ["Started", s.get("started_at")],
        ["Completed", s.get("completed_at")],
        ["Verification", v.get("status")],
        ["First 1 MiB zero", str(v.get("first_mib_all_zero"))],
        ["Reusability score", str(certificate.get("reusability_score")) + "%" if certificate.get("reusability_score") is not None else "N/A"],
    ]
    table = Table(rows, colWidths=[48*mm, 125*mm])
    table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
        ("BACKGROUND", (0,0), (0,-1), colors.whitesmoke),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
    ]))
    story += [table, Spacer(1, 6*mm)]
    integ = certificate["integrity"]
    if qrcode is not None:
        qr_payload = json.dumps({
            "certificate_sha256": integ["canonical_sha256"],
            "public_key_base64": integ["public_key_base64"],
        }, separators=(",", ":"))
        qr = qrcode.QRCode(box_size=4, border=2)
        qr.add_data(qr_payload)
        qr.make(fit=True)
        image = qr.make_image()
        buf = BytesIO()
        image.save(buf, format="PNG")
        buf.seek(0)
        story += [Paragraph("Verification QR", styles["Heading3"]), Image(buf, width=35*mm, height=35*mm), Spacer(1, 4*mm)]
    story.append(Paragraph("SHA-256 of canonical signed data", styles["Heading3"]))
    story.append(Paragraph(integ["canonical_sha256"], styles["BodyText"]))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Ed25519 signature (Base64)", styles["Heading3"]))
    story.append(Paragraph(integ["signature_base64"], styles["BodyText"]))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Public key (Base64)", styles["Heading3"]))
    story.append(Paragraph(integ["public_key_base64"], styles["BodyText"]))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph("This certificate records the reported sanitization operation and its verification evidence. It does not by itself establish a universal guarantee of recoverability under every possible threat model.", styles["BodyText"]))
    doc.build(story)


def verify_certificate(path: Path) -> tuple[bool, str]:
    cert = json.loads(path.read_text(encoding="utf-8"))
    integrity = cert.get("integrity", {})
    signature = base64.b64decode(integrity["signature_base64"])
    public_raw = base64.b64decode(integrity["public_key_base64"])
    public = Ed25519PublicKey.from_public_bytes(public_raw)
    body = {k: cert[k] for k in cert if k != "integrity"}
    canonical = _canonical_bytes(body)
    digest = hashlib.sha256(canonical).hexdigest()
    if digest != integrity.get("canonical_sha256"):
        return False, "SHA-256 mismatch: certificate data was modified."
    try:
        public.verify(signature, canonical)
    except Exception:
        return False, "Ed25519 signature verification failed."
    return True, "Certificate integrity and Ed25519 signature verified."
