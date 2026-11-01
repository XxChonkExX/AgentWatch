"""Mail collector: .eml files, Maildir directories, and .mbox archives.

Each message becomes a body Artifact (headers + decoded text) plus one
Artifact per attachment. Attachment bytes are hashed in full even when the
detector sample is capped.
"""

from __future__ import annotations

import email
import hashlib
import mailbox
from pathlib import Path
from typing import Iterator

from ..core.hashing import hash_bytes
from ..core.schema import SAMPLE_CAP, Artifact, build_artifact
from .base import Collector


class MailCollector(Collector):
    name = "mail"

    def collect(self, target: str) -> Iterator[Artifact]:
        p = Path(target)
        if p.is_dir():
            yield from self._collect_dir(p)
        elif p.is_file():
            if p.suffix.lower() == ".mbox":
                yield from self._collect_mbox(p)
            else:
                yield from self._message(p.name, str(p), p.read_bytes())

    def _collect_dir(self, p: Path) -> Iterator[Artifact]:
        if (p / "cur").is_dir() or (p / "new").is_dir():
            for sub in ("cur", "new"):
                d = p / sub
                if not d.is_dir():
                    continue
                for f in sorted(d.iterdir()):
                    if f.is_file():
                        yield from self._message(f.name, str(f), f.read_bytes())
        else:
            for f in sorted(p.rglob("*.eml")):
                yield from self._message(f.name, str(f), f.read_bytes())

    def _collect_mbox(self, p: Path) -> Iterator[Artifact]:
        box = mailbox.mbox(str(p))
        for i, msg in enumerate(box):
            yield from self._message(f"{p.name}[{i}]", str(p), msg.as_bytes())

    def _message(self, name: str, path: str, raw: bytes) -> Iterator[Artifact]:
        msg = email.message_from_bytes(raw)
        mid = msg.get("Message-ID", "")
        frm = msg.get("From", "")
        subject = msg.get("Subject", "")

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == "text":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode("utf-8", "replace")
        else:
            payload = msg.get_payload(decode=True)
            body = payload.decode("utf-8", "replace") if payload else str(msg.get_payload())

        header = f"From: {frm}\nSubject: {subject}\nMessage-ID: {mid}\n"
        combined = (header + "\n" + body).encode("utf-8")
        yield build_artifact(
            "mail",
            path,
            name,
            combined[:SAMPLE_CAP],
            len(combined),
            hash_bytes(combined),
            {"message_id": mid, "from": frm, "subject": subject, "part": "body",
             "md5": hashlib.md5(combined).hexdigest()},
        )

        if msg.is_multipart():
            for i, part in enumerate(msg.walk()):
                if part.is_multipart():
                    continue
                disp = (part.get("Content-Disposition") or "").lower()
                fname = part.get_filename()
                if "attachment" not in disp and not fname:
                    continue
                payload = part.get_payload(decode=True) or b""
                aname = fname or f"part_{i}"
                yield build_artifact(
                    "mail",
                    path,
                    aname,
                    payload[:SAMPLE_CAP],
                    len(payload),
                    hash_bytes(payload),
                    {
                        "message_id": mid,
                        "from": frm,
                        "subject": subject,
                        "part": "attachment",
                        "filename": aname,
                        "md5": hashlib.md5(payload).hexdigest(),
                    },
                )
