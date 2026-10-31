"""Magic-byte and filename gate.

Compares leading bytes against the name. Executable magic (PE/ELF) in a
non-executable file is escalated to critical. A decoy extension in front of
an executable/script extension is high. A shebang in a non-script file is low.
"""

from __future__ import annotations

import re

from ..core.schema import EXEC_EXT, SCRIPT_EXT, TEXT_EXT, Artifact, Evidence, Finding
from .base import Detector
from .rules import AW_F003

MAGICS = (
    (b"MZ", "PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "ZIP/Office container"),
    (b"%PDF", "PDF"),
    (b"\x89PNG", "PNG"),
    (b"\x1f\x8b", "gzip"),
    (b"Rar!", "RAR"),
    (b"7z\xbc\xaf", "7z"),
    (b"\xd0\xcf\x11\xe0", "OLE/legacy Office"),
)

DOUBLE_EXT_RE = re.compile(
    r"\.(?:txt|pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|gif|bmp|mp4|mp3|wav|zip|rar|"
    r"json|csv|md|html?|xml|log|eml)\.[a-z0-9]{2,4}$",
    re.I,
)


class MagicMismatchDetector(Detector):
    name = "magic.mismatch"
    rule = AW_F003

    def run(self, artifact: Artifact) -> list[Finding]:
        out: list[Finding] = []
        sample = artifact.sample
        ext = artifact.ext

        magic = None
        for sig, label in MAGICS:
            if sample.startswith(sig):
                magic = (sig, label)
                break

        if magic:
            sig, label = magic
            if sig in (b"MZ", b"\x7fELF") and ext not in EXEC_EXT:
                detail = "executable magic (%s) in a file named %r" % (label, artifact.name)
                ev = [Evidence(path=artifact.path, note=label)]
                out.append(self.finding(self.rule, artifact, detail, ev, severity="critical"))
            elif sig == b"PK\x03\x04" and ext in TEXT_EXT:
                detail = "archive/office container magic with text extension %r" % artifact.name
                ev = [Evidence(path=artifact.path, note=label)]
                out.append(self.finding(self.rule, artifact, detail, ev))
            elif sig == b"%PDF" and ext != ".pdf":
                detail = "PDF magic with extension %r" % (ext or "<none>")
                ev = [Evidence(path=artifact.path, note=label)]
                out.append(self.finding(self.rule, artifact, detail, ev, severity="low"))

        if sample.startswith(b"#!") and ext not in SCRIPT_EXT:
            detail = "shebang in a non-script file %r" % artifact.name
            ev = [Evidence(path=artifact.path, note="shebang")]
            out.append(self.finding(self.rule, artifact, detail, ev, severity="low"))

        if DOUBLE_EXT_RE.search(artifact.name):
            last = "." + artifact.name.rsplit(".", 1)[-1].lower()
            if last in EXEC_EXT:
                detail = "double extension ending in %s: %r" % (last, artifact.name)
                ev = [Evidence(path=artifact.path, note="double extension")]
                out.append(self.finding(self.rule, artifact, detail, ev, severity="high"))

        return out
