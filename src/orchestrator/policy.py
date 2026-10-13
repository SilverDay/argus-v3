"""File-extension policy (spec §3.4).

Matching rules (explicit, as the spec requires):
* names are Unicode NFKC-normalised and case-folded;
* trailing dots and spaces are stripped (Windows ignores them: "evil.exe." runs as .exe);
* a configured extension matches if the name ends with "." + extension, so
  multi-part entries such as "tar.gz" work and "invoice.pdf.exe" matches "exe";
* extensionless names never match a block entry and are outside an allow-list scope.
Block matches are policy violations, not malware detections.
"""
from __future__ import annotations

import unicodedata
from collections.abc import Iterable


def _norm_ext(ext: str) -> str:
    return unicodedata.normalize("NFKC", ext).casefold().strip().lstrip(".")


def normalise_name(name: str) -> str:
    return unicodedata.normalize("NFKC", name).casefold().rstrip(". ")


class ExtensionPolicy:
    def __init__(self, block: Iterable[str] = (), allow: Iterable[str] = ()) -> None:
        self.block = tuple(sorted({_norm_ext(e) for e in block if _norm_ext(e)}, key=len, reverse=True))
        self.allow = tuple(sorted({_norm_ext(e) for e in allow if _norm_ext(e)}, key=len, reverse=True))

    @property
    def restricted_scope(self) -> bool:
        return bool(self.allow)

    @staticmethod
    def _matches(name: str, exts: tuple[str, ...]) -> str | None:
        base = normalise_name(name)
        for ext in exts:
            if base.endswith("." + ext) and len(base) > len(ext) + 1:
                return ext
        return None

    def blocked(self, name: str) -> str | None:
        """Return the matching blocked extension, if any."""
        return self._matches(name, self.block)

    def in_scope(self, name: str) -> bool:
        return not self.allow or self._matches(name, self.allow) is not None
