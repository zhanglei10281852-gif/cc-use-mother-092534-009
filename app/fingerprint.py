"""证据内容指纹：规范化 JSON 后取 SHA-256。"""
from __future__ import annotations

import hashlib
import json


def fingerprint(content: dict) -> str:
    canonical = json.dumps(content, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
