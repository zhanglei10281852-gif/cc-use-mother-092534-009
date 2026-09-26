"""领域错误类型。"""
from __future__ import annotations


class DomainError(Exception):
    """违反领域不变量时抛出；调用方应视为本次命令未生效。"""
