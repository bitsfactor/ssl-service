"""Tiny i18n: fixed two-locale message catalog.

For v1 we keep this in-process (no DB lookup, no compile step). When
the catalog grows we move it to per-locale JSON files; the call sites
won't need to change because the public API is just ``t(locale, key)``.
"""
from __future__ import annotations

SUPPORTED_LOCALES = ("zh-CN", "en-US")
DEFAULT_LOCALE = "zh-CN"


_MESSAGES: dict[str, dict[str, str]] = {
  # Auth
  "auth.signup.email_required":          {"zh-CN": "邮箱不能为空",         "en-US": "Email is required"},
  "auth.signup.password_too_short":      {"zh-CN": "密码至少 8 位",        "en-US": "Password must be at least 8 characters"},
  "auth.signup.email_taken":             {"zh-CN": "该邮箱已注册",         "en-US": "Email already registered"},
  "auth.signup.invalid_email":           {"zh-CN": "邮箱格式不正确",       "en-US": "Invalid email format"},
  "auth.login.invalid":                  {"zh-CN": "邮箱或密码错误",       "en-US": "Invalid email or password"},
  "auth.login.disabled":                 {"zh-CN": "账户已被停用",         "en-US": "Account disabled"},
  "auth.session.expired":                {"zh-CN": "会话已过期,请重新登录", "en-US": "Session expired, please log in again"},
  "auth.session.required":               {"zh-CN": "请先登录",             "en-US": "Authentication required"},
  "auth.admin_required":                 {"zh-CN": "需要管理员权限",       "en-US": "Admin permission required"},
  # Generic
  "common.bad_request":                  {"zh-CN": "请求参数错误",         "en-US": "Bad request"},
  "common.not_found":                    {"zh-CN": "资源不存在",           "en-US": "Not found"},
  "common.conflict":                     {"zh-CN": "状态冲突",             "en-US": "Conflict"},
  "common.internal_error":               {"zh-CN": "服务器内部错误",       "en-US": "Internal server error"},
}


def normalize_locale(raw: str | None) -> str:
  if not raw:
    return DEFAULT_LOCALE
  raw = raw.strip()
  for loc in SUPPORTED_LOCALES:
    if raw.lower() == loc.lower():
      return loc
  # Best-effort BCP-47 prefix match (zh, zh-Hans → zh-CN; en, en-GB → en-US)
  prefix = raw.split("-", 1)[0].lower()
  if prefix == "zh":
    return "zh-CN"
  if prefix == "en":
    return "en-US"
  return DEFAULT_LOCALE


def negotiate_locale(accept_language: str | None,
                     user_locale: str | None = None) -> str:
  """User's stored preference wins, else first acceptable from header."""
  if user_locale:
    return normalize_locale(user_locale)
  if not accept_language:
    return DEFAULT_LOCALE
  # Parse just the first tag for simplicity (full Accept-Language is overkill).
  first = accept_language.split(",", 1)[0].split(";", 1)[0].strip()
  return normalize_locale(first)


def t(locale: str, key: str, **fmt) -> str:
  loc = normalize_locale(locale)
  msg = _MESSAGES.get(key, {}).get(loc) or _MESSAGES.get(key, {}).get(DEFAULT_LOCALE) or key
  if fmt:
    try:
      return msg.format(**fmt)
    except (KeyError, IndexError):
      return msg
  return msg
