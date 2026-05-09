// user-center i18n: messages registry.

import { de } from "./locales/de";
import { en } from "./locales/en";
import { ja } from "./locales/ja";
import { ko } from "./locales/ko";
import { zh } from "./locales/zh";
import type { LocaleId } from "./config";
import type { Messages as MessagesType } from "./locales/en";

const MESSAGES_BY_LOCALE = { zh, en, ja, ko, de } satisfies Record<
  LocaleId,
  MessagesType
>;

export type AllMessages = typeof MESSAGES_BY_LOCALE;
export type Messages = MessagesType;

export function getMessagesForLocale(locale: LocaleId): Messages {
  return MESSAGES_BY_LOCALE[locale] ?? en;
}

/**
 * Resolve `nav.dashboard` style dot paths. Returns the path itself as
 * a fallback so the UI still renders something if a key is missing.
 */
export function lookupMessage(messages: Messages, path: string): string {
  const parts = path.split(".");
  let cursor: unknown = messages;
  for (const p of parts) {
    if (
      cursor !== null &&
      typeof cursor === "object" &&
      p in (cursor as Record<string, unknown>)
    ) {
      cursor = (cursor as Record<string, unknown>)[p];
    } else {
      return path;
    }
  }
  return typeof cursor === "string" ? cursor : path;
}

/**
 * Replace {name} placeholders. Never throws — missing keys are left in
 * place so the translator notices.
 */
export function interpolate(
  template: string,
  vars: Record<string, string | number> | undefined
): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_, key) =>
    vars[key] != null ? String(vars[key]) : `{${key}}`
  );
}
