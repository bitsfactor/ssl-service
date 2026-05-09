import type { ServiceEntry } from "./types";

/**
 * The Develop service registry — every service that should appear in
 * the cross-service switcher in the header. Keep this in sync with
 * the actual deployed surfaces; the switcher renders entries in this
 * order.
 *
 * Adding a new service:
 *   1. Add the entry below with a stable id, locale-keyed labels,
 *      and the production URL.
 *   2. Mark `comingSoon: true` while it's being built — the menu will
 *      show it greyed out.
 *   3. Drop it into the consumer's <SiteHeader currentServiceId="…" />
 *      to mark it as the active surface.
 */
export const DEFAULT_SERVICES: ServiceEntry[] = [
  {
    id: "home",
    label: {
      en: "Home",
      zh: "首页",
      ja: "ホーム",
      ko: "홈",
      de: "Startseite",
    },
    description: {
      en: "Welcome page and product overview",
      zh: "欢迎页与产品概览",
      ja: "ようこそページと製品概要",
      ko: "환영 페이지와 제품 개요",
      de: "Willkommensseite und Produktübersicht",
    },
    url: "https://develop.cc",
    comingSoon: true,
  },
  {
    id: "account",
    label: {
      en: "Account",
      zh: "账户",
      ja: "アカウント",
      ko: "계정",
      de: "Konto",
    },
    description: {
      en: "Profile, billing, security, preferences",
      zh: "个人资料、账单、安全、偏好设置",
      ja: "プロフィール、請求、セキュリティ、設定",
      ko: "프로필, 결제, 보안, 설정",
      de: "Profil, Abrechnung, Sicherheit, Einstellungen",
    },
    url: "https://user.develop.cc",
  },
  {
    id: "chat",
    label: {
      en: "Chat",
      zh: "聊天",
      ja: "チャット",
      ko: "채팅",
      de: "Chat",
    },
    description: {
      en: "AI conversations, image generation, vision",
      zh: "AI 对话、图片生成、视觉理解",
      ja: "AI 会話、画像生成、ビジョン",
      ko: "AI 대화, 이미지 생성, 비전",
      de: "KI-Gespräche, Bildgenerierung, Vision",
    },
    url: "https://chat.develop.cc",
  },
  {
    id: "xout",
    label: {
      en: "Xout",
      zh: "Xout",
      ja: "Xout",
      ko: "Xout",
      de: "Xout",
    },
    description: {
      en: "Private networking and proxy services",
      zh: "私人网络与代理服务",
      ja: "プライベートネットワーキングとプロキシサービス",
      ko: "프라이빗 네트워킹 및 프록시 서비스",
      de: "Privates Netzwerk und Proxy-Dienste",
    },
    url: "https://xout.develop.cc",
    comingSoon: true,
  },
];
