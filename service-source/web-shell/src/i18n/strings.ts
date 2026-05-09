import type { LocaleId } from "../types";

/**
 * Header-local strings. Each consumer of `web-shell` may already have
 * its own i18n catalogue; we don't try to share it. Keep the set
 * here small — only labels rendered inside the header itself.
 */
export type HeaderStrings = {
  switchService: string;
  switchServiceDesc: string;
  comingSoon: string;
  language: string;
  theme: string;
  themeLight: string;
  themeDark: string;
  themeSystem: string;
  signIn: string;
  signUp: string;
  signOut: string;
  myAccount: string;
  preferences: string;
  loading: string;
  guest: string;
  openMenu: string;
};

export const HEADER_STRINGS: Record<LocaleId, HeaderStrings> = {
  en: {
    switchService: "Switch service",
    switchServiceDesc: "Jump to another part of Develop",
    comingSoon: "Coming soon",
    language: "Language",
    theme: "Theme",
    themeLight: "Light",
    themeDark: "Dark",
    themeSystem: "System",
    signIn: "Sign in",
    signUp: "Sign up",
    signOut: "Sign out",
    myAccount: "My account",
    preferences: "Preferences",
    loading: "Loading…",
    guest: "Guest",
    openMenu: "Open menu",
  },
  zh: {
    switchService: "切换服务",
    switchServiceDesc: "跳到 Develop 的其他模块",
    comingSoon: "即将上线",
    language: "语言",
    theme: "主题",
    themeLight: "浅色",
    themeDark: "深色",
    themeSystem: "跟随系统",
    signIn: "登录",
    signUp: "注册",
    signOut: "退出登录",
    myAccount: "用户中心",
    preferences: "偏好设置",
    loading: "加载中…",
    guest: "访客",
    openMenu: "打开菜单",
  },
  ja: {
    switchService: "サービスを切り替え",
    switchServiceDesc: "Develop の他のモジュールへ移動",
    comingSoon: "近日公開",
    language: "言語",
    theme: "テーマ",
    themeLight: "ライト",
    themeDark: "ダーク",
    themeSystem: "システムに従う",
    signIn: "ログイン",
    signUp: "新規登録",
    signOut: "ログアウト",
    myAccount: "アカウント",
    preferences: "設定",
    loading: "読み込み中…",
    guest: "ゲスト",
    openMenu: "メニューを開く",
  },
  ko: {
    switchService: "서비스 전환",
    switchServiceDesc: "Develop의 다른 모듈로 이동",
    comingSoon: "출시 예정",
    language: "언어",
    theme: "테마",
    themeLight: "라이트",
    themeDark: "다크",
    themeSystem: "시스템 사용",
    signIn: "로그인",
    signUp: "회원가입",
    signOut: "로그아웃",
    myAccount: "계정",
    preferences: "환경설정",
    loading: "로딩 중…",
    guest: "게스트",
    openMenu: "메뉴 열기",
  },
  de: {
    switchService: "Dienst wechseln",
    switchServiceDesc: "Zu einem anderen Develop-Modul springen",
    comingSoon: "Demnächst",
    language: "Sprache",
    theme: "Thema",
    themeLight: "Hell",
    themeDark: "Dunkel",
    themeSystem: "Systemvorgabe",
    signIn: "Anmelden",
    signUp: "Registrieren",
    signOut: "Abmelden",
    myAccount: "Mein Konto",
    preferences: "Einstellungen",
    loading: "Wird geladen…",
    guest: "Gast",
    openMenu: "Menü öffnen",
  },
};
