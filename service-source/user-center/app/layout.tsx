import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { Suspense } from "react";
import { Toaster } from "sonner";
import { ThemeProvider } from "@/components/theme-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { DEFAULT_LOCALE } from "@/lib/i18n/config";
import { I18nProvider } from "@/lib/i18n/i18n-provider";
import { getServerLocale } from "@/lib/i18n/get-locale";

import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://user.develop.cc"),
  title: {
    default: "Account — Develop",
    template: "%s · Develop",
  },
  description:
    "Develop Account Center — manage your profile, billing, security, and preferences.",
  applicationName: "Develop",
  authors: [{ name: "BitsFactor LLC" }],
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/favicon-32.png", type: "image/png", sizes: "32x32" },
      { url: "/favicon-16.png", type: "image/png", sizes: "16x16" },
      { url: "/icon-192.png", type: "image/png", sizes: "192x192" },
      { url: "/icon-512.png", type: "image/png", sizes: "512x512" },
    ],
    apple: "/apple-touch-icon.png",
  },
};

export const viewport = {
  maximumScale: 1,
};

const geist = Geist({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-geist",
});

const geistMono = Geist_Mono({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-geist-mono",
});

// Inline script that sets the theme-color meta tag before React
// hydrates to avoid a flash of the wrong mobile toolbar colour.
const LIGHT_THEME_COLOR = "hsl(0 0% 100%)";
const DARK_THEME_COLOR = "hsl(240deg 10% 3.92%)";
const THEME_COLOR_SCRIPT = `\
(function() {
  var html = document.documentElement;
  var meta = document.querySelector('meta[name="theme-color"]');
  if (!meta) {
    meta = document.createElement('meta');
    meta.setAttribute('name', 'theme-color');
    document.head.appendChild(meta);
  }
  function updateThemeColor() {
    var isDark = html.classList.contains('dark');
    meta.setAttribute('content', isDark ? '${DARK_THEME_COLOR}' : '${LIGHT_THEME_COLOR}');
  }
  var observer = new MutationObserver(updateThemeColor);
  observer.observe(html, { attributes: true, attributeFilter: ['class'] });
  updateThemeColor();
})();`;

/**
 * Shared provider tree. Used by both the locale-aware and static shells
 * so client hooks (useT, useTheme) never crash during prerender.
 */
function ProvidersTree({
  locale,
  children,
}: {
  locale: string;
  children: React.ReactNode;
}) {
  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="system"
      disableTransitionOnChange
      enableSystem
    >
      <I18nProvider locale={locale as never}>
        <TooltipProvider>
          {children}
          <Toaster
            position="bottom-right"
            toastOptions={{
              classNames: {
                toast:
                  "!bg-card !text-card-foreground !border-border !shadow-[var(--shadow-float)]",
                description: "!text-muted-foreground",
                actionButton: "!bg-primary !text-primary-foreground",
                cancelButton: "!bg-muted !text-muted-foreground",
              },
            }}
          />
        </TooltipProvider>
      </I18nProvider>
    </ThemeProvider>
  );
}

function ThemeColorScript() {
  return (
    <script
      // biome-ignore lint/security/noDangerouslySetInnerHtml: needed for theme-color before hydration
      dangerouslySetInnerHTML={{ __html: THEME_COLOR_SCRIPT }}
    />
  );
}

// Locale-aware shell — awaits cookies/headers so it lives in a Suspense
// boundary. Next.js 16 blocks static prerender of async-data trees.
async function LocaleShell({ children }: { children: React.ReactNode }) {
  const locale = await getServerLocale();
  return (
    <html
      className={`${geist.variable} ${geistMono.variable}`}
      lang={locale}
      suppressHydrationWarning
    >
      <head>
        <ThemeColorScript />
      </head>
      <body className="antialiased">
        <ProvidersTree locale={locale}>{children}</ProvidersTree>
      </body>
    </html>
  );
}

// Pure-static fallback. Replaced by LocaleShell once dynamic data resolves.
function StaticShell({ children }: { children: React.ReactNode }) {
  return (
    <html
      className={`${geist.variable} ${geistMono.variable}`}
      lang={DEFAULT_LOCALE}
      suppressHydrationWarning
    >
      <head>
        <ThemeColorScript />
      </head>
      <body className="antialiased">
        <ProvidersTree locale={DEFAULT_LOCALE}>{children}</ProvidersTree>
      </body>
    </html>
  );
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <Suspense fallback={<StaticShell>{children}</StaticShell>}>
      <LocaleShell>{children}</LocaleShell>
    </Suspense>
  );
}
