/**
 * Auth layout — minimal chrome for login / register / verify-email.
 * No sidebar, no persistent nav — just the brand at the top.
 */
export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-screen flex-col">
      {/* Minimal top bar */}
      <header className="flex h-14 items-center border-b border-border/40 bg-background/85 px-4 backdrop-blur-md">
        <a
          href="/"
          className="flex items-center gap-2 rounded-md px-2 py-1.5 transition-colors hover:bg-muted/60"
        >
          {/* biome-ignore lint/performance/noImgElement: brand logo */}
          <img alt="Develop" className="size-7 rounded-md" src="/logo.png" />
          <span className="font-semibold text-sm tracking-tight">Develop</span>
        </a>
      </header>

      {/* Centered form area */}
      <main className="flex flex-1 items-center justify-center p-4">
        {children}
      </main>

      <footer className="py-4 text-center text-xs text-muted-foreground">
        &copy; {new Date().getFullYear()} BitsFactor LLC
      </footer>
    </div>
  );
}
