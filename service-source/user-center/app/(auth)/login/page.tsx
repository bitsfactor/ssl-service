import { Suspense } from "react";
import { LoginClient } from "./login-client";

export const metadata = { title: "Sign in" };

// Force dynamic — LoginClient uses useSearchParams which requires a
// Suspense boundary or dynamic rendering. user-center pages are all
// personalized anyway so static prerender wouldn't help.
export const dynamic = "force-dynamic";

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginClient />
    </Suspense>
  );
}
