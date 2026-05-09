import { Suspense } from "react";
import { RegisterClient } from "./register-client";

export const metadata = { title: "Create account" };

// Force dynamic — RegisterClient uses useSearchParams which requires a
// Suspense boundary or dynamic rendering. user-center pages are all
// personalized anyway so static prerender wouldn't help.
export const dynamic = "force-dynamic";

export default function RegisterPage() {
  return (
    <Suspense fallback={null}>
      <RegisterClient />
    </Suspense>
  );
}
