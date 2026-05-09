/**
 * Email verification landing page.
 * The user arrives here via a link emailed by user-service:
 *   /auth/verify-email?token=<jwt>
 * We POST the token to /api/auth/verify-email and redirect to / on success.
 */
import { Suspense } from "react";
import { VerifyEmailClient } from "./verify-email-client";

export const metadata = { title: "Verify email" };

// VerifyEmailClient uses useSearchParams which requires dynamic
// rendering or a Suspense boundary in Next 16.
export const dynamic = "force-dynamic";

export default function VerifyEmailPage() {
  return (
    <Suspense fallback={null}>
      <VerifyEmailClient />
    </Suspense>
  );
}
