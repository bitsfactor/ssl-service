import { redirect } from "next/navigation";

// Preferences has merged into /account. Redirect for back-compat.
export default function PreferencesPage() {
  redirect("/account");
}
