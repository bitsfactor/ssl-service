import { redirect } from "next/navigation";

// Profile has merged into /account. Redirect for back-compat.
export default function ProfilePage() {
  redirect("/account");
}
