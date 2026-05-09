import { getServerUser } from "@/lib/api/server";
import { ProfileClient } from "./profile-client";

export const metadata = { title: "Profile" };

export default async function ProfilePage() {
  const user = await getServerUser();
  if (!user) return null;
  return <ProfileClient user={user} />;
}
