import { getBootstrapData } from "@/lib/api/server";
import { AccountClient } from "./account-client";

export const metadata = { title: "Account" };
export const dynamic = "force-dynamic";

export default async function AccountPage() {
  const data = await getBootstrapData();
  if (!data) return null;
  return <AccountClient user={data.user} />;
}
