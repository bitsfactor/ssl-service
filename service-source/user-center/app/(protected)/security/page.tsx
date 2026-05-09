import { getBootstrapData } from "@/lib/api/server";
import { SecurityClient } from "./security-client";

export const metadata = { title: "Security" };
export const dynamic = "force-dynamic";

export default async function SecurityPage() {
  const data = await getBootstrapData();
  if (!data) return null;
  return <SecurityClient email={data.user.email} />;
}
