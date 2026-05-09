import { redirect } from "next/navigation";
import { getServerUser } from "@/lib/api/server";
import { SecurityClient } from "./security-client";

export const metadata = { title: "Security" };
export const dynamic = "force-dynamic";

export default async function SecurityPage() {
  const user = await getServerUser();
  if (!user) {
    redirect("/login?return_to=/security");
  }
  return <SecurityClient email={user.email} />;
}
