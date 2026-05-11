import { getBootstrapData } from "@/lib/api/server";
import { OrdersClient } from "./orders-client";

export const metadata = { title: "Orders" };
export const dynamic = "force-dynamic";

export default async function OrdersPage() {
  const data = await getBootstrapData();
  if (!data) return null;
  return <OrdersClient orders={data.orders} />;
}
