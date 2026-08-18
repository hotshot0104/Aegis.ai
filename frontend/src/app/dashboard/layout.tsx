import { AppSidebarContainer } from "@/components/app-sidebar";

export const dynamic = "force-dynamic";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AppSidebarContainer>{children}</AppSidebarContainer>;
}
