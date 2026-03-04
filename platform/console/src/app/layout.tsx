import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "./providers";
import { NavSidebar } from "@/components/NavSidebar";

export const metadata: Metadata = {
  title: "OpenClaw — Endpoint Security",
  description: "OpenClaw endpoint security management console",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="h-full">
      <body className="h-full bg-gray-950 text-gray-100 antialiased">
        <Providers>
          <div className="flex h-full">
            <NavSidebar />
            <main className="flex-1 overflow-auto">{children}</main>
          </div>
        </Providers>
      </body>
    </html>
  );
}
