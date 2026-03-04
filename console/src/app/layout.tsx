// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";
import { Providers } from "@/lib/providers";

export const metadata: Metadata = {
  title: "OpenClaw Console",
  description: "OpenClaw endpoint security platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Providers>
          <div className="flex min-h-screen">
            <Sidebar />
            <main className="flex-1 overflow-auto">{children}</main>
          </div>
        </Providers>
      </body>
    </html>
  );
}
