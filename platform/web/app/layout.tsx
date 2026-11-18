import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ShadowTrace Intelligence",
  description: "Evidence-first open-source intelligence workspace"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
