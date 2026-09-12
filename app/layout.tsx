import type { Metadata } from "next";
import { Be_Vietnam_Pro, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

// The interface is written entirely in Vietnamese, so the UI face is one drawn
// for Vietnamese diacritics rather than a Latin face with fallback marks.
const interfaceFont = Be_Vietnam_Pro({ variable: "--font-operation-ui", weight: ["400", "500", "600", "700"], subsets: ["latin", "vietnamese"] });
const dataFont = IBM_Plex_Mono({ variable: "--font-operation-data", weight: ["400", "500"], subsets: ["latin"] });

export const metadata: Metadata = {
  title: { default: "Operation Portal", template: "%s · Operation Portal" },
  description: "Dashboard quản trị tập trung Windows Server, Ubuntu và Oracle Linux.",
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="vi">
      <body className={`${interfaceFont.variable} ${dataFont.variable}`}>{children}</body>
    </html>
  );
}
