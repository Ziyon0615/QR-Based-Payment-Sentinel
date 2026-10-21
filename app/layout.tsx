import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "QRBased Sentinel | Scan Before You Pay",
  description: "A threat-intelligence-driven research prototype for real-time detection and explainable risk assessment of QR payment payloads.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
