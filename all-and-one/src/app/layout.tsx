import type { Metadata } from "next";
import { Instrument_Sans, Instrument_Serif } from "next/font/google";

import "./globals.css";

const sans = Instrument_Sans({
  subsets: ["latin"],
  variable: "--font-instrument-sans",
});

const serif = Instrument_Serif({
  subsets: ["latin"],
  weight: "400",
  variable: "--font-instrument-serif",
});

export const metadata: Metadata = {
  title: {
    default: "All and One - RED-BLUE-Yellow-Ant-Team",
    template: "%s · All and One - RED-BLUE-Yellow-Ant-Team",
  },
  description:
    "Orchestrated security framework: bug bounty and pentest, protection and hardening, reverse engineering. Orchestriertes Security-Framework: Bug Bounty und Pentest, Schutz und Hardening, Reverse Engineering.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="de" className={`dark ${sans.variable} ${serif.variable}`}>
      <body className="min-h-dvh antialiased">{children}</body>
    </html>
  );
}
