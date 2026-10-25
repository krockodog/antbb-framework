import type { Metadata } from "next";

import { Laeufe } from "@/components/laeufe";

export const metadata: Metadata = { title: "Gelbe Läufe" };

export default function LaeufePage() {
  return <Laeufe />;
}
