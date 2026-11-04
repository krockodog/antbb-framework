import type { Metadata } from "next";

import { ColonyRoom } from "@/components/colony-room";

export const metadata: Metadata = { title: "Yellow Queen · Gelbe Königin" };

export default function YellowPage() {
  return <ColonyRoom queen="yellow" />;
}
