import type { Metadata } from "next";

import { ColonyRoom } from "@/components/colony-room";

export const metadata: Metadata = { title: "Blaue Königin" };

export default function BluePage() {
  return <ColonyRoom queen="blue" />;
}
