import type { Metadata } from "next";

import { ColonyRoom } from "@/components/colony-room";

export const metadata: Metadata = { title: "Rote Königin" };

export default function RedPage() {
  return <ColonyRoom queen="red" />;
}
