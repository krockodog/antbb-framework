import type { Metadata } from "next";
import { Suspense } from "react";

import { BrainRoute } from "@/components/brain-route";

export const metadata: Metadata = { title: "Neural Brain · Gelb" };

export default function YellowBrainPage() {
  return (
    <Suspense fallback={<div className="brain-root" />}>
      <BrainRoute initialQueen="yellow" />
    </Suspense>
  );
}