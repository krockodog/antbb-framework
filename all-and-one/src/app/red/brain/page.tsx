import type { Metadata } from "next";
import { Suspense } from "react";

import { BrainRoute } from "@/components/brain-route";

export const metadata: Metadata = { title: "Neural Brain · Rot" };

export default function RedBrainPage() {
  return (
    <Suspense fallback={<div className="brain-root" />}>
      <BrainRoute initialQueen="red" />
    </Suspense>
  );
}
