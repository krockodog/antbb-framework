import type { Metadata } from "next";
import { Suspense } from "react";

import { BrainRoute } from "@/components/brain-route";

export const metadata: Metadata = { title: "Neural Brain · Blau" };

export default function BlueBrainPage() {
  return (
    <Suspense fallback={<div className="brain-root" />}>
      <BrainRoute initialQueen="blue" />
    </Suspense>
  );
}
