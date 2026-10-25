import type { Metadata } from "next";
import { Suspense } from "react";

import { BrainRoute } from "@/components/brain-route";

export const metadata: Metadata = { title: "Neural Brain" };

export default function BrainPage() {
  return (
    <Suspense fallback={<div className="brain-root" />}>
      <BrainRoute />
    </Suspense>
  );
}
