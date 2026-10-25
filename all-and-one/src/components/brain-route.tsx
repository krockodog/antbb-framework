"use client";

import { useSearchParams } from "next/navigation";

import { NeuralBrain } from "@/components/neural-brain";
import { isQueenId, type QueenId } from "@/lib/brand";

export function BrainRoute({ initialQueen = null }: { initialQueen?: QueenId | null }) {
  const params = useSearchParams();
  const raw = params.get("queen");
  const focus: QueenId | null = raw === "all" ? null : isQueenId(raw) ? raw : initialQueen;
  return (
    <>
      <NeuralBrain focus={focus} />
      <script src="/static/brain/superhirn-log.js?v=202610240215" defer />
    </>
  );
}
