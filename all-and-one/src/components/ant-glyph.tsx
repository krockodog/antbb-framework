"use client";

import { useId } from "react";

import type { QueenId } from "@/lib/brand";

const TONE: Record<
  QueenId,
  {
    sheen: string;
    body: string;
    deep: string;
    thorax: string;
    head: string;
    limb: string;
    eye: string;
    gold: string;
  }
> = {
  red: {
    sheen: "#d6455c",
    body: "#7a1730",
    deep: "#240810",
    thorax: "#4c1222",
    head: "#9a2340",
    limb: "#e6c48a",
    eye: "#f0d7a4",
    gold: "#f2d48a",
  },
  blue: {
    sheen: "#9ad8e6",
    body: "#1d5568",
    deep: "#07141c",
    thorax: "#143848",
    head: "#2f8498",
    limb: "#c5ebf3",
    eye: "#d9f6fb",
    gold: "#d7f3f8",
  },
  yellow: {
    sheen: "#f2c75a",
    body: "#8d6818",
    deep: "#1a1206",
    thorax: "#5a4210",
    head: "#c8962e",
    limb: "#f6e2aa",
    eye: "#ffe7ad",
    gold: "#ffe3a3",
  },
};

export function AntGlyph({
  queen,
  queenMark = false,
  className = "",
}: {
  queen: QueenId;
  queenMark?: boolean;
  className?: string;
}) {
  const raw = useId().replace(/:/g, "");
  const tone = TONE[queen];
  const fill = `ant-body-${raw}`;

  return (
    <svg
      viewBox="0 0 150 100"
      className={`ant-svg ${className}`}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={fill} x1="16" y1="34" x2="40" y2="64" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor={tone.sheen} />
          <stop offset="0.48" stopColor={tone.body} />
          <stop offset="1" stopColor={tone.deep} />
        </linearGradient>
      </defs>
      <g className="legs legs-a" fill="none" stroke={tone.limb} strokeWidth="2.15" strokeLinecap="round">
        <path d="M58 34 C48 20 40 14 28 11" />
        <path d="M66 33 C66 16 78 11 92 10" />
        <path d="M76 35 C90 20 102 15 116 14" />
      </g>
      <g className="legs legs-b" fill="none" stroke={tone.limb} strokeWidth="2.15" strokeLinecap="round">
        <path d="M58 66 C48 80 40 86 28 89" />
        <path d="M66 67 C66 84 78 89 92 90" />
        <path d="M76 65 C90 80 102 85 116 86" />
      </g>
      <ellipse
        cx="34"
        cy="50"
        rx="18"
        ry="13.5"
        fill={`url(#${fill})`}
        stroke={tone.limb}
        strokeOpacity="0.28"
        strokeWidth="0.7"
      />
      <ellipse cx="68" cy="50" rx="12" ry="10.5" fill={tone.thorax} stroke={tone.limb} strokeOpacity="0.3" strokeWidth="0.7" />
      <ellipse cx="98" cy="50" rx="13" ry="11" fill={tone.head} stroke={tone.limb} strokeOpacity="0.28" strokeWidth="0.7" />
      <ellipse cx="106" cy="46" rx="2.1" ry="2.5" fill={tone.eye} />
      <path d="M110 44 C122 32 132 26 144 18" fill="none" stroke={tone.limb} strokeWidth="1.6" strokeLinecap="round" className="antenna" />
      <path d="M110 55 C122 67 132 74 144 82" fill="none" stroke={tone.limb} strokeWidth="1.6" strokeLinecap="round" className="antenna antenna-b" />
      {queenMark ? (
        <g fill={tone.gold}>
          <circle cx="68" cy="31" r="1.7" />
          <circle cx="61" cy="34.5" r="1.25" />
          <circle cx="75" cy="34.5" r="1.25" />
        </g>
      ) : null}
    </svg>
  );
}
