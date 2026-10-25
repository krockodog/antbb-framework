export const PRODUCT = "All and One - RED-BLUE-Yellow-Ant-Team";

export const DESCRIPTION =
  "Orchestrierte Ameisenfarmen — die vom Bug Bounty und Pentest über Reverse Engineering bis zum Schutz und Hardening helfen.";

export const FOOTER = "All and One · Red · Blue · Yellow";

export const QUEEN_IDS = ["red", "blue", "yellow"] as const;

export type QueenId = (typeof QUEEN_IDS)[number];

export function isQueenId(value: string | null | undefined): value is QueenId {
  return value === "red" || value === "blue" || value === "yellow";
}
