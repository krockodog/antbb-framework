import type { QueenId } from "@/lib/brand";

export type Playbook = {
  queen_id: QueenId;
  playbook_id: string;
  title: string;
  kind: string;
  summary: string;
  destructive: boolean;
  requires_oversight: boolean;
  stub: boolean;
  stub_note: string;
  needs_probe: boolean;
};

export type Soldier = {
  queen_id: QueenId;
  soldier_id: string;
  name: string;
  role: string;
  mode: string;
  tut: string;
  live_satz: string;
  playbook_ids: string[];
  playbooks: Playbook[];
  oversight_required: boolean;
  stub: boolean;
  stub_note: string;
};

export type RunRow = {
  run_id: string;
  queen_id: QueenId;
  soldier_id: string;
  playbook_id: string;
  status: string;
  created_at: string;
  summary: string;
};

export type LedgerRow = {
  queen_id: QueenId;
  run_id: string;
  at: string;
  message: string;
};

export type QueenSummary = {
  queen_id: QueenId;
  name: string;
  kicker: string;
  summary: string;
  cta: string;
  href: string;
  tut: string;
  strip_teil: string;
  live_satz: string;
  oversight: boolean;
  scope: string[];
  soldier_ids: string[];
  playbook_ids: string[];
};

export type QueenDetail = QueenSummary & {
  soldiers: Soldier[];
  playbooks: Playbook[];
  runs: RunRow[];
  ledger: LedgerRow[];
};

export type ClassifyStep = {
  order: number;
  title: string;
  tool: string;
  dynamic: boolean;
  erklaerbaerin: string;
  stub: boolean;
  stub_note: string;
};

export type ClassifyResult = {
  queen_id: "yellow";
  name: string;
  kind: string;
  kind_label: string;
  oversight: boolean;
  withheld: boolean;
  withheld_count: number;
  note: string;
  steps: ClassifyStep[];
  stub: boolean;
  stub_note: string;
};

export type Dossier = {
  run_id: string;
  queen_id: QueenId;
  soldier_id: string;
  soldier_name: string;
  playbook_id: string;
  playbook_title: string;
  targets: string[];
  probe_name: string | null;
  oversight: boolean;
  status: string;
  stub: boolean;
  stub_note: string;
  summary: string;
  created_at: string;
  plan: ClassifyResult | null;
};

export type BrainPayload = {
  product: string;
  description: string;
  footer: string;
  strip: string;
  focus: QueenId | null;
  queens: Array<QueenSummary & { soldiers: Soldier[] }>;
};
