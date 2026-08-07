import { getDatabase } from "../logging/log-store";
import { v4 as uuidv4 } from "uuid";

export interface ChainRecord {
  id: string;
  assessment_id?: string;
  pattern_id?: string;
  name: string;
  description?: string;
  severity_combined?: string;
  confidence?: number;
  status: string;
  finding_id?: string;
  emergent: number;
  steps_json?: string;
  required_tests_json?: string;
  exploit_results_json?: string;
  created_at: string;
  validated_at?: string;
}

export interface ChainLinkRecord {
  id: string;
  chain_id: string;
  finding_id: string;
  step_order: number;
  grants_json?: string;
  requires_json?: string;
  role: string;
}

export interface ChainInput {
  assessment_id?: string;
  pattern_id?: string;
  name: string;
  description?: string;
  severity_combined?: string;
  confidence?: number;
  status?: string;
  finding_id?: string;
  emergent?: boolean;
  steps_json?: string;
  required_tests_json?: string;
}

export interface ChainLinkInput {
  chain_id: string;
  finding_id: string;
  step_order: number;
  grants?: string[];
  requires?: string[];
  role?: string;
}

export async function createChain(input: ChainInput): Promise<ChainRecord> {
  const db = getDatabase();
  const id = uuidv4();
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO finding_chains (id, assessment_id, pattern_id, name, description,
      severity_combined, confidence, status, finding_id, emergent,
      steps_json, required_tests_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    input.assessment_id || null,
    input.pattern_id || null,
    input.name,
    input.description || null,
    input.severity_combined || null,
    input.confidence ?? null,
    input.status || "hypothesized",
    input.finding_id || null,
    input.emergent ? 1 : 0,
    input.steps_json || null,
    input.required_tests_json || null,
    now
  );

  return {
    id,
    assessment_id: input.assessment_id,
    pattern_id: input.pattern_id,
    name: input.name,
    description: input.description,
    severity_combined: input.severity_combined,
    confidence: input.confidence,
    status: input.status || "hypothesized",
    finding_id: input.finding_id,
    emergent: input.emergent ? 1 : 0,
    steps_json: input.steps_json,
    required_tests_json: input.required_tests_json,
    created_at: now,
  };
}

export async function addChainLink(input: ChainLinkInput): Promise<ChainLinkRecord> {
  const db = getDatabase();
  const id = uuidv4();

  db.prepare(`
    INSERT INTO finding_chain_links (id, chain_id, finding_id, step_order, grants_json, requires_json, role)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    input.chain_id,
    input.finding_id,
    input.step_order,
    input.grants ? JSON.stringify(input.grants) : null,
    input.requires ? JSON.stringify(input.requires) : null,
    input.role || "step"
  );

  return {
    id,
    chain_id: input.chain_id,
    finding_id: input.finding_id,
    step_order: input.step_order,
    grants_json: input.grants ? JSON.stringify(input.grants) : undefined,
    requires_json: input.requires ? JSON.stringify(input.requires) : undefined,
    role: input.role || "step",
  };
}

export async function updateChainStatus(
  chainId: string,
  status: string,
  exploitResults?: string
): Promise<void> {
  const db = getDatabase();
  const now = new Date().toISOString();

  db.prepare(`
    UPDATE finding_chains
    SET status = ?, exploit_results_json = COALESCE(?, exploit_results_json), validated_at = ?
    WHERE id = ?
  `).run(status, exploitResults || null, now, chainId);
}

export async function getChainsForAssessment(assessmentId: string): Promise<ChainRecord[]> {
  const db = getDatabase();
  return db.prepare(
    "SELECT * FROM finding_chains WHERE assessment_id = ? ORDER BY created_at DESC"
  ).all(assessmentId) as ChainRecord[];
}

export interface ChainWithLinks extends ChainRecord {
  links: ChainLinkRecord[];
}

export async function getChainWithLinks(chainId: string): Promise<ChainWithLinks | null> {
  const db = getDatabase();

  const chain = db.prepare("SELECT * FROM finding_chains WHERE id = ?").get(chainId) as ChainRecord | undefined;
  if (!chain) return null;

  const links = db.prepare(
    "SELECT * FROM finding_chain_links WHERE chain_id = ? ORDER BY step_order ASC"
  ).all(chainId) as ChainLinkRecord[];

  return { ...chain, links };
}

export async function getChainsForFinding(findingId: string): Promise<ChainRecord[]> {
  const db = getDatabase();
  return db.prepare(`
    SELECT DISTINCT fc.* FROM finding_chains fc
    JOIN finding_chain_links fcl ON fc.id = fcl.chain_id
    WHERE fcl.finding_id = ?
    ORDER BY fc.created_at DESC
  `).all(findingId) as ChainRecord[];
}
