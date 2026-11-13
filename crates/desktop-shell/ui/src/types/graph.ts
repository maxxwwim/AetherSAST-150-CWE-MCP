export type SymbolKind =
  | 'Function'
  | 'Method'
  | 'Struct'
  | 'Class'
  | 'Interface'
  | 'Trait'
  | 'Module'
  | 'File'
  | 'Endpoint'
  | 'Query'
  | 'Form'
  | 'Other';

export interface AstMethod {
  name: string;
  signature?: string;
  args?: string;
  returns?: string;
  is_async?: boolean;
  calls?: string[];
  docstring?: string;
  visibility?: string;
  line?: number;
}

export interface AstAttribute {
  name: string;
  attr_type?: string;
  type?: string;
  visibility?: string;
}

export interface CveAnomalyRecord {
  rule_id?: string;
  cve_id: string;
  cwe_class?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  title?: string;
  description?: string;
  message?: string;
  remediation: string;
  file_path: string;
  line_number: number;
  snippet?: string;
  transgression_data?: string;
  transmitted_data?: string;
  transmitted_type?: string;
  is_reachable?: boolean;
  exploit_path?: string[];
}

export interface SymbolMetadata {
  lines?: number;
  file_type?: string;
  methods?: AstMethod[];
  attributes?: AstAttribute[];
  raw_content?: string;
  blake3_hash?: string;
  lock_verified?: boolean;
  ears_count?: number;
  violations?: string[];
  cve_anomalies?: CveAnomalyRecord[];
}

export interface SymbolBubble {
  id: string;
  name: string;
  kind: SymbolKind | string;
  galaxy?: string;
  layer: string;
  file_path: string;
  folder?: string;
  symbol_type?: string;
  stereotype?: string;
  is_file?: boolean;
  is_class?: boolean;
  is_form?: boolean;
  is_dead_code?: boolean;
  has_security_violation?: boolean;
  birth_time?: number;
  layouts?: {
    obsidian?: { x: number; y: number };
    system?: { x: number; y: number };
    flow?: { x: number; y: number };
    classes?: { x: number; y: number };
  };
  line_number: number;
  loc: number;
  lines_count?: number;
  cyclomatic_complexity: number;
  complexity?: number;
  in_degree: number;
  out_degree: number;
  docstring?: string;
  methods: AstMethod[];
  attributes: AstAttribute[];
  anomalies?: CveAnomalyRecord[];
  violations?: CveAnomalyRecord[];
  metadata?: SymbolMetadata;
  is_orphan: boolean;
  x: number;
  y: number;
  z: number;
  cluster_id: string;
}

export interface AffiliationEdge {
  source: string;
  target: string;
  edge_type?: 'Call' | 'Import' | 'Data' | 'Error' | 'Test' | 'Layout' | string;
  relation?: string;
  weight?: number;
  cve_id?: string;
  severity?: string;
  transmitted_data?: string;
}

export interface AetherGraph {
  project_name: string;
  project_path?: string;
  nodes: SymbolBubble[];
  edges: AffiliationEdge[];
  clusters: Record<string, string[]>;
  anomalies_count: number;
  critical_count: number;
  system_prompt?: string;
}

export interface TaskItem {
  id: string;
  title: string;
  kind: 'function' | 'research' | 'security_fix' | 'arch_refactor' | 'other';
  status: 'pending' | 'in_progress' | 'blocked' | 'done';
  priority: 'low' | 'medium' | 'high' | 'critical';
  progress: number;
  target_symbol?: string;
  target_file?: string;
  author: string;
  created_at: string;
  updated_at: string;
  readme: string;
}
