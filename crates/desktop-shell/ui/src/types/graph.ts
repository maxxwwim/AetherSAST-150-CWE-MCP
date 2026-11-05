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
  signature: string;
  visibility: string;
  line: number;
}

export interface AstAttribute {
  name: string;
  attr_type: string;
  visibility: string;
}

export interface CveAnomalyRecord {
  cve_id: string;
  cwe_class: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  remediation: string;
  file_path: string;
  line_number: number;
  snippet?: string;
  transgression_data?: string;
}

export interface SymbolBubble {
  id: string;
  name: string;
  kind: SymbolKind;
  layer: string;
  file_path: string;
  line_number: number;
  loc: number;
  cyclomatic_complexity: number;
  in_degree: number;
  out_degree: number;
  docstring?: string;
  methods: AstMethod[];
  attributes: AstAttribute[];
  anomalies: CveAnomalyRecord[];
  is_orphan: boolean;
  x: number;
  y: number;
  z: number;
  cluster_id: string;
}

export interface AffiliationEdge {
  source: string;
  target: string;
  edge_type: 'Call' | 'Import' | 'Data' | 'Error' | 'Test' | 'Layout';
  weight: number;
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
