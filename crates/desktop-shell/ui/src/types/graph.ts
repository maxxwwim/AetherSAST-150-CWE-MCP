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

export interface SsaVar {
  name: string;
  version: number;
  func_scope: string;
  line: number;
  file_path?: string;
}

export type SourceKind =
  | 'HttpQueryParam'
  | 'HttpBodyParam'
  | 'HttpHeader'
  | 'HttpCookie'
  | 'WebSocketPayload'
  | 'FileSystemRead'
  | 'DatabaseRead'
  | 'FunctionArgument'
  | { Custom: string };

export type SinkKind =
  | 'SqlExecution'
  | 'CommandExecution'
  | 'HtmlRender'
  | 'FileAccess'
  | 'SsrfNetworkRequest'
  | 'LdapQuery'
  | { Custom: string };

export type TaintStepKind =
  | 'DirectAssignment'
  | 'BinaryExpression'
  | 'PhiJoin'
  | {
      CallArgumentPassing: {
        caller_function: string;
        callee_function: string;
        arg_index: number;
        param_name: string;
      };
    }
  | {
      CallReturnPassing: {
        caller_function: string;
        callee_function: string;
      };
    }
  | {
      SanitizerCall: {
        sanitizer_name: string;
        cwe_targeted: string;
      };
    }
  | { Custom: string };

export interface TaintSource {
  var: SsaVar;
  source_kind: SourceKind;
  cwe: string;
  file_path: string;
  line: number;
  description?: string;
}

export interface TaintSink {
  var: SsaVar;
  sink_kind: SinkKind;
  cwe: string;
  rule_id?: string;
  severity?: string;
  file_path: string;
  line: number;
  description?: string;
}

export interface TaintStep {
  step_index: number;
  from_var: SsaVar;
  to_var: SsaVar;
  step_kind: TaintStepKind;
  line: number;
  is_sanitizer: boolean;
  sanitizer_name?: string | null;
  file_path?: string;
  code_snippet?: string | null;
}

export interface TaintFlowTrace {
  source: TaintSource;
  sink: TaintSink;
  steps: TaintStep[];
  is_sanitized: boolean;
  applied_sanitizers: string[];
  is_vulnerable: boolean;
}

export interface DataflowEdge {
  from_var: SsaVar;
  to_var: SsaVar;
  step_kind: TaintStepKind;
  line: number;
  is_sanitizer: boolean;
  sanitizer_name?: string | null;
  file_path?: string;
  code_snippet?: string | null;
}

export interface DataflowGraph {
  nodes: Record<string, SsaVar>;
  edges: DataflowEdge[];
  sources: TaintSource[];
  sinks: TaintSink[];
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
  taint_trace?: TaintFlowTrace;
}

export interface SymbolMetadata {
  lines?: number;
  file_type?: string;
  methods?: AstMethod[];
  attributes?: AstAttribute[];
  raw_content?: string;
  blake3_hash?: string;
  file_blake3_hash?: string;
  lock_verified?: boolean;
  ears_count?: number;
  contract_folder?: string;
  max_lines_limit?: number;
  file_max_lines_override?: number;
  violations?: string[];
  cve_anomalies?: CveAnomalyRecord[];
}

export type EditActivityKind = 'none' | 'modif' | 'text' | 'new_file' | 'new_folder' | 'violation';

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
  git_status?: 'clean' | 'modified' | 'untracked' | 'violation' | 'text' | 'new_folder';
  edit_kind?: EditActivityKind;
  last_edit_ts?: number;
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
  dataflow_graph?: DataflowGraph;
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

export interface GitFileChange {
  path: string;
  status: 'modified' | 'untracked' | 'staged' | 'deleted' | 'renamed' | 'conflict' | string;
  index_code?: string;
  worktree_code?: string;
  has_security_violation: boolean;
  cwe_count: number;
  ears_violation: boolean;
  max_severity?: string | null;
}

export interface GitStatusResponse {
  is_git_repo: boolean;
  branch?: string | null;
  clean: boolean;
  files: GitFileChange[];
  modified_count: number;
  untracked_count: number;
  staged_count: number;
  deleted_count: number;
  security_alert_count: number;
}

