import type { AetherGraph, TaskItem } from '../types/graph';
import type { VisualPluginPack } from '../engine/visualPlugins';

export interface VisualPluginsInventoryResponse {
  status: string;
  visuals_dir: string;
  active_visual_plugin: string;
  visual_version: number;
  plugins: VisualPluginPack[];
}

export interface PluginRuleSummary {
  id: string;
  cwe_id: string;
  name: string;
  category: string;
  severity: string;
  description: string;
  remediation: string;
  file_extensions: string[];
  match_mode: string;
  check_literals: boolean;
  must_contain: string[];
  must_not_contain: string[];
  regex_patterns: string[];
  forbidden_tokens: string[];
  not_preceded_within_lines?: { patterns: string[]; lines: number } | null;
  in_path_matching: string[];
  not_in_path_matching: string[];
  ast_scope?: string | null;
  test_cases_count: number;
}

export interface PluginEntryInfo {
  name: string;
  rel_path: string;
  folder_alias?: string | null;
  version: string;
  author?: string | null;
  description?: string | null;
  enabled: boolean;
  profile?: string | null;
  tags: string[];
  rules_count: number;
  test_cases_count: number;
  taint_sources_count: number;
  taint_sinks_count: number;
  sanitizers_count: number;
  rules: PluginRuleSummary[];
  taint_sources: any[];
  taint_sinks: any[];
  sanitizers: any[];
}

export interface PluginsInventoryResponse {
  status: string;
  plugins_dir: string;
  community_bundle_installed: boolean;
  community_bundle_rules_count: number;
  total_plugins: number;
  enabled_plugins: number;
  total_active_rules: number;
  total_taint_sources: number;
  total_taint_sinks: number;
  total_sanitizers: number;
  plugins: PluginEntryInfo[];
}

export interface PluginTestReportResponse {
  status: string;
  total_tests: number;
  passed: number;
  failed: number;
  failures: string[];
}

export interface ProjectStatusResponse {
  status?: string;
  project_type: 'PureCode' | 'PureObsidianVault' | 'Mixed' | string;
  has_obsidian_dir?: boolean;
  obsidian_dir_path?: string | null;
  supported_views?: string[];
  active_view_mode?: string;
  active_view?: string;
  code_files_count?: number;
  markdown_files_count?: number;
  obsidian_syntax_markers_count?: number;
}

export class AetherApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = '') {
    this.baseUrl = baseUrl;
  }

  async getGraph(): Promise<AetherGraph> {
    const res = await fetch(`${this.baseUrl}/api/graph`);
    return res.json();
  }

  async getProjects(): Promise<{ projects: string[]; default_project?: string }> {
    const res = await fetch(`${this.baseUrl}/api/projects`);
    return res.json();
  }

  async analyzeProject(path: string, exclusions: string[] = []): Promise<AetherGraph> {
    const res = await fetch(`${this.baseUrl}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, exclusions }),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status === 'error') {
      throw new Error(data?.message || `Erreur analyse HTTP ${res.status}`);
    }
    return data;
  }

  async getTasks(): Promise<TaskItem[]> {
    const res = await fetch(`${this.baseUrl}/api/tasks`);
    const data = await res.json();
    if (Array.isArray(data)) return data;
    return Array.isArray(data?.tasks) ? data.tasks : [];
  }

  async createTask(payload: {
    title: string;
    kind?: string;
    target_symbol?: string;
    target_file?: string;
    author?: string;
    agent_id?: string;
    agent_name?: string;
    color?: string;
    priority?: string;
    initial_readme?: string;
  }): Promise<{ status: string; task?: TaskItem; message?: string }> {
    const res = await fetch(`${this.baseUrl}/api/tasks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return res.json();
  }

  async updateTask(
    taskId: string,
    status: string,
    progress: number,
    progressNote: string,
    fullReadme?: string,
    extra?: {
      title?: string;
      target_symbol?: string;
      target_file?: string;
      priority?: string;
      agent_id?: string;
      agent_name?: string;
      color?: string;
    }
  ): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/tasks/update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        task_id: taskId,
        status,
        progress,
        progress_note: progressNote,
        full_readme: fullReadme,
        ...extra,
      }),
    });
    return res.json();
  }

  async sendChatMessage(
    text: string,
    sender: 'user' | 'ai' = 'user',
    targetSymbol?: string,
    agent?: { agent_id?: string; agent_name?: string; recipient?: string; color?: string }
  ): Promise<{ status: string; message?: any }> {
    const res = await fetch(`${this.baseUrl}/api/ai/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text,
        sender,
        target_symbol: targetSymbol,
        agent_id: agent?.agent_id,
        agent_name: agent?.agent_name,
        recipient: agent?.recipient,
        color: agent?.color,
      }),
    });
    return res.json();
  }

  async getChatHistory(): Promise<{ messages: any[]; agent_status: string }> {
    const res = await fetch(`${this.baseUrl}/api/ai/chat`);
    return res.json();
  }

  async clearChatHistory(): Promise<{ status: string }> {
    const res = await fetch(`${this.baseUrl}/api/ai/chat/clear`, { method: 'POST' });
    return res.json();
  }

  async getTelemetry(): Promise<{
    telemetry: {
      target: string;
      action: string;
      details: string;
      timestamp: number;
      agent_id?: string;
      agent_name?: string;
      color?: string;
    } | null;
    agents?: {
      target: string;
      action: string;
      details: string;
      timestamp: number;
      agent_id?: string;
      agent_name?: string;
      color?: string;
    }[];
    history?: {
      target: string;
      action: string;
      details: string;
      timestamp: number;
      agent_id?: string;
      agent_name?: string;
      color?: string;
    }[];
  }> {
    const res = await fetch(`${this.baseUrl}/api/ai/telemetry`);
    return res.json();
  }

  async clearTelemetry(): Promise<{ status: string }> {
    const res = await fetch(`${this.baseUrl}/api/ai/telemetry`, { method: 'DELETE' });
    return res.json();
  }

  async cancelAi(): Promise<{ status: string; message?: string }> {
    const res = await fetch(`${this.baseUrl}/api/ai/cancel`, { method: 'POST' });
    return res.json();
  }

  async newAiSession(): Promise<{ status: string; message?: string }> {
    const res = await fetch(`${this.baseUrl}/api/ai/new_session`, { method: 'POST' });
    return res.json();
  }

  async launchCli(tool: string, projectPath?: string, prompt?: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/ai/launch_cli`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool, project_path: projectPath, prompt }),
    });
    return res.json();
  }

  async teleportCamera(
    target: string,
    action?: string,
    details?: string,
    agent?: { agent_id?: string; agent_name?: string; color?: string }
  ): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/ai/telemetry`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target,
        action,
        details,
        agent_id: agent?.agent_id,
        agent_name: agent?.agent_name,
        color: agent?.color,
      }),
    });
    return res.json();
  }

  async initProject(
    path: string,
    stack: string,
    topology: 'local' | 'dissociated' = 'local'
  ): Promise<{ status: string; message: string; created_dirs: string[] }> {
    const res = await fetch(`${this.baseUrl}/api/init_project`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, stack, topology }),
    });
    return res.json();
  }

  async listDirectory(path?: string): Promise<{
    status: string;
    current_path: string;
    parent_path?: string | null;
    drives: string[];
    entries: {
      name: string;
      path: string;
      is_project: boolean;
      stack_hint?: string | null;
      is_obsidian: boolean;
    }[];
    message?: string;
  }> {
    const q = path && path.trim() ? `?path=${encodeURIComponent(path.trim())}` : '';
    const res = await fetch(`${this.baseUrl}/api/fs/list${q}`);
    const data = await res.json().catch(() => null);
    if (!res.ok || !data) {
      throw new Error(data?.message || `Erreur lecture dossier HTTP ${res.status}`);
    }
    return data;
  }

  async pickWorkspace(): Promise<{
    status: string;
    workspace?: string;
    projects?: { name: string; path: string }[];
    message?: string;
  }> {
    const res = await fetch(`${this.baseUrl}/api/dialog/pick_workspace`, { method: 'POST' });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      throw new Error(data?.message || `Erreur sélecteur workspace HTTP ${res.status}`);
    }
    return data;
  }

  async pickProject(): Promise<{ status: string; project_path?: string; graph?: AetherGraph; message?: string }> {
    const res = await fetch(`${this.baseUrl}/api/dialog/pick_project`, { method: 'POST' });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      throw new Error(data?.message || `Erreur sélecteur projet HTTP ${res.status}`);
    }
    return data;
  }

  async getSettings(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/settings`);
    return res.json();
  }

  async saveSettings(payload: {
    exclusions?: string[];
    active_cve_rules?: string[];
    ignored_cwes?: string[];
    show_alerts?: boolean;
    show_cwe_bubbles?: boolean;
    show_cwe_titles?: boolean;
    show_folder_titles?: boolean;
    show_file_titles?: boolean;
    low_memory_mode?: boolean;
    ui_settings?: any;
    rescan?: boolean;
  }): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return res.json();
  }

  async exportHtml(path?: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/export`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    });
    return res.json();
  }

  async getProjectStatus(): Promise<ProjectStatusResponse> {
    const res = await fetch(`${this.baseUrl}/api/project/status`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async switchViewMode(mode: 'code' | 'vault' | 'vault-notes' | 'ide'): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/view_mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    });
    return res.json();
  }

  async getSystemPrompt(): Promise<{ system_prompt?: string }> {
    const res = await fetch(`${this.baseUrl}/api/ai/system_prompt`);
    return res.json();
  }

  async getFileContent(path: string, raw: boolean = true): Promise<any> {
    const rawParam = raw ? '&raw=true' : '';
    const res = await fetch(`${this.baseUrl}/api/file_content?path=${encodeURIComponent(path)}${rawParam}`);
    return res.json();
  }

  async saveFile(filePath: string, content: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/save_file`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file_path: filePath, content }),
    });
    return res.json();
  }

  async getFiles(): Promise<{
    status: string;
    files: Array<{ name: string; path: string; is_dir: boolean; size: number; extension: string }>;
  }> {
    const res = await fetch(`${this.baseUrl}/api/files`);
    return res.json();
  }

  getRawFileUrl(path: string): string {
    return `${this.baseUrl}/api/raw_file?path=${encodeURIComponent(path)}`;
  }

  async surfaceScan(req: {
    target: string;
    scan_level?: number;
    check_dns?: boolean;
    check_ports?: boolean;
    check_headers?: boolean;
    check_endpoints?: boolean;
    check_web_forms?: boolean;
    check_sensitive_files?: boolean;
    custom_ports?: string;
  }): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/surface_scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    return res.json();
  }

  async getGraphVersion(): Promise<{ version: number; visual_version?: number }> {
    const res = await fetch(`${this.baseUrl}/api/graph/version`);
    return res.json();
  }

  async saveDoc(payload: {
    project_path: string;
    folder: string;
    file_name: string;
    content: string;
  }): Promise<{ status: string; saved_path: string; blake3_hash?: string; graph?: AetherGraph }> {
    const res = await fetch(`${this.baseUrl}/api/save_doc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return res.json();
  }

  async signContracts(payload: {
    project_path?: string;
    folder?: string;
  }): Promise<{ status: string; message: string; signed_count: number; blake3_hash?: string; graph?: AetherGraph }> {
    const res = await fetch(`${this.baseUrl}/api/contracts/sign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return res.json();
  }

  async updateContract(payload: {
    project_path?: string;
    folder?: string;
    file_path?: string;
    max_lines_per_file?: number;
    file_max_lines?: number;
    clear_file_override?: boolean;
    allowed_imports?: string[];
    forbidden_imports?: string[];
  }): Promise<{
    status: string;
    message: string;
    folder: string;
    blake3_hash?: string;
    effective_max_lines: number;
    graph?: AetherGraph;
  }> {
    const res = await fetch(`${this.baseUrl}/api/contracts/update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return res.json();
  }

  async deleteTask(taskId: string): Promise<{ status: string; deleted?: boolean; message?: string }> {
    const res = await fetch(`${this.baseUrl}/api/tasks/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ task_id: taskId }),
    });
    return res.json();
  }

  async createFile(payload: {
    project_path: string;
    file_path: string;
    content: string;
  }): Promise<{ status: string; file_path?: string; created_symbol?: string; message?: string; graph?: AetherGraph }> {
    const res = await fetch(`${this.baseUrl}/api/ai/create_file`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status === 'error') {
      throw new Error(data?.message || `Erreur import/création fichier HTTP ${res.status}`);
    }
    return data;
  }

  async setAiTarget(symbolId: string, actionType?: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/ai/target`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ symbol_id: symbolId, action_type: actionType }),
    });
    return res.json();
  }

  async getBountyScope(): Promise<{
    status: string;
    scope: {
      in_scope: string[];
      out_of_scope: string[];
      mode: string;
      updated_by?: string;
      rationale?: string;
      timestamp: number;
    };
    recommendations: {
      folder: string;
      status: string;
      critical_count: number;
      high_count: number;
      total_violations: number;
      entrypoints_count: number;
      score: number;
      reason: string;
    }[];
  }> {
    const res = await fetch(`${this.baseUrl}/api/bounty/scope`);
    return res.json();
  }

  async updateBountyScope(payload: {
    action?: 'set' | 'auto_recommend';
    in_scope?: string[];
    out_of_scope?: string[];
    mode?: string;
    updated_by?: string;
    rationale?: string;
  }): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/bounty/scope`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return res.json();
  }

  async getPlugins(): Promise<PluginsInventoryResponse> {
    const res = await fetch(`${this.baseUrl}/api/plugins`);
    const data = await res.json().catch(() => null);
    if (!res.ok || !data) {
      throw new Error(data?.message || `Erreur lecture plugins HTTP ${res.status}`);
    }
    return data;
  }

  async togglePlugin(relPath: string, enabled: boolean): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/plugins/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rel_path: relPath, enabled }),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status === 'error') {
      throw new Error(data?.message || `Erreur bascule plugin HTTP ${res.status}`);
    }
    return data;
  }

  async testPlugins(relPath?: string): Promise<PluginTestReportResponse> {
    const res = await fetch(`${this.baseUrl}/api/plugins/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(relPath ? { rel_path: relPath } : {}),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data) {
      throw new Error(data?.message || `Erreur tests plugins HTTP ${res.status}`);
    }
    return data;
  }

  async initCommunityPluginBundle(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/plugins/init_bundle`, {
      method: 'POST',
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status === 'error') {
      throw new Error(data?.message || `Erreur déploiement bundle HTTP ${res.status}`);
    }
    return data;
  }

  async importSemgrepPlugin(pluginName: string, yamlContent: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/plugins/import_semgrep`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plugin_name: pluginName, yaml_content: yamlContent }),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status === 'error') {
      throw new Error(data?.message || `Erreur import Semgrep HTTP ${res.status}`);
    }
    return data;
  }

  async upsertPluginRule(payload: {
    plugin_name: string;
    profile?: string;
    tags?: string[];
    plugin_description?: string;
    rule_id: string;
    cwe_id: string;
    name: string;
    category?: string;
    severity: string;
    description: string;
    remediation: string;
    file_extensions: string[];
    match_mode?: 'line_by_line' | 'whole_file';
    must_contain?: string[];
    must_not_contain?: string[];
    regex_patterns?: string[];
    forbidden_tokens?: string[];
    check_literals?: boolean;
    not_preceded_within_lines?: { patterns: string[]; lines: number } | null;
    in_path_matching?: string[];
    not_in_path_matching?: string[];
    ast_scope?: string | null;
    test_cases?: { name: string; file_name: string; code: string; should_trigger: boolean }[];
    taint_sources?: any[];
    taint_sinks?: any[];
    sanitizers?: any[];
  }): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/plugins/upsert`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status === 'error' || data?.status === 'failed') {
      const detail = Array.isArray(data?.failures) && data.failures.length > 0
        ? ` — ${data.failures.join(' | ')}`
        : '';
      throw new Error((data?.message || `Erreur sauvegarde règle HTTP ${res.status}`) + detail);
    }
    return data;
  }

  async deletePlugin(relPath: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/plugins/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rel_path: relPath }),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status === 'error') {
      throw new Error(data?.message || `Erreur suppression plugin HTTP ${res.status}`);
    }
    return data;
  }

  async getVisualPlugins(): Promise<VisualPluginsInventoryResponse> {
    const res = await fetch(`${this.baseUrl}/api/visual_plugins`);
    const data = await res.json().catch(() => null);
    if (!res.ok || !data) {
      throw new Error(data?.message || `Erreur lecture plugins visuels HTTP ${res.status}`);
    }
    return data;
  }

  async activateVisualPlugin(id: string): Promise<{ status: string; active_visual_plugin: string; visual_version: number }> {
    const res = await fetch(`${this.baseUrl}/api/visual_plugins/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status === 'error') {
      throw new Error(data?.message || `Erreur activation thème WebGL HTTP ${res.status}`);
    }
    return data;
  }

  async upsertVisualPlugin(payload: {
    id: string;
    name: string;
    version?: string;
    author?: string;
    description?: string;
    palette: VisualPluginPack['palette'];
    overlay: VisualPluginPack['overlay'];
    uniforms: Record<string, number>;
    backdrop_glsl?: string | null;
    node_sdf_glsl?: string | null;
    activate?: boolean;
  }): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/visual_plugins/upsert`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status === 'error') {
      throw new Error(data?.message || `Erreur sauvegarde plugin visuel HTTP ${res.status}`);
    }
    return data;
  }

  async deleteVisualPlugin(id: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/visual_plugins/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status === 'error') {
      throw new Error(data?.message || `Erreur suppression plugin visuel HTTP ${res.status}`);
    }
    return data;
  }
}

export const api = new AetherApiClient();
