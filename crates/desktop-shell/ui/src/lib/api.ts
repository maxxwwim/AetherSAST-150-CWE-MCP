import type { AetherGraph, TaskItem } from '../types/graph';

export class AetherApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = '') {
    this.baseUrl = baseUrl;
  }

  async getHealth(): Promise<{ status: string; engine: string }> {
    const res = await fetch(`${this.baseUrl}/api/health`);
    return res.json();
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
    return res.json();
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
    fullReadme?: string
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

  async getAiStatus(): Promise<{ status: string }> {
    const res = await fetch(`${this.baseUrl}/api/ai/status`);
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

  async pickWorkspace(): Promise<{ status: string; workspace?: string }> {
    const res = await fetch(`${this.baseUrl}/api/dialog/pick_workspace`, { method: 'POST' });
    return res.json();
  }

  async pickProject(): Promise<{ status: string; project_path?: string; graph?: AetherGraph }> {
    const res = await fetch(`${this.baseUrl}/api/dialog/pick_project`, { method: 'POST' });
    return res.json();
  }

  async getSettings(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/settings`);
    return res.json();
  }

  async saveSettings(payload: {
    exclusions: string[];
    active_cve_rules?: string[];
    ignored_cwes?: string[];
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

  async switchViewMode(mode: 'code' | 'vault'): Promise<any> {
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

  async getFileContent(path: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/file_content?path=${encodeURIComponent(path)}`);
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

  async getGraphVersion(): Promise<{ version: number }> {
    const res = await fetch(`${this.baseUrl}/api/graph/version`);
    return res.json();
  }

  async getProjectStatus(): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/project/status`);
    return res.json();
  }

  async saveDoc(payload: {
    project_path: string;
    folder: string;
    file_name: string;
    content: string;
  }): Promise<{ status: string; saved_path: string; blake3_hash?: string }> {
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
  }): Promise<{ status: string; file_path: string; created_symbol: string; graph?: AetherGraph }> {
    const res = await fetch(`${this.baseUrl}/api/ai/create_file`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return res.json();
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
}

export const api = new AetherApiClient();
