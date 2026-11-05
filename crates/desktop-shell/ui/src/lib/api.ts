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

  async sendChatMessage(text: string, thought?: string, targetSymbol?: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/ai/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, thought, target_symbol: targetSymbol }),
    });
    return res.json();
  }

  async getChatHistory(): Promise<any[]> {
    const res = await fetch(`${this.baseUrl}/api/ai/chat`);
    return res.json();
  }

  async teleportCamera(target: string, action?: string, details?: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}/api/ai/telemetry`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, action, details }),
    });
    return res.json();
  }
}

export const api = new AetherApiClient();
