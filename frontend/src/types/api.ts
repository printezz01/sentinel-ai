// ═══════════════════════════════════════════════════
// Sentinel AI — API Type Definitions
// ═══════════════════════════════════════════════════

export type TargetType = 'ip' | 'subnet' | 'url' | 'github';
export type ScanStatus = 'queued' | 'running' | 'complete' | 'failed';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Layer = 'network' | 'code' | 'web' | 'iot';

export interface ScanErrorInfo {
  error_code: string;
  title: string;
  message: string;
  action: string;
  category?: 'BLOCKED' | 'FAILED' | 'WARNING';
}

export interface ToolWarning {
  tool: string;
  status: 'completed' | 'failed' | 'skipped';
  findings_count?: number;
  error_code?: string;
  title?: string;
  message?: string;
  reason?: string;
}

export interface Finding {
  id: string;
  layer: Layer;
  severity: Severity;
  title: string;
  description: string;
  cve_id: string | null;
  gives: string;
  requires: string;
}

export interface ScanRequest {
  target: string;
  target_type: TargetType;
}

export interface ScanResponse {
  scan_id: string;
}

export interface ScanStatusResponse {
  scan_id?: string;
  status: ScanStatus;
  current_tool: string | null;
  elapsed_seconds?: number;
  findings_so_far: Pick<Finding, 'id' | 'title' | 'severity' | 'layer' | 'cve_id'>[];
  error_info?: ScanErrorInfo;
  tool_warnings?: ToolWarning[];
}

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface RiskScore {
  score: number;
  breakdown: Record<string, number>;
}

export interface OwaspCategory {
  category: string;
  findings: Finding[];
}

export interface DashboardResponse {
  status?: ScanStatus;
  severity_breakdown: SeverityBreakdown;
  findings: Finding[];
  risk_score: RiskScore | number;
  owasp_mapping: OwaspCategory[] | Record<string, string>;
}

export interface ChainNode {
  data: {
    id: string;
    label: string;
    layer: Layer;
    severity: Severity;
    gives?: string;
    requires?: string;
  };
}

export interface ChainEdge {
  data: {
    source: string;
    target: string;
    reason: string;
  };
}

export interface ChainResponse {
  nodes: ChainNode[];
  edges: ChainEdge[];
}

export interface ChatRequest {
  question: string;
}

export interface ChatResponse {
  answer: string;
  sources?: Finding[];
  context?: Finding[];
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  sources?: Finding[];
  timestamp: Date;
}
