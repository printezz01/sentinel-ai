// ═══════════════════════════════════════════════════
// Sentinel AI — Live Scan Feed
// Real-time polling with terminal log and timer
// ═══════════════════════════════════════════════════

import { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getScanStatus } from '../api/client';
import type { Severity } from '../types/api';
import { CheckCircle, AlertTriangle, ArrowRight, Loader } from 'lucide-react';
import toast from 'react-hot-toast';

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#c75050',
  high: '#d4784a',
  medium: '#c4a644',
  low: '#7a9c5e',
  info: '#8a8e7c',
};

const TOOL_DESCRIPTIONS: Record<string, string> = {
  nmap: 'Scanning ports and services',
  bandit: 'Analyzing Python source code',
  semgrep: 'Running pattern-based code analysis',
  trufflehog: 'Scanning for leaked secrets',
  nikto: 'Probing web vulnerabilities',
  'NVD lookup': 'Cross-referencing known CVEs',
  'CCTV check': 'Fingerprinting IoT cameras',
  'attack chain build': 'Building attack graph',
  embedding: 'Generating semantic embeddings',
};



export default function LiveScanPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const logRef = useRef<HTMLDivElement>(null);
  // ── Reliable 1-second timer ──────────────────────
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const { data: status } = useQuery({
    queryKey: ['scanStatus', id],
    queryFn: () => getScanStatus(id!),
    refetchInterval: (query) => {
      const s = query.state.data?.status;
      if (s === 'complete' || s === 'failed') return false;
      return 1500;
    },
    retry: 1,
    enabled: !!id,
  });

  // Start the timer on mount, stop when scan ends
  useEffect(() => {
    timerRef.current = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  // Stop the timer when scan completes or fails
  useEffect(() => {
    if (status?.status === 'complete' || status?.status === 'failed') {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    }
  }, [status?.status]);

  const logEntries = Array.from(new Map((status?.findings_so_far ?? []).map(f => [f.id, f])).values());

  // Auto-scroll terminal
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logEntries]);

  // Show toast on failure
  useEffect(() => {
    if (status?.status === 'failed') {
      const errorTitle = status?.error_info?.title;
      toast.error(errorTitle ? `${errorTitle}` : 'Scan could not be completed. Partial results may be available.');
    }
  }, [status?.status]);


  const isComplete = status?.status === 'complete';
  const isFailed = status?.status === 'failed';



  const elapsed = status?.elapsed_seconds ?? elapsedSeconds;
  const minutes = Math.floor(elapsed / 60).toString().padStart(2, '0');
  const seconds = (elapsed % 60).toString().padStart(2, '0');

  return (
    <div className="animate-fade-in h-full flex flex-col">
      {/* Header */}
      <div className="mb-6">
        <div className="text-[11px] tracking-[0.2em] uppercase text-sentinel-text-dim font-medium mb-3">
          Live Scan
        </div>
        <h1 className="text-3xl font-semibold text-[#2a2e24] mb-2">
          {isComplete ? 'Scan Complete' : isFailed ? (status?.error_info?.category === 'BLOCKED' ? 'Scan Blocked' : 'Scan Could Not Be Completed') : 'Scanning target...'}
        </h1>
      </div>

      {/* Timer & Status */}
      <div className="flex items-center gap-8 mb-6">
        {/* Timer */}
        <div className="threat-panel px-8 py-6">
          <div className="text-[10px] tracking-[0.2em] uppercase text-sentinel-text-muted mb-2">
            Elapsed
          </div>
          <div className="text-5xl font-bold text-sentinel-text font-mono tabular-nums">
            {minutes}:{seconds}
          </div>
        </div>

        {/* Current tool */}
        <div className="flex-1">
          {!isComplete && !isFailed && status?.current_tool && (
            <div className="glass-panel p-5 animate-fade-in">
              <div className="flex items-center gap-3 mb-2">
                <Loader size={16} className="text-sentinel-accent animate-spin" />
                <span className="font-mono text-sm font-semibold text-[#2a2e24]">
                  {status.current_tool}
                </span>
              </div>
              <p className="text-[13px] text-[#6b6e60]">
                {TOOL_DESCRIPTIONS[status.current_tool] ?? 'Processing...'}
              </p>
            </div>
          )}

          {isComplete && status?.tool_warnings && status.tool_warnings.some(w => w.status === 'failed') && (
            <div className="glass-panel p-5 animate-fade-in border-l-4 border-l-sev-medium">
              <div className="flex items-center gap-3 mb-2">
                <AlertTriangle size={20} className="text-sev-medium" />
                <span className="font-semibold text-[#2a2e24]">Scan Completed With Warnings</span>
              </div>
              <div className="space-y-1 mb-3">
                {status.tool_warnings.map((tw) => (
                  <div key={tw.tool} className="flex items-center gap-2 text-[13px]">
                    {tw.status === 'completed' ? (
                      <CheckCircle size={14} className="text-sev-low shrink-0" />
                    ) : tw.status === 'failed' ? (
                      <AlertTriangle size={14} className="text-sev-critical shrink-0" />
                    ) : (
                      <span className="text-sentinel-text-dim shrink-0">—</span>
                    )}
                    <span className={tw.status === 'failed' ? 'text-sev-critical' : 'text-[#4a4e40]'}>
                      {tw.tool}
                    </span>
                    {tw.status === 'completed' && tw.findings_count !== undefined && (
                      <span className="text-sentinel-text-dim">({tw.findings_count} findings)</span>
                    )}
                    {tw.status === 'failed' && tw.title && (
                      <span className="text-sentinel-text-dim">— {tw.title}</span>
                    )}
                  </div>
                ))}
              </div>
              <p className="text-[13px] text-[#6b6e60] mb-3">
                Found {logEntries.length} vulnerabilities in {minutes}:{seconds}
              </p>
              <button
                onClick={() => navigate(`/scan/${id}/dashboard`)}
                className="btn-primary"
              >
                View Dashboard
                <ArrowRight size={16} />
              </button>
            </div>
          )}

          {isComplete && (!status?.tool_warnings || !status.tool_warnings.some(w => w.status === 'failed')) && (
            <div className="glass-panel p-5 animate-fade-in border-l-4 border-l-sev-low">
              <div className="flex items-center gap-3 mb-2">
                <CheckCircle size={20} className="text-sev-low" />
                <span className="font-semibold text-[#2a2e24]">Scan Complete</span>
              </div>
              <p className="text-[13px] text-[#6b6e60] mb-3">
                Found {logEntries.length} vulnerabilities in {minutes}:{seconds}
              </p>
              <button
                onClick={() => navigate(`/scan/${id}/dashboard`)}
                className="btn-primary"
              >
                View Dashboard
                <ArrowRight size={16} />
              </button>
            </div>
          )}

          {isFailed && (
            <div className="glass-panel p-5 animate-fade-in border-l-4 border-l-sev-critical">
              <div className="flex items-center gap-3 mb-2">
                <AlertTriangle size={20} className="text-sev-critical" />
                <span className="font-semibold text-[#2a2e24]">
                  {status?.error_info?.category === 'BLOCKED'
                    ? 'Scan Blocked'
                    : 'Scan Could Not Be Completed'}
                </span>
              </div>
              {status?.error_info ? (
                <>
                  <div className="mb-2">
                    <div className="text-[11px] tracking-[0.15em] uppercase text-sentinel-text-dim mb-1">Reason</div>
                    <p className="text-[14px] font-medium text-[#2a2e24] mb-1">{status.error_info.title}</p>
                    <p className="text-[13px] text-[#6b6e60]">{status.error_info.message}</p>
                  </div>
                  <div className="mb-3">
                    <div className="text-[11px] tracking-[0.15em] uppercase text-sentinel-text-dim mb-1">What you can do</div>
                    <p className="text-[13px] text-[#6b6e60]">{status.error_info.action}</p>
                  </div>
                </>
              ) : (
                <p className="text-[13px] text-[#6b6e60] mb-3">
                  An unexpected error occurred. Partial results may be available.
                </p>
              )}
              {logEntries.length > 0 && (
                <button
                  onClick={() => navigate(`/scan/${id}/dashboard`)}
                  className="btn-primary"
                >
                  View Partial Results
                  <ArrowRight size={16} />
                </button>
              )}
            </div>
          )}
        </div>

        {/* Stats */}
        <div className="flex gap-4">
          <div className="stat-card text-center min-w-[100px]">
            <div className="text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c] mb-1">
              Findings
            </div>
            <div className="text-3xl font-bold text-[#2a2e24]">
              {logEntries.length}
            </div>
          </div>
          <div className="stat-card text-center min-w-[100px]">
            <div className="text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c] mb-1">
              Critical
            </div>
            <div className="text-3xl font-bold text-sev-critical">
              {logEntries.filter((f) => f.severity === 'critical').length}
            </div>
          </div>
        </div>
      </div>

      {/* Terminal Log */}
      <div className="flex-1 min-h-0">
        <div ref={logRef} className="terminal h-full max-h-[420px]">
          <div className="text-sentinel-accent mb-2">
            {'>'} Sentinel AI v1.0 — scan initiated for {id}
          </div>
          <div className="text-sentinel-text-dim mb-3">
            {'>'} Probing target across network, code, web, and IoT surfaces...
          </div>
          {logEntries.map((finding) => (
            <div key={finding.id} className="terminal-line flex items-start gap-2">
              <span className="text-sentinel-text-dim select-none shrink-0">
                [finding]
              </span>
              <span
                className="font-semibold shrink-0 uppercase text-[11px] min-w-[64px]"
                style={{ color: SEVERITY_COLORS[finding.severity] }}
              >
                {finding.severity}
              </span>
              <span className="text-sentinel-text">
                {finding.title}
              </span>
              {finding.cve_id && (
                <span className="text-sentinel-accent font-mono text-[11px]">
                  {finding.cve_id}
                </span>
              )}
            </div>
          ))}
          {!isComplete && !isFailed && (
            <div className="terminal-line text-sentinel-accent animate-pulse mt-1">
              {'>'} scanning...
            </div>
          )}
          {isComplete && (
            <div className="terminal-line text-sev-low mt-2">
              {'>'} Scan completed. {logEntries.length} findings across all layers.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
