import { useQuery } from '@tanstack/react-query';
import { useParams, Link } from 'react-router-dom';
import { Clock, Activity, GitBranch } from 'lucide-react';
import { getScanHistory } from '../api/client';
import type { ScanHistoryResponse, ScanSummary } from '../types/api';

function formatDate(isoString: string | null) {
  if (!isoString) return 'Unknown Date';
  return new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  }).format(new Date(isoString));
}

function SummaryCard({ title, scan, isLatest }: { title: string; scan: ScanSummary; isLatest?: boolean }) {
  return (
    <Link 
      to={`/scan/${scan.id}/dashboard`}
      className={`block p-5 rounded-2xl border transition-colors hover:border-sentinel-accent/50 ${isLatest ? 'bg-[#2a3024] border-sentinel-accent/30' : 'bg-[#232820] border-[#3a4234]'}`}
    >
      <h3 className="text-sm font-semibold text-sentinel-text mb-4">{title}</h3>
      <div className="text-xs text-sentinel-text-dim mb-4">{formatDate(scan.created_at)}</div>
      
      <div className="space-y-3">
        <div className="flex justify-between items-center">
          <span className="text-sm text-sentinel-text-muted">Findings</span>
          <span className="text-sm font-mono text-sentinel-text">{scan.total_findings}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-sm text-sentinel-text-muted">Critical</span>
          <span className="text-sm font-mono text-sev-critical">{scan.critical_findings}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-sm text-sentinel-text-muted">Risk Score</span>
          <span className="text-sm font-mono text-sentinel-accent">{scan.risk_score}/100</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-sm text-sentinel-text-muted">Attack Paths</span>
          <span className="text-sm font-mono text-sentinel-text">{scan.attack_paths}</span>
        </div>
      </div>
    </Link>
  );
}

export default function ScanHistoryPage() {
  const { id } = useParams<{ id: string }>();

  const { data, isLoading, isError } = useQuery<ScanHistoryResponse>({
    queryKey: ['scanHistory', id],
    queryFn: () => getScanHistory(id!),
    enabled: !!id,
    refetchInterval: 30000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 animate-fade-in">
        <div className="text-sentinel-text-muted text-sm font-mono flex items-center gap-2">
          <span className="status-dot animate-pulse" /> Loading history...
        </div>
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="text-sev-critical text-sm text-center mt-10">
        Failed to load scan history.
      </div>
    );
  }

  return (
    <div className="animate-fade-in max-w-4xl mx-auto py-6 pb-20">
      <div className="flex items-center gap-3 mb-8">
        <Clock className="text-sentinel-text-dim" size={20} />
        <div>
          <h1 className="text-xl font-semibold text-sentinel-text tracking-tight">Scan History</h1>
          <div className="text-sm text-sentinel-text-muted mt-1">Target: <span className="font-mono">{data.target}</span></div>
        </div>
      </div>

      {!data.history_available ? (
        <div className="p-8 rounded-2xl bg-[#232820] border border-[#3a4234] text-center">
          <Activity className="mx-auto text-sentinel-text-dim mb-4" size={32} />
          <h3 className="text-lg font-medium text-sentinel-text mb-2">First scan recorded</h3>
          <p className="text-sm text-sentinel-text-muted">No previous scan is available for comparison yet.</p>
        </div>
      ) : (
        <>
          {/* Comparison Cards */}
          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr] gap-6 items-center mb-8">
            <SummaryCard title="Latest Scan" scan={data.latest_scan} isLatest />
            <div className="flex justify-center text-sentinel-text-dim font-mono text-sm py-4">
              VS
            </div>
            {data.previous_scan && (
              <SummaryCard title="Previous Scan" scan={data.previous_scan} />
            )}
          </div>

          {/* Deltas & Summary */}
          {data.comparison && (
            <div className="p-6 rounded-2xl bg-[#232820] border border-[#3a4234] mb-8">
              <div className="text-center mb-6">
                <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-sentinel-accent/10 text-sentinel-accent text-sm font-medium">
                  {data.comparison.summary}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4 mb-6">
                <div className="text-center p-4 rounded-xl bg-sev-critical/5 border border-sev-critical/10">
                  <div className="text-2xl font-mono text-sev-critical mb-1">{data.comparison.counts.new}</div>
                  <div className="text-xs text-sentinel-text-muted uppercase tracking-wider">New</div>
                </div>
                <div className="text-center p-4 rounded-xl bg-sentinel-accent/5 border border-sentinel-accent/10">
                  <div className="text-2xl font-mono text-sentinel-accent mb-1">{data.comparison.counts.resolved}</div>
                  <div className="text-xs text-sentinel-text-muted uppercase tracking-wider">Resolved</div>
                </div>
                <div className="text-center p-4 rounded-xl bg-white/5 border border-white/5">
                  <div className="text-2xl font-mono text-sentinel-text mb-1">{data.comparison.counts.unchanged}</div>
                  <div className="text-xs text-sentinel-text-muted uppercase tracking-wider">Unchanged</div>
                </div>
              </div>

              <div className="flex items-center justify-center gap-2 text-sm text-sentinel-text-muted border-t border-white/5 pt-4 mt-2">
                <GitBranch size={16} />
                <span>{data.comparison.path_summary}</span>
                <span className="text-sentinel-text-dim mx-2">•</span>
                <span className="font-mono text-xs">Prev: {data.previous_scan?.attack_paths} → Curr: {data.latest_scan.attack_paths}</span>
              </div>
            </div>
          )}

          {/* Older Scans */}
          {data.older_scans && data.older_scans.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-sentinel-text mb-4 px-2">Previous Scans</h3>
              <div className="space-y-2">
                {data.older_scans.map(scan => (
                  <Link
                    key={scan.id}
                    to={`/scan/${scan.id}/dashboard`}
                    className="flex items-center justify-between p-4 rounded-xl bg-[#232820] border border-transparent hover:border-[#3a4234] transition-colors cursor-pointer group"
                  >
                    <div className="text-sm text-sentinel-text group-hover:text-sentinel-accent transition-colors">{formatDate(scan.created_at)}</div>
                    <div className="text-sm font-mono text-sentinel-text-muted">{scan.total_findings} findings</div>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
