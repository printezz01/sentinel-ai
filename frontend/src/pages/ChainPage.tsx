// ═══════════════════════════════════════════════════
// Sentinel AI — Attack Paths Page
// Two views: Top Attack Path (linear) + Full Graph (hierarchical)
// Isolated findings separated below the graph
// ═══════════════════════════════════════════════════

import { useEffect, useRef, useState, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import cytoscape from 'cytoscape';
import { getChain } from '../api/client';
import type { Severity, ChainResponse, ChainEdge } from '../types/api';
import { X, ZoomIn, ZoomOut, Maximize2, Shield, Code, Terminal, Globe, Database, Lock, Bug, Eye, Server, Key, FileWarning, Hash } from 'lucide-react';

// ── Color system ──

const SEV_COLORS: Record<Severity, string> = {
  critical: '#c75050',
  high: '#d4784a',
  medium: '#c4a644',
  low: '#7a9c5e',
  info: '#8a8e7c',
};

const SEV_BG: Record<Severity, string> = {
  critical: 'rgba(199,80,80,0.12)',
  high: 'rgba(212,120,74,0.12)',
  medium: 'rgba(196,166,68,0.12)',
  low: 'rgba(122,156,94,0.12)',
  info: 'rgba(138,142,124,0.12)',
};

// ── Stage classification ──

interface Stage {
  key: string;
  label: string;
  subtitle: string;
}

const STAGES: Stage[] = [
  { key: 'initial_access', label: 'Initial Access', subtitle: 'Gain foothold' },
  { key: 'execution', label: 'Execution', subtitle: 'Run code' },
  { key: 'lateral', label: 'Lateral Movement', subtitle: 'Move through system' },
  { key: 'impact', label: 'Data Access', subtitle: 'Access sensitive data' },
];

/** Classify a finding into an attack stage based on its gives/requires */
function classifyStage(gives: string, requires: string, severity: string): string {
  const g = (gives || '').toLowerCase();
  const r = (requires || '').toLowerCase();

  // If it requires nothing or internet_access → initial access
  if (!r || r === 'internet_access' || r === 'web_access' || r === 'code_read_access') {
    if (g.includes('command_execution') || g.includes('app_data_write')) return 'execution';
    return 'initial_access';
  }
  // If it gives database or file access → impact
  if (g.includes('database') || g.includes('file_read') || g.includes('app_data_read')) return 'impact';
  // If it gives lateral movement or server access → lateral
  if (g.includes('lateral') || g.includes('server_access')) return 'lateral';
  // If it gives command execution → execution
  if (g.includes('command_execution')) return 'execution';
  // If it gives privilege escalation → lateral
  if (g.includes('privilege_escalation')) return 'lateral';
  // Default by severity
  if (severity === 'critical') return 'execution';
  return 'initial_access';
}

/** Shorten a vulnerability title */
function shortenTitle(title: string): string {
  if (!title) return '?';
  const map: Record<string, string> = {
    'Arbitrary Code Execution via eval()': 'eval() Exec',
    'Dynamic Code Injection via String Concatenation': 'Code Injection',
    'Missing Cross-Site Request Forgery (CSRF) Protection': 'CSRF Missing',
    'Exposed Cryptographic Private Key': 'Exposed Key',
    'Hardcoded Password Hash (Bcrypt)': 'Hardcoded Hash',
    'Hardcoded Password in Source Code': 'Hardcoded Pwd',
    'Hardcoded Database Connection String': 'DB Conn String',
    'Hardcoded Credentials in Source Code': 'Cred Leak',
    'Unvalidated Open URL Redirection': 'Open Redirect',
    'Insecure Container Configuration (Docker)': 'Docker Root',
    'Insecure Session Cookie Configuration': 'Insecure Cookie',
    'Insecure Cleartext Transport (HTTP)': 'Insecure Cleartext',
    'OS Command Injection': 'Cmd Injection',
    'OS Command Injection (Node.js)': 'Cmd Injection',
    'Unsafe Shell Execution': 'Shell Exec',
    'Cross-Site Scripting (XSS)': 'XSS',
    'Cross-Site Scripting via Disabled Autoescaping': 'XSS',
    'Cross-Site Scripting via Unescaped Template Output': 'XSS',
    'Cross-Site Scripting via EJS Unescaped Output': 'XSS',
    'Database Injection Vulnerability': 'SQL Injection',
    'NoSQL Injection': 'NoSQL Injection',
    'NoSQL Operator Injection Pattern': 'NoSQL Operator',
    'Server-Side Request Forgery (SSRF)': 'SSRF',
    'Server-Side Template Injection (SSTI)': 'SSTI',
    'Path Traversal / Local File Inclusion': 'Path Traversal',
    'Weak Cryptographic Hash (MD5)': 'Weak MD5',
    'Weak Cryptographic Hash (SHA1)': 'Weak SHA1',
    'Insecure Deserialization': 'Deserialize',
    'Debug Mode Enabled in Production': 'Debug Mode',
    'Regular Expression Denial of Service (ReDoS)': 'ReDoS',
    'Information Disclosure via Server Header': 'Server Header',
  };
  return map[title] || title.split(/[(/]/).map(s => s.trim())[0].substring(0, 20);
}

/** Pick an icon for a finding title */
function getIcon(title: string): typeof Code {
  const t = title.toLowerCase();
  if (t.includes('eval') || t.includes('code injection') || t.includes('dynamic')) return Code;
  if (t.includes('command') || t.includes('shell') || t.includes('cmd')) return Terminal;
  if (t.includes('xss') || t.includes('csrf') || t.includes('cookie') || t.includes('redirect') || t.includes('cleartext')) return Globe;
  if (t.includes('sql') || t.includes('nosql') || t.includes('database') || t.includes('db conn')) return Database;
  if (t.includes('key') || t.includes('password') || t.includes('credential') || t.includes('secret') || t.includes('hash') || t.includes('bcrypt')) return Key;
  if (t.includes('docker') || t.includes('container') || t.includes('privilege')) return Server;
  if (t.includes('ssrf') || t.includes('ssti') || t.includes('deserial')) return Bug;
  if (t.includes('path') || t.includes('traversal') || t.includes('file')) return FileWarning;
  if (t.includes('debug') || t.includes('header') || t.includes('disclosure')) return Eye;
  if (t.includes('regex') || t.includes('redos')) return Hash;
  return Shield;
}

// Fix encoding
const fixEncoding = (text: string | undefined): string => {
  if (!text) return '';
  return text.replace(/â€"/g, '—').replace(/â€˜/g, "'").replace(/â€™/g, "'").replace(/â€œ/g, '"').replace(/â€\u009d/g, '"');
};

// ── Types ──

interface ProcessedNode {
  id: string;
  label: string;
  shortLabel: string;
  severity: Severity;
  layer: string;
  gives: string;
  requires: string;
  stage: string;
  isConnected: boolean;
  inPrimaryPath: boolean;
}

type ViewMode = 'top-path' | 'full-graph';

// ── Component ──

export default function ChainPage() {
  const { id } = useParams<{ id: string }>();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('top-path');
  const [selectedNode, setSelectedNode] = useState<ProcessedNode | null>(null);
  const [selectedEdgeReason, setSelectedEdgeReason] = useState<string>('');

  const { data: chainData } = useQuery<ChainResponse>({
    queryKey: ['chain', id],
    queryFn: () => getChain(id!),
    retry: 1,
    enabled: !!id,
  });

  // ── Compute primary path and classify nodes ──
  const { connectedNodes, isolatedNodes, primaryPath, primaryEdges, allEdges, processedNodeMap } = useMemo(() => {
    if (!chainData) return { connectedNodes: [] as ProcessedNode[], isolatedNodes: [] as ProcessedNode[], primaryPath: [] as string[], primaryEdges: new Set<string>(), allEdges: [] as ChainEdge[], processedNodeMap: new Map<string, ProcessedNode>() };

    const edgeNodeIds = new Set<string>();
    chainData.edges.forEach(e => {
      edgeNodeIds.add(e.data.source);
      edgeNodeIds.add(e.data.target);
    });

    const nodeMap = new Map<string, ProcessedNode>();
    chainData.nodes.forEach(n => {
      const isConn = edgeNodeIds.has(n.data.id);
      const pn: ProcessedNode = {
        id: n.data.id,
        label: n.data.label || '',
        shortLabel: shortenTitle(n.data.label || ''),
        severity: n.data.severity || 'info',
        layer: n.data.layer || 'code',
        gives: n.data.gives || '',
        requires: n.data.requires || '',
        stage: classifyStage(n.data.gives || '', n.data.requires || '', n.data.severity || 'info'),
        isConnected: isConn,
        inPrimaryPath: false,
      };
      nodeMap.set(n.data.id, pn);
    });

    // Find longest path through highest-severity nodes (primary attack path)
    // Build adjacency list
    const adj = new Map<string, string[]>();
    chainData.edges.forEach(e => {
      if (!adj.has(e.data.source)) adj.set(e.data.source, []);
      adj.get(e.data.source)!.push(e.data.target);
    });

    // Find roots (nodes with no incoming edges among connected nodes)
    const hasIncoming = new Set<string>();
    chainData.edges.forEach(e => hasIncoming.add(e.data.target));
    const roots = [...edgeNodeIds].filter(id => !hasIncoming.has(id));

    // BFS/DFS to find the longest path with highest cumulative severity
    const sevWeight: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

    function findBestPath(start: string): string[] {
      let bestPath: string[] = [];
      let bestScore = -1;

      function dfs(node: string, path: string[], score: number, visited: Set<string>) {
        if (score > bestScore || (score === bestScore && path.length > bestPath.length)) {
          bestScore = score;
          bestPath = [...path];
        }
        for (const next of (adj.get(node) || [])) {
          if (!visited.has(next)) {
            visited.add(next);
            const nextNode = nodeMap.get(next);
            dfs(next, [...path, next], score + (sevWeight[nextNode?.severity || 'info'] || 0), visited);
            visited.delete(next);
          }
        }
      }

      const startNode = nodeMap.get(start);
      dfs(start, [start], sevWeight[startNode?.severity || 'info'] || 0, new Set([start]));
      return bestPath;
    }

    let globalBestPath: string[] = [];
    let globalBestScore = -1;
    for (const root of roots.length > 0 ? roots : [...edgeNodeIds]) {
      const path = findBestPath(root);
      const score = path.reduce((s, id) => s + (sevWeight[nodeMap.get(id)?.severity || 'info'] || 0), 0);
      if (score > globalBestScore || (score === globalBestScore && path.length > globalBestPath.length)) {
        globalBestScore = score;
        globalBestPath = path;
      }
    }

    // Mark primary path nodes
    const primarySet = new Set(globalBestPath);
    primarySet.forEach(id => {
      const n = nodeMap.get(id);
      if (n) n.inPrimaryPath = true;
    });

    // Compute primary edges
    const pEdges = new Set<string>();
    for (let i = 0; i < globalBestPath.length - 1; i++) {
      pEdges.add(`${globalBestPath[i]}->${globalBestPath[i + 1]}`);
    }

    const connected = [...nodeMap.values()].filter(n => n.isConnected);
    const isolated = [...nodeMap.values()].filter(n => !n.isConnected);

    return {
      connectedNodes: connected,
      isolatedNodes: isolated,
      primaryPath: globalBestPath,
      primaryEdges: pEdges,
      allEdges: chainData.edges,
      processedNodeMap: nodeMap,
    };
  }, [chainData]);

  // ── Cytoscape graph (Full Graph View) ──
  useEffect(() => {
    if (viewMode !== 'full-graph' || !containerRef.current || !chainData || connectedNodes.length === 0) return;

    const nodes = connectedNodes.map(n => ({
      group: 'nodes' as const,
      data: { ...n, shortLabel: n.shortLabel, fullLabel: n.label },
    }));

    const edges = allEdges
      .filter(e => connectedNodes.some(n => n.id === e.data.source) && connectedNodes.some(n => n.id === e.data.target))
      .map(e => {
        const isPrimary = primaryEdges.has(`${e.data.source}->${e.data.target}`);
        return { group: 'edges' as const, data: { ...e.data, isPrimary } };
      });

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...nodes, ...edges],
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(shortLabel)',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'font-size': '10px',
            'font-family': 'Inter, sans-serif',
            'font-weight': 600,
            color: '#3a3e34',
            'text-margin-y': 8,
            'text-max-width': '90px',
            'text-wrap': 'wrap',
            'background-color': function (ele: cytoscape.NodeSingular) {
              const sev = ele.data('severity') as Severity;
              return ele.data('inPrimaryPath') ? SEV_COLORS[sev] || '#8a8e7c' : '#c8c4b8';
            },
            width: function (ele: cytoscape.NodeSingular) {
              return ele.data('inPrimaryPath') ? 44 : 32;
            },
            height: function (ele: cytoscape.NodeSingular) {
              return ele.data('inPrimaryPath') ? 44 : 32;
            },
            'border-width': function (ele: cytoscape.NodeSingular) {
              return ele.data('inPrimaryPath') ? 3 : 1;
            },
            'border-color': function (ele: cytoscape.NodeSingular) {
              return ele.data('inPrimaryPath') ? '#c75050' : '#b0ad9f';
            },
            'border-opacity': 1,
            'overlay-opacity': 0,
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node:selected',
          style: { 'border-width': 4, 'border-color': '#2a2e24' } as cytoscape.Css.Node,
        },
        {
          selector: 'edge[isPrimary]',
          style: {
            width: 3,
            'line-color': '#c75050',
            'target-arrow-color': '#c75050',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.8,
            'curve-style': 'straight',
            'overlay-opacity': 0,
          } as cytoscape.Css.Edge,
        },
        {
          selector: 'edge[!isPrimary]',
          style: {
            width: 1,
            'line-color': 'rgba(160,160,148,0.3)',
            'target-arrow-color': 'rgba(160,160,148,0.4)',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.5,
            'curve-style': 'straight',
            'overlay-opacity': 0,
          } as cytoscape.Css.Edge,
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        spacingFactor: 1.8,
        padding: 60,
        avoidOverlap: true,
        nodeDimensionsIncludeLabels: true,
        animate: true,
        animationDuration: 600,
      },
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.25,
    });

    cy.on('tap', 'node', (evt: cytoscape.EventObject) => {
      const d = evt.target.data();
      const pn = processedNodeMap.get(d.id);
      if (pn) setSelectedNode(pn);
    });

    cy.on('tap', 'edge', (evt: cytoscape.EventObject) => {
      setSelectedEdgeReason(evt.target.data().reason || '');
    });

    cy.on('tap', (evt: cytoscape.EventObject) => {
      if (evt.target === cy) {
        setSelectedNode(null);
        setSelectedEdgeReason('');
      }
    });

    cyRef.current = cy;
    return () => { cy.destroy(); };
  }, [viewMode, chainData, connectedNodes, primaryEdges, allEdges, processedNodeMap]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.3);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() / 1.3);
  const handleFit = () => cyRef.current?.fit(undefined, 40);

  // ── Render ──

  const primaryNodes = useMemo(() =>
    primaryPath.map(id => processedNodeMap.get(id)).filter(Boolean) as ProcessedNode[],
    [primaryPath, processedNodeMap]
  );

  return (
    <div className="h-full flex flex-col animate-fade-in gap-4 overflow-y-auto pb-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-[#2a2e24] mb-1">Attack Paths</h1>
          <p className="text-[13px] text-[#6b6e60]">
            Correlated findings and potential attacker movement discovered in this scan.
          </p>
        </div>

        {/* View toggle */}
        <div className="flex rounded-lg overflow-hidden border border-[#d8d4c8]">
          <button
            onClick={() => { setViewMode('top-path'); setSelectedNode(null); }}
            className={`px-4 py-2 text-xs font-medium transition-colors ${
              viewMode === 'top-path'
                ? 'bg-[#2a2e24] text-white'
                : 'bg-white text-[#4a4e40] hover:bg-[#f0ece0]'
            }`}
          >
            Top Attack Path
          </button>
          <button
            onClick={() => { setViewMode('full-graph'); setSelectedNode(null); }}
            className={`px-4 py-2 text-xs font-medium transition-colors ${
              viewMode === 'full-graph'
                ? 'bg-[#2a2e24] text-white'
                : 'bg-white text-[#4a4e40] hover:bg-[#f0ece0]'
            }`}
          >
            Full Graph View
          </button>
        </div>
      </div>

      {/* ════════ TOP ATTACK PATH VIEW ════════ */}
      {viewMode === 'top-path' && (
        <div className="glass-panel p-6">
          {primaryNodes.length === 0 ? (
            <div className="text-center py-12 text-[#8a8e7c]">
              <Shield size={32} className="mx-auto mb-3 opacity-50" />
              <p className="text-sm">No connected attack paths found in this scan.</p>
            </div>
          ) : (
            <>
              {/* Stage headers */}
              <div className="grid gap-0" style={{ gridTemplateColumns: `repeat(${primaryNodes.length}, 1fr)` }}>
                {primaryNodes.map((node, i) => {
                  const stage = STAGES.find(s => s.key === node.stage) || STAGES[0];
                  return (
                    <div key={`stage-${i}`} className="text-center pb-4 border-b border-[#e8e4d8]">
                      <div className="text-[11px] font-semibold text-[#4a4e40] uppercase tracking-wider">
                        {stage.label}
                      </div>
                      <div className="text-[10px] text-[#8a8e7c]">{stage.subtitle}</div>
                    </div>
                  );
                })}
              </div>

              {/* Primary path nodes */}
              <div className="flex items-center justify-center gap-0 py-8">
                {primaryNodes.map((node, i) => {
                  const Icon = getIcon(node.label);
                  return (
                    <div key={node.id} className="flex items-center">
                      {/* Node card */}
                      <button
                        onClick={() => setSelectedNode(node)}
                        className="flex flex-col items-center gap-2 px-6 py-4 rounded-xl transition-all hover:scale-105 cursor-pointer"
                        style={{ background: SEV_BG[node.severity] }}
                      >
                        <div
                          className="w-12 h-12 rounded-full flex items-center justify-center"
                          style={{ background: SEV_COLORS[node.severity] }}
                        >
                          <Icon size={20} className="text-white" />
                        </div>
                        <div className="text-xs font-semibold text-[#2a2e24] text-center leading-tight max-w-[100px]">
                          {node.shortLabel}
                        </div>
                        <span
                          className="text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full"
                          style={{ color: SEV_COLORS[node.severity], background: SEV_BG[node.severity] }}
                        >
                          {node.severity}
                        </span>
                      </button>

                      {/* Arrow */}
                      {i < primaryNodes.length - 1 && (
                        <div className="flex items-center mx-1">
                          <div className="w-8 h-0.5 bg-[#c75050]" />
                          <div className="w-0 h-0 border-t-[5px] border-t-transparent border-b-[5px] border-b-transparent border-l-[8px] border-l-[#c75050]" />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Secondary connected nodes */}
              {connectedNodes.filter(n => !n.inPrimaryPath).length > 0 && (
                <div className="border-t border-[#e8e4d8] pt-4 mt-2">
                  <div className="text-[10px] text-[#8a8e7c] uppercase tracking-wider mb-3 font-medium">
                    Other connected findings
                  </div>
                  <div className="flex flex-wrap gap-3">
                    {connectedNodes.filter(n => !n.inPrimaryPath).map(node => {
                      const Icon = getIcon(node.label);
                      return (
                        <button
                          key={node.id}
                          onClick={() => setSelectedNode(node)}
                          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#f8f6f0] hover:bg-[#f0ece0] transition-colors cursor-pointer border border-[#e8e4d8]"
                        >
                          <div className="w-7 h-7 rounded-full flex items-center justify-center" style={{ background: SEV_COLORS[node.severity], opacity: 0.7 }}>
                            <Icon size={14} className="text-white" />
                          </div>
                          <div className="text-left">
                            <div className="text-[11px] font-medium text-[#3a3e34]">{node.shortLabel}</div>
                            <div className="text-[9px] uppercase font-semibold" style={{ color: SEV_COLORS[node.severity] }}>
                              {node.severity}
                            </div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ════════ FULL GRAPH VIEW ════════ */}
      {viewMode === 'full-graph' && (
        <div className="flex-1 relative glass-panel overflow-hidden" style={{ minHeight: '450px' }}>
          <div ref={containerRef} className="cytoscape-container w-full h-full min-h-[450px]" />

          {/* Zoom controls */}
          <div className="absolute bottom-4 right-4 flex flex-col gap-2">
            <button onClick={handleZoomIn} className="w-8 h-8 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors rounded-lg">
              <ZoomIn size={14} className="text-[#4a4e40]" />
            </button>
            <button onClick={handleZoomOut} className="w-8 h-8 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors rounded-lg">
              <ZoomOut size={14} className="text-[#4a4e40]" />
            </button>
            <button onClick={handleFit} className="w-8 h-8 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors rounded-lg">
              <Maximize2 size={14} className="text-[#4a4e40]" />
            </button>
          </div>

          {/* Legend */}
          <div className="absolute top-4 left-4 glass-panel p-3 text-[10px] text-[#6b6e60]">
            <div className="flex items-center gap-2 mb-1">
              <div className="w-6 h-0.5 bg-[#c75050]" />
              <span>Primary attack path</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-6 h-0.5 bg-[#c8c4b8]" />
              <span>Secondary relationship</span>
            </div>
          </div>
        </div>
      )}

      {/* ════════ DETAIL PANEL ════════ */}
      {selectedNode && (
        <div className="glass-panel p-5 border-l-4" style={{ borderLeftColor: SEV_COLORS[selectedNode.severity] }}>
          <div className="flex items-start justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full flex items-center justify-center" style={{ background: SEV_COLORS[selectedNode.severity] }}>
                {(() => { const Icon = getIcon(selectedNode.label); return <Icon size={18} className="text-white" />; })()}
              </div>
              <div>
                <h3 className="font-semibold text-[#2a2e24] text-sm">{fixEncoding(selectedNode.label)}</h3>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-[10px] font-bold uppercase" style={{ color: SEV_COLORS[selectedNode.severity] }}>
                    {selectedNode.severity}
                  </span>
                  <span className="text-[10px] text-[#8a8e7c] uppercase">{selectedNode.layer}</span>
                </div>
              </div>
            </div>
            <button onClick={() => setSelectedNode(null)} className="text-[#8a8e7c] hover:text-[#4a4e40] transition-colors">
              <X size={16} />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-4">
            {selectedNode.gives && (
              <div>
                <span className="text-[10px] uppercase tracking-wider text-[#8a8e7c] font-medium">Gives attacker</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.gives.split(',').map(g => (
                    <span key={g.trim()} className="text-[11px] font-mono px-2 py-0.5 rounded" style={{ color: SEV_COLORS.critical, background: SEV_BG.critical }}>
                      {g.trim()}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {selectedNode.requires && (
              <div>
                <span className="text-[10px] uppercase tracking-wider text-[#8a8e7c] font-medium">Requires</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.requires.split(',').map(r => (
                    <span key={r.trim()} className="text-[11px] font-mono px-2 py-0.5 rounded" style={{ color: SEV_COLORS.medium, background: SEV_BG.medium }}>
                      {r.trim()}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {selectedEdgeReason && (
            <div className="mt-3 pt-3 border-t border-[#e8e4d8]">
              <span className="text-[10px] uppercase tracking-wider text-[#8a8e7c] font-medium">Relationship</span>
              <p className="text-xs text-[#4a4e40] mt-1">{fixEncoding(selectedEdgeReason)}</p>
            </div>
          )}
        </div>
      )}

      {/* ════════ ISOLATED FINDINGS ════════ */}
      {isolatedNodes.length > 0 && (
        <div className="glass-panel p-5">
          <div className="flex items-center gap-2 mb-4">
            <Lock size={14} className="text-[#8a8e7c]" />
            <span className="text-[11px] tracking-wider uppercase text-[#8a8e7c] font-medium">
              Other findings not in active path (Isolated findings)
            </span>
          </div>
          <div className="flex flex-wrap gap-3">
            {isolatedNodes.map(node => {
              const Icon = getIcon(node.label);
              return (
                <button
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  className="flex flex-col items-center gap-1.5 px-4 py-3 rounded-lg bg-[#f8f6f0] hover:bg-[#f0ece0] transition-colors cursor-pointer border border-[#e8e4d8] min-w-[100px]"
                >
                  <div className="w-9 h-9 rounded-full flex items-center justify-center bg-[#e0dcd4]">
                    <Icon size={16} className="text-[#6b6e60]" />
                  </div>
                  <div className="text-[11px] font-medium text-[#3a3e34] text-center leading-tight">
                    {node.shortLabel}
                  </div>
                  <span className="text-[9px] font-bold uppercase" style={{ color: SEV_COLORS[node.severity] }}>
                    {node.severity}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
