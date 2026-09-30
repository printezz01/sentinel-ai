// ═══════════════════════════════════════════════════
// Sentinel AI — Attack Paths Page (React Flow Edition)
// Perfected layout to match the mockup exactly.
// ═══════════════════════════════════════════════════

import { useMemo, useState, useCallback, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
  MarkerType,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from 'dagre';
import { getChain } from '../api/client';
import type { Severity, ChainResponse } from '../types/api';
import {
  X,
  Shield,
  Code,
  Terminal,
  Globe,
  Database,
  Lock,
  Bug,
  Eye,
  Server,
  Key,
  FileWarning,
  Hash,
} from 'lucide-react';

// ── Helpers & Styling ──

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

const STAGES = [
  { key: 'initial_access', label: 'Initial Access', subtitle: 'Gain foothold' },
  { key: 'execution', label: 'Execution', subtitle: 'Run code' },
  { key: 'lateral', label: 'Lateral Movement', subtitle: 'Move through system' },
  { key: 'impact', label: 'Data Access', subtitle: 'Access sensitive data' },
];

function classifyStage(gives: string, requires: string, severity: string): string {
  const g = (gives || '').toLowerCase();
  const r = (requires || '').toLowerCase();
  if (!r || r === 'internet_access' || r === 'web_access' || r === 'code_read_access') {
    if (g.includes('command_execution') || g.includes('app_data_write')) return 'execution';
    return 'initial_access';
  }
  if (g.includes('database') || g.includes('file_read') || g.includes('app_data_read')) return 'impact';
  if (g.includes('lateral') || g.includes('server_access')) return 'lateral';
  if (g.includes('command_execution')) return 'execution';
  if (g.includes('privilege_escalation')) return 'lateral';
  if (severity === 'critical') return 'execution';
  return 'initial_access';
}

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

const fixEncoding = (text: string | undefined): string => {
  if (!text) return '';
  return text.replace(/â€"/g, '—').replace(/â€˜/g, "'").replace(/â€™/g, "'").replace(/â€œ/g, '"').replace(/â€\u009d/g, '"');
};

// ── React Flow Custom Node ──

const AttackNode = ({ data }: { data: any }) => {
  const Icon = getIcon(data.fullLabel);
  const color = SEV_COLORS[data.severity as Severity] || '#8a8e7c';
  const bg = SEV_BG[data.severity as Severity] || 'rgba(138,142,124,0.12)';

  return (
    <div
      className={`relative flex flex-col items-center p-3 rounded-2xl bg-white shadow-sm transition-all duration-300 ${
        data.selected ? 'ring-2 ring-[#2a2e24]' : ''
      }`}
      style={{
        border: data.inPrimaryPath ? `2px solid ${color}` : '1px solid #e8e4d8',
        boxShadow: data.inPrimaryPath ? `0 0 20px ${bg}` : '0 2px 10px rgba(0,0,0,0.03)',
      }}
    >
      <Handle type="target" position={Position.Left} className="w-2 h-2 opacity-0" />
      
      <div
        className="w-14 h-14 rounded-full flex items-center justify-center mb-2 z-10 relative"
        style={{ background: color }}
      >
        <Icon size={24} className="text-white drop-shadow-sm" />
        
        {/* Glow effect for primary path */}
        {data.inPrimaryPath && (
          <div 
            className="absolute inset-0 rounded-full animate-pulse" 
            style={{ boxShadow: `0 0 15px ${color}`, opacity: 0.5 }}
          />
        )}
      </div>
      
      <div className="text-xs font-bold text-[#2a2e24] text-center mb-1 max-w-[120px] leading-tight">
        {data.label}
      </div>
      
      <div
        className="text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full"
        style={{ color: color, background: bg }}
      >
        {data.severity}
      </div>

      <Handle type="source" position={Position.Right} className="w-2 h-2 opacity-0" />
    </div>
  );
};

const nodeTypes = { attackNode: AttackNode };

// ── Dagre Layout Algorithm ──

const dagreGraph = new dagre.graphlib.Graph();
dagreGraph.setDefaultEdgeLabel(() => ({}));

const getLayoutedElements = (nodes: Node[], edges: Edge[], direction = 'LR') => {
  const isHorizontal = direction === 'LR';
  dagreGraph.setGraph({ rankdir: direction, nodesep: 60, ranksep: 200 });

  nodes.forEach((node) => {
    // Exact dimensions of our custom node roughly
    dagreGraph.setNode(node.id, { width: 140, height: 140 });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const newNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    const newNode = { ...node };

    // We are shifting the dagre node position (anchor=center center) to the top left
    newNode.position = {
      x: nodeWithPosition.x - 70,
      y: nodeWithPosition.y - 70,
    };

    return newNode;
  });

  return { nodes: newNodes, edges };
};


// ── Main Page Component ──

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

export default function ChainPage() {
  const { id } = useParams<{ id: string }>();
  const [viewMode, setViewMode] = useState<'top-path' | 'full-graph'>('full-graph');
  const [selectedNodeData, setSelectedNodeData] = useState<ProcessedNode | null>(null);

  // React Flow state
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  const { data: chainData } = useQuery<ChainResponse>({
    queryKey: ['chain', id],
    queryFn: () => getChain(id!),
    retry: 1,
    enabled: !!id,
  });

  const { connectedNodes, isolatedNodes, primaryPath, primaryEdges, processedNodeMap } = useMemo(() => {
    if (!chainData) return { connectedNodes: [] as ProcessedNode[], isolatedNodes: [] as ProcessedNode[], primaryPath: [] as string[], primaryEdges: new Set<string>(), processedNodeMap: new Map<string, ProcessedNode>() };

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

    const adj = new Map<string, string[]>();
    chainData.edges.forEach(e => {
      if (!adj.has(e.data.source)) adj.set(e.data.source, []);
      adj.get(e.data.source)!.push(e.data.target);
    });

    const hasIncoming = new Set<string>();
    chainData.edges.forEach(e => hasIncoming.add(e.data.target));
    const roots = [...edgeNodeIds].filter(nodeId => !hasIncoming.has(nodeId));

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
      const score = path.reduce((s, nodeId) => s + (sevWeight[nodeMap.get(nodeId)?.severity || 'info'] || 0), 0);
      if (score > globalBestScore || (score === globalBestScore && path.length > globalBestPath.length)) {
        globalBestScore = score;
        globalBestPath = path;
      }
    }

    const primarySet = new Set(globalBestPath);
    primarySet.forEach(nodeId => {
      const n = nodeMap.get(nodeId);
      if (n) n.inPrimaryPath = true;
    });

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
      processedNodeMap: nodeMap,
    };
  }, [chainData]);

  // Convert to React Flow nodes/edges
  useEffect(() => {
    if (!chainData || connectedNodes.length === 0) return;

    let rfNodes: Node[] = [];
    let rfEdges: Edge[] = [];

    if (viewMode === 'full-graph') {
      rfNodes = connectedNodes.map(n => ({
        id: n.id,
        type: 'attackNode',
        position: { x: 0, y: 0 }, // computed by dagre below
        data: {
          label: n.shortLabel,
          fullLabel: n.label,
          severity: n.severity,
          inPrimaryPath: n.inPrimaryPath,
          selected: selectedNodeData?.id === n.id,
        },
      }));

      rfEdges = (chainData.edges || [])
        .filter(e => connectedNodes.some(n => n.id === e.data.source) && connectedNodes.some(n => n.id === e.data.target))
        .map(e => {
          const isPrimary = primaryEdges.has(`${e.data.source}->${e.data.target}`);
          return {
            id: `${e.data.source}-${e.data.target}`,
            source: e.data.source,
            target: e.data.target,
            type: 'bezier', // smooth curve
            animated: isPrimary,
            style: {
              stroke: isPrimary ? '#c75050' : 'rgba(160,160,148,0.4)',
              strokeWidth: isPrimary ? 3 : 1.5,
            },
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: isPrimary ? '#c75050' : 'rgba(160,160,148,0.4)',
              width: 20,
              height: 20,
            },
          };
        });

      const layouted = getLayoutedElements(rfNodes, rfEdges, 'LR');
      setNodes(layouted.nodes);
      setEdges(layouted.edges);

    } else {
      // Top path view - manual layout
      const primaryNodesList = primaryPath.map(id => processedNodeMap.get(id)).filter(Boolean) as ProcessedNode[];
      
      rfNodes = primaryNodesList.map((n, i) => ({
        id: n.id,
        type: 'attackNode',
        position: { x: i * 300, y: 150 },
        data: {
          label: n.shortLabel,
          fullLabel: n.label,
          severity: n.severity,
          inPrimaryPath: true,
          selected: selectedNodeData?.id === n.id,
        },
      }));

      rfEdges = [];
      for (let i = 0; i < primaryNodesList.length - 1; i++) {
        rfEdges.push({
          id: `${primaryNodesList[i].id}-${primaryNodesList[i+1].id}`,
          source: primaryNodesList[i].id,
          target: primaryNodesList[i+1].id,
          type: 'straight',
          animated: true,
          style: { stroke: '#c75050', strokeWidth: 3 },
          markerEnd: { type: MarkerType.ArrowClosed, color: '#c75050' },
        });
      }

      setNodes(rfNodes);
      setEdges(rfEdges);
    }
  }, [chainData, viewMode, connectedNodes, primaryPath, primaryEdges, processedNodeMap]);

  // Sync selection highlight
  useEffect(() => {
    setNodes(nds => nds.map(n => ({
      ...n,
      data: { ...n.data, selected: n.id === selectedNodeData?.id }
    })));
  }, [selectedNodeData, setNodes]);


  const onNodeClick = useCallback((_: any, node: Node) => {
    const pn = processedNodeMap.get(node.id);
    if (pn) setSelectedNodeData(pn);
  }, [processedNodeMap]);

  const onPaneClick = useCallback(() => {
    setSelectedNodeData(null);
  }, []);

  return (
    <div className="h-full flex flex-col animate-fade-in gap-4 overflow-hidden relative pb-4">
      {/* ── Header ── */}
      <div className="flex items-start justify-between shrink-0">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-10 h-10 bg-[#e0efd8] text-[#5a8a4e] rounded-xl flex items-center justify-center">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="18" cy="5" r="3"></circle>
                <circle cx="6" cy="12" r="3"></circle>
                <circle cx="18" cy="19" r="3"></circle>
                <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line>
                <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>
              </svg>
            </div>
            <h1 className="text-2xl font-bold text-[#2a2e24]">Attack Paths</h1>
          </div>
          <p className="text-[13px] text-[#6b6e60] mt-2">
            Correlated findings and potential attacker movement discovered in this scan.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => { setViewMode('top-path'); setSelectedNodeData(null); }}
            className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-semibold transition-colors ${
              viewMode === 'top-path'
                ? 'bg-[#2a2e24] text-white'
                : 'bg-white border border-[#d8d4c8] text-[#4a4e40] hover:bg-[#f8f6f0]'
            }`}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 20V10"/><path d="M18 20V4"/><path d="M6 20v-4"/></svg>
            Top Attack Path
          </button>
          <button
            onClick={() => { setViewMode('full-graph'); setSelectedNodeData(null); }}
            className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-semibold transition-colors ${
              viewMode === 'full-graph'
                ? 'bg-[#2a2e24] text-white'
                : 'bg-white border border-[#d8d4c8] text-[#4a4e40] hover:bg-[#f8f6f0]'
            }`}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
            Full Graph View
          </button>
        </div>
      </div>

      {/* ── Main Canvas Area ── */}
      <div className="flex-1 relative rounded-2xl border border-[#d8d4c8] bg-[#fdfdfc] overflow-hidden flex flex-col">
        
        {/* Stage Columns Background (Full Graph View Only) */}
        {viewMode === 'full-graph' && (
          <div className="absolute inset-0 z-0 flex pointer-events-none opacity-50">
            {STAGES.map((stage, i) => (
              <div 
                key={stage.key} 
                className={`flex-1 h-full ${i < STAGES.length - 1 ? 'border-r border-dashed border-[#d8d4c8]' : ''}`}
              >
                <div className="pt-6 pb-2 text-center">
                  <div className="text-sm font-bold text-[#2a2e24]">{stage.label}</div>
                  <div className="text-[11px] text-[#8a8e7c]">{stage.subtitle}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* React Flow Canvas */}
        <div className="flex-1 w-full h-full z-10">
          {nodes.length > 0 ? (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={onNodeClick}
              onPaneClick={onPaneClick}
              fitView
              fitViewOptions={{ padding: 0.2 }}
              minZoom={0.1}
              maxZoom={1.5}
              proOptions={{ hideAttribution: true }}
            >
              <Background color="#e8e4d8" gap={20} size={1} />
              <Controls className="bg-white border-[#d8d4c8] shadow-sm" showInteractive={false} />
            </ReactFlow>
          ) : (
            <div className="w-full h-full flex flex-col items-center justify-center text-[#8a8e7c]">
              <Shield size={48} className="opacity-20 mb-4" />
              <p>No active attack paths found.</p>
            </div>
          )}
        </div>

        {/* Selected Node Details Panel overlay */}
        {selectedNodeData && (
          <div className="absolute top-4 right-4 w-[340px] bg-white/95 backdrop-blur-md rounded-2xl border-l-4 shadow-xl p-6 z-50 animate-slide-right"
               style={{ borderLeftColor: SEV_COLORS[selectedNodeData.severity] }}>
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-full flex items-center justify-center shrink-0 shadow-inner" style={{ background: SEV_COLORS[selectedNodeData.severity] }}>
                  {(() => { const Icon = getIcon(selectedNodeData.label); return <Icon size={22} className="text-white" />; })()}
                </div>
                <div>
                  <h3 className="font-bold text-[#2a2e24] text-base leading-tight">{fixEncoding(selectedNodeData.label)}</h3>
                  <div className="flex items-center gap-2 mt-1.5">
                    <span className="text-[10px] font-extrabold uppercase px-2 py-0.5 rounded text-white" style={{ background: SEV_COLORS[selectedNodeData.severity] }}>
                      {selectedNodeData.severity}
                    </span>
                    <span className="text-[10px] text-[#8a8e7c] uppercase font-bold tracking-wider">{selectedNodeData.layer}</span>
                  </div>
                </div>
              </div>
              <button onClick={() => setSelectedNodeData(null)} className="text-[#8a8e7c] hover:text-[#2a2e24] transition-colors p-1 bg-[#f4f2ea] rounded-full">
                <X size={16} />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 mt-6 pt-4 border-t border-[#e8e4d8]">
              {selectedNodeData.gives && (
                <div>
                  <span className="text-[9px] uppercase tracking-widest text-[#8a8e7c] font-bold">Gives attacker</span>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {selectedNodeData.gives.split(',').map(g => (
                      <span key={g.trim()} className="text-[11px] font-mono font-medium px-2 py-1 rounded-md" style={{ color: SEV_COLORS.critical, background: SEV_BG.critical }}>
                        {g.trim()}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {selectedNodeData.requires && (
                <div>
                  <span className="text-[9px] uppercase tracking-widest text-[#8a8e7c] font-bold">Requires</span>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {selectedNodeData.requires.split(',').map(r => (
                      <span key={r.trim()} className="text-[11px] font-mono font-medium px-2 py-1 rounded-md" style={{ color: SEV_COLORS.medium, background: SEV_BG.medium }}>
                        {r.trim()}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Isolated Findings Area ── */}
      {isolatedNodes.length > 0 && (
        <div className="glass-panel p-5 mt-2 shrink-0">
          <div className="flex items-center gap-2 mb-4">
            <Lock size={16} className="text-[#8a8e7c]" />
            <span className="text-[11px] tracking-[0.1em] uppercase text-[#6b6e60] font-bold">
              Other findings not in active path (Isolated findings)
            </span>
          </div>
          <div className="flex flex-wrap gap-4">
            {isolatedNodes.map(node => {
              const Icon = getIcon(node.label);
              return (
                <button
                  key={node.id}
                  onClick={() => setSelectedNodeData(node)}
                  className="flex flex-col items-center gap-2 px-5 py-4 rounded-xl bg-white hover:shadow-md transition-all cursor-pointer border border-[#e8e4d8] min-w-[140px] shadow-sm"
                >
                  <div className="w-10 h-10 rounded-full flex items-center justify-center bg-[#f4f2ea] shadow-inner mb-1 text-[#6b6e60]">
                    <Icon size={20} />
                  </div>
                  <div className="text-[12px] font-bold text-[#2a2e24] text-center leading-tight">
                    {node.shortLabel}
                  </div>
                  <span className="text-[9px] font-extrabold uppercase px-2 py-0.5 rounded-full mt-1" style={{ color: SEV_COLORS[node.severity], background: SEV_BG[node.severity] }}>
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
