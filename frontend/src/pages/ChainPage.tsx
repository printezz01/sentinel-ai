// ═══════════════════════════════════════════════════
// Sentinel AI — Attack Chain Graph Page
// Clean hierarchical layout: connected chains flow
// left-to-right, isolated nodes listed separately
// ═══════════════════════════════════════════════════

import { useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import cytoscape from 'cytoscape';
import { getChain } from '../api/client';
import type { ChainNode, Severity, Layer } from '../types/api';
import { X, ZoomIn, ZoomOut, Maximize2, Shield } from 'lucide-react';

const LAYER_COLORS: Record<Layer, string> = {
  network: '#4a7a5e',
  code: '#5a6a4e',
  web: '#8a9c5e',
  iot: '#c75050',
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#c75050',
  high: '#d4784a',
  medium: '#c4a644',
  low: '#7a9c5e',
  info: '#8a8e7c',
};

const SEVERITY_SIZE: Record<Severity, number> = {
  critical: 44,
  high: 38,
  medium: 34,
  low: 30,
  info: 26,
};

/** Shorten a vulnerability title to fit a node label */
function shortenTitle(title: string): string {
  if (!title) return '?';
  const abbreviations: Record<string, string> = {
    'Arbitrary Code Execution via eval()': 'eval()',
    'Dynamic Code Injection via String Concatenation': 'Code Inject',
    'Missing Cross-Site Request Forgery (CSRF) Protection': 'No CSRF',
    'Exposed Cryptographic Private Key': 'Priv Key',
    'Hardcoded Password Hash (Bcrypt)': 'Hash Leak',
    'Hardcoded Password in Source Code': 'Hardcoded Pwd',
    'Hardcoded Database Connection String': 'DB String',
    'Hardcoded Credentials in Source Code': 'Cred Leak',
    'Unvalidated Open URL Redirection': 'Redirect',
    'Insecure Container Configuration (Docker)': 'Docker',
    'Insecure Session Cookie Configuration': 'Cookie',
    'OS Command Injection': 'Cmd Inject',
    'OS Command Injection (Node.js)': 'Cmd Inject',
    'Unsafe Shell Execution': 'Shell Exec',
    'Cross-Site Scripting (XSS)': 'XSS',
    'Cross-Site Scripting via Disabled Autoescaping': 'XSS',
    'Cross-Site Scripting via Unescaped Template Output': 'XSS',
    'Cross-Site Scripting via EJS Unescaped Output': 'XSS',
    'DOM-Based Cross-Site Scripting (innerHTML)': 'XSS',
    'DOM-Based Cross-Site Scripting (document.write)': 'XSS',
    'Server-Side XSS via Unescaped Template Output': 'XSS',
    'Database Injection Vulnerability': 'SQLi',
    'NoSQL Injection': 'NoSQLi',
    'NoSQL Operator Injection Pattern': 'NoSQL Op',
    'Server-Side Request Forgery (SSRF)': 'SSRF',
    'Server-Side Template Injection (SSTI)': 'SSTI',
    'Path Traversal / Local File Inclusion': 'Path Trav',
    'Weak Cryptographic Hash (MD5)': 'MD5',
    'Weak Cryptographic Hash (SHA1)': 'SHA1',
    'Insecure Deserialization': 'Deserial',
    'Debug Mode Enabled in Production': 'Debug',
    'Regular Expression Denial of Service (ReDoS)': 'ReDoS',
    'Information Disclosure via Server Header': 'Header',
    'Insecure Cleartext Transport (HTTP)': 'HTTP',
  };
  if (abbreviations[title]) return abbreviations[title];
  const words = title.replace(/[()]/g, '').split(/\s+/);
  return words.slice(0, 2).join(' ');
}

// Fix encoding issues
const fixEncoding = (text: string | undefined): string => {
  if (!text) return '';
  return text
    .replace(/â€"/g, '—').replace(/â€˜/g, "'")
    .replace(/â€™/g, "'").replace(/â€œ/g, '"').replace(/â€\u009d/g, '"');
};

interface IsolatedFinding {
  id: string;
  label: string;
  severity: Severity;
  layer: Layer;
  gives?: string;
  requires?: string;
}

export default function ChainPage() {
  const { id } = useParams<{ id: string }>();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<(ChainNode['data'] & { shortLabel: string; fullLabel: string }) | null>(null);
  const [isolatedNodes, setIsolatedNodes] = useState<IsolatedFinding[]>([]);

  const { data: chainData } = useQuery({
    queryKey: ['chain', id],
    queryFn: () => getChain(id!),
    retry: 1,
    enabled: !!id,
  });

  useEffect(() => {
    if (!containerRef.current || !chainData) return;

    // Identify connected vs isolated nodes
    const edgeNodeIds = new Set<string>();
    chainData.edges.forEach(e => {
      edgeNodeIds.add(e.data.source);
      edgeNodeIds.add(e.data.target);
    });

    const connectedNodes = chainData.nodes.filter(n => edgeNodeIds.has(n.data.id));
    const isolated = chainData.nodes
      .filter(n => !edgeNodeIds.has(n.data.id))
      .map(n => ({
        id: n.data.id,
        label: n.data.label || '',
        severity: (n.data.severity || 'medium') as Severity,
        layer: (n.data.layer || 'code') as Layer,
        gives: n.data.gives,
        requires: n.data.requires,
      }));

    setIsolatedNodes(isolated);

    // Build cytoscape only with connected nodes
    const processedNodes = connectedNodes.map((n) => ({
      group: 'nodes' as const,
      data: {
        ...n.data,
        shortLabel: shortenTitle(n.data.label || ''),
        fullLabel: n.data.label,
      },
    }));

    const processedEdges = chainData.edges.map(e => ({
      group: 'edges' as const,
      data: e.data,
    }));

    if (processedNodes.length === 0) {
      // No connected nodes, nothing to graph
      return;
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...processedNodes, ...processedEdges],
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(shortLabel)',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'font-size': '11px',
            'font-family': 'Inter, sans-serif',
            'font-weight': 600,
            color: '#3a3e34',
            'text-margin-y': 8,
            'text-max-width': '80px',
            'text-wrap': 'wrap',
            'background-color': function (ele: cytoscape.NodeSingular) {
              const layer = ele.data('layer') as Layer;
              return LAYER_COLORS[layer] || '#8a8e7c';
            },
            width: function (ele: cytoscape.NodeSingular) {
              const severity = ele.data('severity') as Severity;
              return SEVERITY_SIZE[severity] || 34;
            },
            height: function (ele: cytoscape.NodeSingular) {
              const severity = ele.data('severity') as Severity;
              return SEVERITY_SIZE[severity] || 34;
            },
            'border-width': 3,
            'border-color': function (ele: cytoscape.NodeSingular) {
              const severity = ele.data('severity') as Severity;
              return SEVERITY_COLORS[severity] || '#8a8e7c';
            },
            'border-opacity': 0.8,
            'overlay-opacity': 0,
            'transition-property': 'background-color, width, height',
            'transition-duration': 200,
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 4,
            'border-color': '#2a2e24',
            'border-opacity': 1,
          } as cytoscape.Css.Node,
        },
        {
          selector: 'edge',
          style: {
            width: 1.5,
            'line-color': 'rgba(90, 106, 78, 0.3)',
            'target-arrow-color': 'rgba(90, 106, 78, 0.5)',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.7,
            'curve-style': 'straight',
            'overlay-opacity': 0,
          } as cytoscape.Css.Edge,
        },
        {
          selector: 'edge:selected',
          style: {
            width: 2.5,
            'line-color': '#c75050',
            'target-arrow-color': '#c75050',
          } as cytoscape.Css.Edge,
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        spacingFactor: 1.5,
        padding: 60,
        avoidOverlap: true,
        nodeDimensionsIncludeLabels: true,
        animate: true,
        animationDuration: 800,
      },
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.25,
    });

    cy.on('tap', 'node', (evt) => {
      setSelectedNode(evt.target.data());
    });
    cy.on('tap', (evt) => {
      if (evt.target === cy) setSelectedNode(null);
    });

    cyRef.current = cy;
    return () => { cy.destroy(); };
  }, [chainData]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.3);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() / 1.3);
  const handleFit = () => cyRef.current?.fit(undefined, 40);

  const connectedCount = chainData
    ? chainData.nodes.length - isolatedNodes.length
    : 0;

  return (
    <div className="h-full flex flex-col animate-fade-in gap-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="glass-panel p-5 max-w-lg">
          <div className="text-[10px] tracking-[0.2em] uppercase text-[#8a8e7c] mb-2">
            Attack Path Visualizer
          </div>
          <h2 className="text-xl font-semibold text-[#2a2e24] mb-2">
            A quiet map of how an attacker would connect the dots.
          </h2>
          <p className="text-[13px] text-[#6b6e60]">
            Click any node to inspect its severity and attack capabilities.
            {connectedCount > 0 && (
              <span className="ml-1 font-medium text-sev-critical">
                {connectedCount} chained vulnerabilities detected.
              </span>
            )}
          </p>
        </div>

        {/* Legend */}
        <div className="glass-panel p-4 text-xs text-[#6b6e60]">
          <div className="font-medium text-[#3a3e34] mb-2">Severity</div>
          <div className="flex gap-4">
            {(['critical', 'high', 'medium', 'low'] as Severity[]).map(sev => (
              <div key={sev} className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full" style={{ background: SEVERITY_COLORS[sev] }} />
                <span className="capitalize">{sev}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Graph — connected nodes only */}
      <div className="flex-1 relative glass-panel overflow-hidden" style={{ minHeight: '400px' }}>
        <div ref={containerRef} className="cytoscape-container w-full h-full min-h-[400px]" />

        {/* Zoom controls */}
        <div className="absolute bottom-4 right-4 flex flex-col gap-2">
          <button onClick={handleZoomIn} className="w-9 h-9 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors">
            <ZoomIn size={16} className="text-[#4a4e40]" />
          </button>
          <button onClick={handleZoomOut} className="w-9 h-9 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors">
            <ZoomOut size={16} className="text-[#4a4e40]" />
          </button>
          <button onClick={handleFit} className="w-9 h-9 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors">
            <Maximize2 size={16} className="text-[#4a4e40]" />
          </button>
        </div>

        {/* Selected node panel */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 glass-panel p-5 animate-slide-right shadow-lg">
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full" style={{ background: SEVERITY_COLORS[selectedNode.severity as Severity] || '#8a8e7c' }} />
                <span className={`text-[10px] tracking-wider uppercase font-semibold badge-${selectedNode.severity}`}>
                  {selectedNode.severity}
                </span>
                <span className="text-[10px] text-[#8a8e7c] uppercase tracking-wider">
                  {selectedNode.layer}
                </span>
              </div>
              <button onClick={() => setSelectedNode(null)} className="text-[#8a8e7c] hover:text-[#4a4e40] transition-colors">
                <X size={16} />
              </button>
            </div>
            <h3 className="font-semibold text-[#2a2e24] mb-3 text-sm leading-relaxed">
              {fixEncoding(selectedNode.fullLabel || selectedNode.label)}
            </h3>
            {selectedNode.gives && (
              <div className="mb-3">
                <span className="text-[10px] uppercase tracking-wider text-[#8a8e7c]">Gives attacker</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.gives.split(',').map((g: string) => (
                    <span key={g.trim()} className="text-[11px] font-mono bg-sev-critical/10 text-sev-critical px-2 py-0.5 rounded">
                      {g.trim()}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {selectedNode.requires && (
              <div>
                <span className="text-[10px] uppercase tracking-wider text-[#8a8e7c]">Requires</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.requires.split(',').map((r: string) => (
                    <span key={r.trim()} className="text-[11px] font-mono bg-sev-medium/10 text-sev-medium px-2 py-0.5 rounded">
                      {r.trim()}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Isolated findings — shown as a clean list below the graph */}
      {isolatedNodes.length > 0 && (
        <div className="glass-panel p-5">
          <div className="flex items-center gap-2 mb-3">
            <Shield size={14} className="text-[#8a8e7c]" />
            <span className="text-[10px] tracking-[0.2em] uppercase text-[#8a8e7c] font-medium">
              Standalone Findings — not part of any attack chain
            </span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
            {isolatedNodes.map(node => (
              <div
                key={node.id}
                className="flex items-center gap-2.5 p-2.5 rounded-lg hover:bg-black/3 transition-colors"
              >
                <div
                  className="w-3 h-3 rounded-full shrink-0"
                  style={{ background: SEVERITY_COLORS[node.severity] || '#8a8e7c' }}
                />
                <div className="min-w-0">
                  <div className="text-xs font-medium text-[#3a3e34] truncate">
                    {fixEncoding(node.label)}
                  </div>
                  <div className="text-[10px] text-[#8a8e7c] uppercase">{node.severity}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
