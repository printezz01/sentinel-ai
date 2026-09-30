// ═══════════════════════════════════════════════════
// Sentinel AI — Attack Chain Graph Page
// Cytoscape.js visualization of vulnerability chains
// Clean hierarchical layout with meaningful labels
// ═══════════════════════════════════════════════════

import { useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import cytoscape from 'cytoscape';
import { getChain } from '../api/client';
import type { ChainNode, Severity, Layer } from '../types/api';
import { X, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react';

const LAYER_COLORS: Record<Layer, string> = {
  network: '#4a7a5e',
  code: '#5a6a4e',
  web: '#8a9c5e',
  iot: '#c75050',
};

const LAYER_LABELS: Record<Layer, string> = {
  network: 'network',
  code: 'code',
  web: 'web',
  iot: 'cctv',
};

// Severity drives both color ring and node size
const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#c75050',
  high: '#d4784a',
  medium: '#c4a644',
  low: '#7a9c5e',
  info: '#8a8e7c',
};

const SEVERITY_SIZE: Record<Severity, number> = {
  critical: 50,
  high: 44,
  medium: 38,
  low: 32,
  info: 28,
};

/** Shorten a vulnerability title to fit a node label (max ~18 chars) */
function shortenTitle(title: string): string {
  if (!title) return '?';
  
  const abbreviations: Record<string, string> = {
    'Arbitrary Code Execution via eval()': 'eval() Exec',
    'Dynamic Code Injection via String Concatenation': 'Code Injection',
    'Missing Cross-Site Request Forgery (CSRF) Protection': 'CSRF Missing',
    'Exposed Cryptographic Private Key': 'Exposed Key',
    'Hardcoded Password Hash (Bcrypt)': 'Hardcoded Hash',
    'Hardcoded Password in Source Code': 'Hardcoded Pwd',
    'Hardcoded Database Connection String': 'DB Conn String',
    'Hardcoded Credentials in Source Code': 'Hardcoded Creds',
    'Unvalidated Open URL Redirection': 'Open Redirect',
    'Insecure Container Configuration (Docker)': 'Docker Root',
    'Insecure Session Cookie Configuration': 'Insecure Cookie',
    'OS Command Injection': 'Cmd Injection',
    'OS Command Injection (Node.js)': 'Cmd Injection',
    'Cross-Site Scripting (XSS)': 'XSS',
    'Cross-Site Scripting via Disabled Autoescaping': 'XSS Autoescape',
    'Cross-Site Scripting via Unescaped Template Output': 'XSS Template',
    'Cross-Site Scripting via EJS Unescaped Output': 'XSS EJS',
    'DOM-Based Cross-Site Scripting (innerHTML)': 'XSS innerHTML',
    'DOM-Based Cross-Site Scripting (document.write)': 'XSS doc.write',
    'Server-Side XSS via Unescaped Template Output': 'XSS Template',
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
    'Unsafe Shell Execution': 'Shell=True',
  };

  if (abbreviations[title]) return abbreviations[title];
  
  // Generic shortener: take first 2-3 meaningful words
  const words = title.replace(/[()]/g, '').split(/\s+/);
  if (words.length <= 2) return title;
  return words.slice(0, 2).join(' ');
}

export default function ChainPage() {
  const { id } = useParams<{ id: string }>();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [selectedNode, setSelectedNode] = useState<(ChainNode['data'] & { shortLabel: string; fullLabel: string }) | null>(null);

  const { data: chainData } = useQuery({
    queryKey: ['chain', id],
    queryFn: () => getChain(id!),
    retry: 1,
    enabled: !!id,
  });

  useEffect(() => {
    if (!containerRef.current || !chainData) return;

    const processedNodes = chainData.nodes.map((n) => {
      const shortLabel = shortenTitle(n.data.label || '');
      return {
        group: 'nodes' as const,
        data: {
          ...n.data,
          shortLabel,
          fullLabel: n.data.label,
        },
      };
    });

    const processedEdges = chainData.edges.map(e => ({ group: 'edges' as const, data: e.data }));

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
            'font-size': '10px',
            'font-family': 'Inter, sans-serif',
            'font-weight': 600,
            color: '#3a3e34',
            'text-margin-y': 8,
            'text-max-width': '100px',
            'text-wrap': 'wrap',
            'background-color': function (ele: cytoscape.NodeSingular) {
              const layer = ele.data('layer') as Layer;
              return LAYER_COLORS[layer] || '#8a8e7c';
            },
            width: function (ele: cytoscape.NodeSingular) {
              const severity = ele.data('severity') as Severity;
              return SEVERITY_SIZE[severity] || 38;
            },
            height: function (ele: cytoscape.NodeSingular) {
              const severity = ele.data('severity') as Severity;
              return SEVERITY_SIZE[severity] || 38;
            },
            'border-width': 3,
            'border-color': function (ele: cytoscape.NodeSingular) {
              const severity = ele.data('severity') as Severity;
              return SEVERITY_COLORS[severity] || '#8a8e7c';
            },
            'border-opacity': 0.7,
            'overlay-opacity': 0,
            'transition-property': 'background-color, width, height, border-color',
            'transition-duration': 200,
          } as cytoscape.Css.Node,
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 4,
            'border-color': '#e8e4dc',
            'border-opacity': 1,
            'background-color': function (ele: cytoscape.NodeSingular) {
              const severity = ele.data('severity') as Severity;
              return SEVERITY_COLORS[severity] || '#8a8e7c';
            },
          } as cytoscape.Css.Node,
        },
        {
          selector: 'edge',
          style: {
            width: 1.5,
            'line-color': 'rgba(90, 100, 80, 0.2)',
            'target-arrow-color': 'rgba(90, 100, 80, 0.35)',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.7,
            'curve-style': 'unbundled-bezier',
            'control-point-distances': [30],
            'control-point-weights': [0.5],
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
        name: 'cose',
        animate: true,
        animationDuration: 1000,
        animationEasing: 'ease-out',
        nodeRepulsion: () => 80000,
        idealEdgeLength: () => 250,
        edgeElasticity: () => 100,
        gravity: 0.08,
        numIter: 1500,
        padding: 80,
        nodeDimensionsIncludeLabels: true,
      },
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.25,
    });

    cy.on('tap', 'node', (evt) => {
      const nodeData = evt.target.data();
      setSelectedNode(nodeData);
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [chainData]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.3);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() / 1.3);
  const handleFit = () => cyRef.current?.fit(undefined, 40);

  // Fix encoding issues in text (â€" → —)
  const fixEncoding = (text: string | undefined): string => {
    if (!text) return '';
    return text
      .replace(/â€"/g, '—')
      .replace(/â€˜/g, "'")
      .replace(/â€™/g, "'")
      .replace(/â€œ/g, '"')
      .replace(/â€\u009d/g, '"');
  };

  return (
    <div className="h-full flex flex-col animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="glass-panel p-5 max-w-lg">
          <div className="text-[10px] tracking-[0.2em] uppercase text-[#8a8e7c] mb-2">
            Attack Path Visualizer
          </div>
          <h2 className="text-xl font-semibold text-[#2a2e24] mb-2">
            A quiet map of how an attacker would connect the dots.
          </h2>
          <p className="text-[13px] text-[#6b6e60]">
            Click any node to inspect its CVSS weight and our AI mitigation plan.
          </p>
        </div>

        {/* Legend */}
        <div className="glass-panel p-4">
          <div className="flex gap-6 mb-3">
            {(Object.entries(LAYER_LABELS) as [Layer, string][]).map(([layer, label]) => (
              <div key={layer} className="flex items-center gap-2">
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ background: LAYER_COLORS[layer] }}
                />
                <span className="text-xs text-[#4a4e40]">{label}</span>
              </div>
            ))}
          </div>
          <div className="flex gap-4 border-t border-[#e0dcd4] pt-3">
            {(Object.entries(SEVERITY_COLORS) as [Severity, string][])
              .filter(([sev]) => sev !== 'info')
              .map(([sev, color]) => (
                <div key={sev} className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full" style={{ background: color }} />
                  <span className="text-[10px] text-[#6b6e60] uppercase">{sev}</span>
                </div>
              ))}
          </div>
        </div>
      </div>

      {/* Graph container */}
      <div className="flex-1 relative glass-panel overflow-hidden">
        <div ref={containerRef} className="cytoscape-container w-full h-full min-h-[500px]" />

        {/* Zoom controls */}
        <div className="absolute bottom-4 right-4 flex flex-col gap-2">
          <button
            onClick={handleZoomIn}
            className="w-9 h-9 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors"
          >
            <ZoomIn size={16} className="text-[#4a4e40]" />
          </button>
          <button
            onClick={handleZoomOut}
            className="w-9 h-9 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors"
          >
            <ZoomOut size={16} className="text-[#4a4e40]" />
          </button>
          <button
            onClick={handleFit}
            className="w-9 h-9 glass-panel flex items-center justify-center hover:bg-black/5 transition-colors"
          >
            <Maximize2 size={16} className="text-[#4a4e40]" />
          </button>
        </div>

        {/* Selected node panel */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 glass-panel p-5 animate-slide-right shadow-lg">
            <div className="flex items-start justify-between mb-3">
              <div>
                <span
                  className={`text-[10px] tracking-wider uppercase font-semibold badge-${selectedNode.severity}`}
                >
                  {selectedNode.severity}
                </span>
                <span className="text-[10px] text-[#8a8e7c] ml-2 uppercase tracking-wider">
                  {selectedNode.layer}
                </span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-[#8a8e7c] hover:text-[#4a4e40] transition-colors"
              >
                <X size={16} />
              </button>
            </div>
            <h3 className="font-semibold text-[#2a2e24] mb-3 text-sm leading-relaxed">
              {fixEncoding(selectedNode.fullLabel || selectedNode.label)}
            </h3>
            {selectedNode.gives && (
              <div className="mb-3">
                <span className="text-[10px] uppercase tracking-wider text-[#8a8e7c]">
                  Gives attacker
                </span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.gives.split(',').map((g: string) => (
                    <span
                      key={g.trim()}
                      className="text-[11px] font-mono bg-sev-critical/10 text-sev-critical px-2 py-0.5 rounded"
                    >
                      {g.trim()}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {selectedNode.requires && (
              <div>
                <span className="text-[10px] uppercase tracking-wider text-[#8a8e7c]">
                  Requires
                </span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedNode.requires.split(',').map((r: string) => (
                    <span
                      key={r.trim()}
                      className="text-[11px] font-mono bg-sev-medium/10 text-sev-medium px-2 py-0.5 rounded"
                    >
                      {r.trim()}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
