/**
 * SOL-MATE — Advanced Interactive Multi-Tier Forensic Knowledge Graph
 * Visualizes multi-layer execution topology, CPI call chains, token mints,
 * authority control vectors, and client onboarding asset flows with zero truncation.
 */

import React, { useState, useRef, useMemo } from 'react';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  Filter,
  Layers,
  Shield,
  ArrowRight,
  Copy,
  Check,
  ExternalLink,
  Cpu,
  Coins,
  Key,
  Network,
} from 'lucide-react';
import { AccountRecord, AccountRelationship, AddressCategory } from '../types/forensics';

interface GraphNode {
  id: string;
  title: string;
  subtitle: string;
  category: AddressCategory;
  roles: string[];
  tier: 0 | 1 | 2 | 3;
  x: number;
  y: number;
  isSigner?: boolean;
  isFeePayer?: boolean;
  isWritable?: boolean;
  solBalance?: number;
  deltaSol?: number;
  tokenSummary?: string;
}

interface GraphLink {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  asset?: string;
  amount?: string;
  confidence: string;
  rawRelationship: AccountRelationship;
}

interface KnowledgeGraphProps {
  relationships: AccountRelationship[];
  accountsRegistry: Record<string, AccountRecord>;
  onSelectAddress: (address: string) => void;
  onSelectRelationship: (rel: AccountRelationship) => void;
}

export const KnowledgeGraph: React.FC<KnowledgeGraphProps> = ({
  relationships,
  accountsRegistry,
  onSelectAddress,
  onSelectRelationship,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [zoom, setZoom] = useState(0.92);
  const [pan, setPan] = useState({ x: 30, y: 20 });
  const [isPanning, setIsPanning] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string>('all');
  const [activeEdgeId, setActiveEdgeId] = useState<string | null>(null);
  const [copiedAddr, setCopiedAddr] = useState<string | null>(null);

  const copyAddr = (addr: string) => {
    navigator.clipboard.writeText(addr);
    setCopiedAddr(addr);
    setTimeout(() => setCopiedAddr(null), 1800);
  };

  // Build rich multi-tier nodes from accountsRegistry and relationships
  const { nodes, links } = useMemo(() => {
    const nodeMap = new Map<string, GraphNode>();

    const classifyTier = (acc?: AccountRecord, id?: string): 0 | 1 | 2 | 3 => {
      if (!acc) return 2;
      if (acc.isFeePayer || (acc.isSigner && !acc.isExecutable)) return 0; // Tier 0: Signers & Initiators
      if (
        acc.isExecutable ||
        acc.category === 'program' ||
        acc.category === 'system-program' ||
        acc.category === 'spl-token-program' ||
        acc.category === 'compute-budget' ||
        acc.category === 'dex-amm'
      ) {
        return 1; // Tier 1: Smart Contracts & CPI Programs
      }
      if (acc.category === 'token-mint' || acc.category === 'pda') {
        return 2; // Tier 2: Mints & Governance PDAs
      }
      return 3; // Tier 3: Client Token Accounts & Destination Wallets
    };

    const ensureNode = (addr: string) => {
      if (!addr || nodeMap.has(addr)) return;
      const acc = accountsRegistry[addr];
      const tier = classifyTier(acc, addr);
      const title =
        acc?.institutionalInfo?.shortLabel ||
        acc?.label ||
        acc?.ownerProgramLabel ||
        (tier === 0 ? 'Transaction Signer' : tier === 1 ? 'On-Chain Program' : 'Solana Account');

      const tokenSummary = acc?.tokenMetadata?.mintSymbol
        ? `${acc.tokenMetadata.mintName || acc.tokenMetadata.mintSymbol} (${acc.tokenMetadata.mintSymbol})`
        : undefined;

      nodeMap.set(addr, {
        id: addr,
        title,
        subtitle: addr,
        category: acc?.category || 'unclassified',
        roles: acc?.roles || [],
        tier,
        x: 0,
        y: 0,
        isSigner: acc?.isSigner,
        isFeePayer: acc?.isFeePayer,
        isWritable: acc?.isWritable,
        solBalance: acc?.solBalance,
        deltaSol: acc?.deltaSol,
        tokenSummary,
      });
    };

    // Add all relationship endpoints first
    for (const rel of relationships) {
      ensureNode(rel.source);
      ensureNode(rel.target);
    }

    // Also include all key accounts from accountsRegistry so no important account is omitted
    for (const addr of Object.keys(accountsRegistry)) {
      ensureNode(addr);
    }

    // Compute multi-column tier coordinates
    const allNodes = Array.from(nodeMap.values());
    const tierBuckets: Record<number, GraphNode[]> = { 0: [], 1: [], 2: [], 3: [] };
    for (const n of allNodes) {
      tierBuckets[n.tier].push(n);
    }

    const tierX: Record<number, number> = {
      0: 120,
      1: 360,
      2: 600,
      3: 840,
    };

    Object.entries(tierBuckets).forEach(([tStr, list]) => {
      const t = Number(tStr);
      const x = tierX[t];
      const verticalSpacing = Math.max(92, Math.min(130, 520 / Math.max(1, list.length)));
      const totalHeight = (list.length - 1) * verticalSpacing;
      const startY = Math.max(85, 290 - totalHeight / 2);

      list.forEach((node, idx) => {
        node.x = x;
        node.y = startY + idx * verticalSpacing;
      });
    });

    const rawLinks: GraphLink[] = relationships.map((r) => ({
      id: r.id,
      source: r.source,
      target: r.target,
      type: r.type,
      label: r.label,
      asset: r.asset,
      amount: r.amount,
      confidence: r.confidence,
      rawRelationship: r,
    }));

    return { nodes: allNodes, links: rawLinks };
  }, [relationships, accountsRegistry]);

  const filteredLinks = useMemo(() => {
    if (filterType === 'all') return links;
    if (filterType === 'transfers')
      return links.filter((l) => l.type.includes('transfer') || l.type.includes('minted') || l.type.includes('burned'));
    if (filterType === 'authorities')
      return links.filter((l) => l.type.includes('owner') || l.type.includes('authority') || l.type.includes('governance'));
    if (filterType === 'programs') return links.filter((l) => l.type.includes('invoke') || l.type.includes('cpi'));
    return links;
  }, [links, filterType]);

  const getNodeTheme = (category: AddressCategory, isFeePayer?: boolean) => {
    if (isFeePayer) {
      return { stroke: '#06b6d4', badgeBg: '#083344', badgeText: '#67e8f9', tag: 'FEE PAYER & SIGNER' };
    }
    switch (category) {
      case 'system-program':
      case 'program':
      case 'native-loader':
      case 'compute-budget':
        return { stroke: '#8b5cf6', badgeBg: '#2e1065', badgeText: '#c4b5fd', tag: 'EXECUTABLE PROGRAM' };
      case 'spl-token-program':
      case 'token-mint':
        return { stroke: '#ec4899', badgeBg: '#500724', badgeText: '#f9a8d4', tag: 'TOKEN MINT / SPL' };
      case 'token-account':
        return { stroke: '#3b82f6', badgeBg: '#172554', badgeText: '#93c5fd', tag: 'TOKEN CUSTODY VAULT' };
      case 'dex-amm':
        return { stroke: '#10b981', badgeBg: '#064e3b', badgeText: '#6ee7b7', tag: 'DEX / LIQUIDITY' };
      case 'user-wallet':
        return { stroke: '#14b8a6', badgeBg: '#042f2e', badgeText: '#5eead4', tag: 'CLIENT / USER WALLET' };
      case 'pda':
        return { stroke: '#f59e0b', badgeBg: '#451a03', badgeText: '#fcd34d', tag: 'AUTHORITY / STATE PDA' };
      default:
        return { stroke: '#64748b', badgeBg: '#1e293b', badgeText: '#cbd5e1', tag: 'REFERENCED ACCOUNT' };
    }
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).tagName === 'svg' || (e.target as HTMLElement).id === 'graph-canvas') {
      setIsPanning(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isPanning) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }
  };

  const handleMouseUp = () => setIsPanning(false);

  const resetView = () => {
    setZoom(0.92);
    setPan({ x: 30, y: 20 });
  };

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) || nodes[0] || null,
    [nodes, selectedNodeId]
  );

  const activeEdge = useMemo(
    () => links.find((l) => l.id === activeEdgeId) || null,
    [links, activeEdgeId]
  );

  return (
    <div className="space-y-5">
      {/* Top Architecture Summary Banner */}
      <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-4 sm:p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            <h3 className="font-extrabold text-base text-white">
              Multi-Layer Forensic Knowledge Graph & Execution Topology
            </h3>
          </div>
          <p className="text-xs text-slate-400">
            4-Tier Directed Graph: <strong className="text-cyan-300">Tier 1: Signers & Authorities</strong> →{' '}
            <strong className="text-violet-300">Tier 2: Invoked Programs & CPIs</strong> →{' '}
            <strong className="text-pink-300">Tier 3: Token Mints & PDAs</strong> →{' '}
            <strong className="text-blue-300">Tier 4: Client Token Vaults & Wallets</strong>
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="px-3 py-1.5 rounded-xl bg-[#090d14] border border-slate-800 font-mono text-cyan-300 font-bold">
            {nodes.length} Forensic Nodes
          </span>
          <span className="px-3 py-1.5 rounded-xl bg-[#090d14] border border-slate-800 font-mono text-violet-300 font-bold">
            {filteredLinks.length} Verified Edges
          </span>
        </div>
      </div>

      {/* Main Split View: Interactive Visual Graph + Live Forensic Node/Edge Inspector */}
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
        {/* Left 3 Columns: Interactive SVG Topology Canvas */}
        <div className="xl:col-span-3 relative h-[620px] bg-[#080c14] rounded-2xl border border-slate-800 overflow-hidden select-none shadow-2xl">
          {/* Canvas Toolbar */}
          <div className="absolute top-3 left-3 right-3 z-10 flex flex-wrap items-center justify-between gap-2 pointer-events-none">
            <div className="flex items-center gap-1.5 pointer-events-auto bg-[#111827]/95 backdrop-blur-md p-1 rounded-xl border border-slate-700/70 text-xs">
              {[
                { id: 'all', label: `All Edges (${links.length})` },
                { id: 'transfers', label: 'Token & SOL Flows' },
                { id: 'authorities', label: 'Authority & Custody' },
                { id: 'programs', label: 'Program & CPI Calls' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setFilterType(tab.id)}
                  className={`px-2.5 py-1 rounded-lg font-semibold transition cursor-pointer ${
                    filterType === tab.id
                      ? 'bg-cyan-500 text-slate-950 font-bold'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="flex items-center bg-[#111827]/95 backdrop-blur-md rounded-xl border border-slate-700/70 p-1 pointer-events-auto">
              <button
                onClick={() => setZoom((z) => Math.min(2.2, z + 0.15))}
                className="p-1.5 text-slate-300 hover:text-cyan-400 hover:bg-slate-800 rounded-lg transition cursor-pointer"
                title="Zoom In"
              >
                <ZoomIn className="w-4 h-4" />
              </button>
              <button
                onClick={() => setZoom((z) => Math.max(0.45, z - 0.15))}
                className="p-1.5 text-slate-300 hover:text-cyan-400 hover:bg-slate-800 rounded-lg transition cursor-pointer"
                title="Zoom Out"
              >
                <ZoomOut className="w-4 h-4" />
              </button>
              <button
                onClick={resetView}
                className="p-1.5 text-slate-300 hover:text-cyan-400 hover:bg-slate-800 rounded-lg transition cursor-pointer"
                title="Reset View"
              >
                <Maximize2 className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* SVG Graph Viewport */}
          <div
            id="graph-canvas"
            ref={containerRef}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            className="w-full h-full cursor-grab active:cursor-grabbing"
          >
            <svg className="w-full h-full">
              <defs>
                <pattern id="forensic-grid" width="32" height="32" patternUnits="userSpaceOnUse">
                  <path
                    d="M 32 0 L 0 0 0 32"
                    fill="none"
                    stroke="#1e293b"
                    strokeWidth="0.6"
                    strokeOpacity="0.55"
                  />
                </pattern>
                <marker
                  id="arrow-cyan"
                  viewBox="0 0 10 10"
                  refX="9"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#06b6d4" />
                </marker>
                <marker
                  id="arrow-pink"
                  viewBox="0 0 10 10"
                  refX="9"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#ec4899" />
                </marker>
                <marker
                  id="arrow-violet"
                  viewBox="0 0 10 10"
                  refX="9"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#8b5cf6" />
                </marker>
                <marker
                  id="arrow-emerald"
                  viewBox="0 0 10 10"
                  refX="9"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" />
                </marker>
              </defs>

              <rect width="100%" height="100%" fill="url(#forensic-grid)" />

              <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                {/* Column Tier Headers */}
                {[
                  { x: 140, title: 'TIER 1: SIGNERS & DISPATCHERS', color: '#06b6d4' },
                  { x: 430, title: 'TIER 2: INVOKED PROGRAMS & CPI', color: '#8b5cf6' },
                  { x: 730, title: 'TIER 3: MINTS & AUTHORITY PDAs', color: '#ec4899' },
                  { x: 1030, title: 'TIER 4: CUSTODY VAULTS & HOLDERS', color: '#3b82f6' },
                ].map((col, idx) => (
                  <g key={idx} transform={`translate(${col.x}, 32)`}>
                    <rect
                      x="-115"
                      y="-16"
                      width="230"
                      height="24"
                      rx="6"
                      fill="#0f172a"
                      stroke={col.color}
                      strokeOpacity="0.4"
                    />
                    <text
                      textAnchor="middle"
                      y="0"
                      fill={col.color}
                      fontSize="9"
                      fontWeight="800"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {col.title}
                    </text>
                  </g>
                ))}

                {/* Directed Bezier Links */}
                {filteredLinks.map((link) => {
                  const src = nodes.find((n) => n.id === link.source);
                  const tgt = nodes.find((n) => n.id === link.target);
                  if (!src || !tgt) return null;

                  const isHighlighted =
                    activeEdgeId === link.id ||
                    selectedNode?.id === link.source ||
                    selectedNode?.id === link.target;

                  const isMintOrTransfer =
                    link.type.includes('transfer') || link.type.includes('minted') || link.type.includes('burned');
                  const isAuth = link.type.includes('owner') || link.type.includes('authority');

                  const strokeColor = isHighlighted
                    ? '#38bdf8'
                    : isMintOrTransfer
                    ? '#ec4899'
                    : isAuth
                    ? '#10b981'
                    : '#8b5cf6';

                  const markerId = isMintOrTransfer
                    ? 'arrow-pink'
                    : isAuth
                    ? 'arrow-emerald'
                    : 'arrow-violet';

                  // Self-loop (e.g. Anchor self-CPI) vs standard bezier curve
                  const isSelfLoop = src.id === tgt.id;
                  const startX = src.x + (src.tier <= tgt.tier ? 105 : -105);
                  const startY = src.y;
                  const endX = tgt.x + (src.tier <= tgt.tier ? -105 : 105);
                  const endY = tgt.y;

                  const ctrlX1 = startX + (endX - startX) * 0.45;
                  const ctrlY1 = startY;
                  const ctrlX2 = startX + (endX - startX) * 0.55;
                  const ctrlY2 = endY;

                  const pathData = isSelfLoop
                    ? `M ${src.x + 90} ${src.y - 12} C ${src.x + 175} ${src.y - 65}, ${src.x + 175} ${src.y + 65}, ${src.x + 90} ${src.y + 12}`
                    : `M ${startX} ${startY} C ${ctrlX1} ${ctrlY1}, ${ctrlX2} ${ctrlY2}, ${endX} ${endY}`;

                  const midX = isSelfLoop ? src.x + 150 : (startX + endX) / 2;
                  const midY = isSelfLoop ? src.y : (startY + endY) / 2 - 8;

                  return (
                    <g
                      key={link.id}
                      className="cursor-pointer"
                      onClick={(e) => {
                        e.stopPropagation();
                        setActiveEdgeId(link.id);
                        onSelectRelationship(link.rawRelationship);
                      }}
                    >
                      <path
                        d={pathData}
                        fill="none"
                        stroke={strokeColor}
                        strokeWidth={isHighlighted ? 2.8 : 1.8}
                        strokeDasharray={link.confidence === 'derived' ? '5 4' : undefined}
                        opacity={isHighlighted ? 1 : 0.78}
                        markerEnd={`url(#${markerId})`}
                      />

                      {/* Edge Label Pill */}
                      <g transform={`translate(${midX}, ${midY})`}>
                        <rect
                          x="-72"
                          y="-10"
                          width="144"
                          height="16"
                          rx="4"
                          fill="#090d16"
                          stroke={strokeColor}
                          strokeWidth="0.8"
                          opacity="0.92"
                        />
                        <text
                          textAnchor="middle"
                          y="1"
                          fill={isHighlighted ? '#ffffff' : '#cbd5e1'}
                          fontSize="8.5"
                          fontWeight="700"
                          fontFamily="JetBrains Mono, monospace"
                        >
                          {link.amount ? `${link.label}` : link.label}
                        </text>
                      </g>
                    </g>
                  );
                })}

                {/* Rich Visual Node Cards */}
                {nodes.map((node) => {
                  const isSelected = selectedNode?.id === node.id;
                  const theme = getNodeTheme(node.category, node.isFeePayer);
                  const cardW = 210;
                  const cardH = 66;

                  return (
                    <g
                      key={node.id}
                      transform={`translate(${node.x}, ${node.y})`}
                      className="cursor-pointer"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedNodeId(node.id);
                        onSelectAddress(node.id);
                      }}
                    >
                      {/* Outer Selection Halo */}
                      {isSelected && (
                        <rect
                          x={-cardW / 2 - 4}
                          y={-cardH / 2 - 4}
                          width={cardW + 8}
                          height={cardH + 8}
                          rx="12"
                          fill="none"
                          stroke={theme.stroke}
                          strokeWidth="2"
                          opacity="0.6"
                        />
                      )}

                      {/* Main Node Card */}
                      <rect
                        x={-cardW / 2}
                        y={-cardH / 2}
                        width={cardW}
                        height={cardH}
                        rx="9"
                        fill="#0f172a"
                        stroke={theme.stroke}
                        strokeWidth={isSelected ? 2.4 : 1.4}
                      />

                      {/* Top Category Badge Bar */}
                      <rect
                        x={-cardW / 2 + 8}
                        y={-cardH / 2 + 6}
                        width={cardW - 16}
                        height="14"
                        rx="4"
                        fill={theme.badgeBg}
                      />
                      <text
                        x={-cardW / 2 + 14}
                        y={-cardH / 2 + 16}
                        fill={theme.badgeText}
                        fontSize="8"
                        fontWeight="800"
                        fontFamily="JetBrains Mono, monospace"
                      >
                        {theme.tag}
                      </text>

                      {/* Signer / Writable Mini Indicator */}
                      <text
                        x={cardW / 2 - 12}
                        y={-cardH / 2 + 16}
                        textAnchor="end"
                        fill="#94a3b8"
                        fontSize="7.5"
                        fontFamily="JetBrains Mono, monospace"
                      >
                        {node.isSigner ? 'SIGNER' : node.isWritable ? 'WRITABLE' : 'READ'}
                      </text>

                      {/* Node Descriptive Title */}
                      <text
                        x={-cardW / 2 + 10}
                        y={2}
                        fill="#f8fafc"
                        fontSize="9.5"
                        fontWeight="700"
                      >
                        {node.title.length > 27 ? node.title.slice(0, 27) + '...' : node.title}
                      </text>

                      {/* Address Line */}
                      <text
                        x={-cardW / 2 + 10}
                        y={16}
                        fill="#38bdf8"
                        fontSize="8.5"
                        fontFamily="JetBrains Mono, monospace"
                      >
                        {node.id.slice(0, 10)}...{node.id.slice(-8)}
                      </text>

                      {/* Balance or Token Tag */}
                      {node.tokenSummary && (
                        <text
                          x={-cardW / 2 + 10}
                          y={27}
                          fill="#f472b6"
                          fontSize="8"
                          fontWeight="700"
                          fontFamily="JetBrains Mono, monospace"
                        >
                          {node.tokenSummary.slice(0, 28)}
                        </text>
                      )}
                    </g>
                  );
                })}
              </g>
            </svg>
          </div>

          {/* Bottom Legend Bar */}
          <div className="absolute bottom-3 left-3 right-3 z-10 flex flex-wrap items-center justify-between gap-2 bg-[#111827]/95 backdrop-blur-md px-3.5 py-2 rounded-xl border border-slate-700/70 text-[11px] text-slate-300 pointer-events-none">
            <div className="flex flex-wrap items-center gap-3">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span> Fee Payer / Signer
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-violet-500"></span> Program / CPI
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-pink-500"></span> Token Mint
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span> Custody Token Account
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span> Authority / State PDA
              </span>
            </div>
            <span className="text-cyan-400 font-semibold">
              Click any Node Card or Edge to inspect full untruncated address & proofs →
            </span>
          </div>
        </div>

        {/* Right 1 Column: Live Interactive Node & Edge Inspector */}
        <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-4 flex flex-col justify-between space-y-4 h-[620px] overflow-y-auto">
          {selectedNode ? (
            <div className="space-y-4">
              <div className="border-b border-slate-800 pb-3 space-y-1">
                <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-400">
                  Selected Graph Node Inspector
                </span>
                <h4 className="font-extrabold text-sm text-white leading-snug">{selectedNode.title}</h4>
                <span className="inline-block text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  {selectedNode.category.toUpperCase()}
                </span>
              </div>

              {/* Full Untruncated Address Box */}
              <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between text-[10px] text-slate-400">
                  <span>FULL BASE58 ADDRESS (UNTRUNCATED)</span>
                  <button
                    onClick={() => copyAddr(selectedNode.id)}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                  >
                    {copiedAddr === selectedNode.id ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" /> Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" /> Copy
                      </>
                    )}
                  </button>
                </div>
                <code className="text-xs font-mono text-cyan-300 break-all select-all block">
                  {selectedNode.id}
                </code>
              </div>

              {/* Node Metrics */}
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="p-2.5 rounded-lg bg-[#090d14] border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">SOL Balance</span>
                  <span className="font-mono font-bold text-white">
                    {(selectedNode.solBalance ?? 0).toFixed(6)} SOL
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-[#090d14] border border-slate-800">
                  <span className="text-[10px] text-slate-400 block">Permissions</span>
                  <span className="font-mono font-bold text-emerald-300">
                    {selectedNode.isSigner ? 'Signer' : selectedNode.isWritable ? 'Writable' : 'Read-Only'}
                  </span>
                </div>
              </div>

              {/* Connected Relationships for Selected Node */}
              <div className="space-y-2">
                <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider block">
                  Connected Graph Edges (
                  {links.filter((l) => l.source === selectedNode.id || l.target === selectedNode.id).length})
                </span>
                <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                  {links
                    .filter((l) => l.source === selectedNode.id || l.target === selectedNode.id)
                    .map((l) => (
                      <div
                        key={l.id}
                        onClick={() => {
                          setActiveEdgeId(l.id);
                          onSelectRelationship(l.rawRelationship);
                        }}
                        className="p-2.5 rounded-lg bg-[#090d14] hover:bg-slate-900 border border-slate-800 text-[11px] space-y-1 cursor-pointer"
                      >
                        <div className="font-bold text-cyan-300">{l.label}</div>
                        <div className="font-mono text-[10px] text-slate-400 break-all">
                          From: {l.source}
                        </div>
                        <div className="font-mono text-[10px] text-slate-400 break-all">
                          To: {l.target}
                        </div>
                      </div>
                    ))}
                </div>
              </div>

              <button
                onClick={() => onSelectAddress(selectedNode.id)}
                className="w-full py-2 px-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition cursor-pointer"
              >
                Open Full Address Intelligence Drawer
              </button>
            </div>
          ) : (
            <div className="text-center py-12 text-xs text-slate-500">
              Select any node on the canvas to inspect its forensic metadata.
            </div>
          )}

          {activeEdge && (
            <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-xs space-y-1">
              <div className="font-bold text-cyan-300">Selected Edge Proof</div>
              <div className="text-[11px] text-slate-200">{activeEdge.rawRelationship.evidence.interpretation}</div>
              <div className="text-[10px] font-mono text-slate-400">
                Source: {activeEdge.rawRelationship.evidence.sourceMethod}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Complete Untruncated Topology Relationship Matrix */}
      <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="font-bold text-sm text-white">
              Complete Untruncated Knowledge Graph Relationship Ledger ({filteredLinks.length} Edges)
            </h4>
            <p className="text-xs text-slate-400">
              Full Base58 source and destination addresses for every cryptographic, CPI, authority, and token transfer edge.
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-[#090d14]">
                <th className="p-3">Relationship Type</th>
                <th className="p-3">Source Entity (Full Untruncated Address)</th>
                <th className="p-3">Target Entity (Full Untruncated Address)</th>
                <th className="p-3">Forensic Interpretation & Proof</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredLinks.map((l) => {
                const srcAcc = accountsRegistry[l.source];
                const tgtAcc = accountsRegistry[l.target];
                return (
                  <tr key={l.id} className="hover:bg-slate-800/30 transition">
                    <td className="p-3 align-top">
                      <span className="inline-block px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-mono text-[10px] font-bold">
                        {l.label}
                      </span>
                    </td>
                    <td className="p-3 align-top">
                      <div className="font-bold text-slate-200 text-xs">{srcAcc?.label || 'Source Account'}</div>
                      <button
                        onClick={() => onSelectAddress(l.source)}
                        className="font-mono text-[11px] text-cyan-300 hover:underline break-all text-left cursor-pointer"
                      >
                        {l.source}
                      </button>
                    </td>
                    <td className="p-3 align-top">
                      <div className="font-bold text-slate-200 text-xs">{tgtAcc?.label || 'Target Account'}</div>
                      <button
                        onClick={() => onSelectAddress(l.target)}
                        className="font-mono text-[11px] text-cyan-300 hover:underline break-all text-left cursor-pointer"
                      >
                        {l.target}
                      </button>
                    </td>
                    <td className="p-3 align-top text-[11px] text-slate-300">
                      <div>{l.rawRelationship.evidence.interpretation}</div>
                      <div className="text-[10px] font-mono text-slate-500 mt-0.5">
                        Provenance: {l.rawRelationship.evidence.sourceMethod} ({l.rawRelationship.evidence.fieldPath})
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
