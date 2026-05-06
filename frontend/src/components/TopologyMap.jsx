import React, { useMemo, useState, useRef, useEffect } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { motion, AnimatePresence } from 'framer-motion';

function getSeverityColor(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return '#ff3355'; // crimson
    case 'high': return '#ff8c00'; // orange
    case 'medium': return '#ffd700'; // gold
    case 'low': return '#40aaff'; // blue
    default: return '#00e5a0'; // neon for safe/info
  }
}

export default function TopologyMap({ scan, findings }) {
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 0, height: 600 });
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (containerRef.current) {
      setDimensions({
        width: containerRef.current.clientWidth,
        height: 600
      });
    }
    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: 600
        });
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const { graphData, nodeMap } = useMemo(() => {
    const nodes = [];
    const links = [];
    const map = new Map();

    const rootId = 'root';
    const rootUrl = scan?.target_url || 'Target Application';
    
    // Add root node
    nodes.push({
      id: rootId,
      name: rootUrl,
      val: 16,
      color: '#00e5a0',
      type: 'root',
      findings: []
    });
    map.set(rootId, nodes[0]);

    // Group findings by URL
    findings.forEach(finding => {
      const url = finding.url || finding.endpoint || 'Unknown Endpoint';
      
      // Simplify URL for display
      let displayUrl = url;
      try {
        if (rootUrl !== 'Target Application' && url.startsWith(rootUrl)) {
          displayUrl = url.substring(rootUrl.length) || '/';
        } else {
          const urlObj = new URL(url);
          displayUrl = urlObj.pathname;
        }
      } catch(e) {
        // Fallback
      }
      
      if (!map.has(url)) {
        const node = {
          id: url,
          name: displayUrl,
          fullUrl: url,
          val: 8, // base node size
          color: getSeverityColor(finding.severity),
          type: 'endpoint',
          highestSeverity: finding.severity,
          findings: [finding]
        };
        nodes.push(node);
        map.set(url, node);
        
        // Link to root
        links.push({
          source: rootId,
          target: url
        });
      } else {
        const node = map.get(url);
        node.findings.push(finding);
        node.val = Math.min(24, node.val + 1.5); // grow size slightly with more findings
        
        // Update color if severity is higher
        const levels = ['info', 'low', 'medium', 'high', 'critical'];
        const currentSevLevel = levels.indexOf((node.highestSeverity || 'info').toLowerCase());
        const newSevLevel = levels.indexOf((finding.severity || 'info').toLowerCase());
        
        if (newSevLevel > currentSevLevel) {
          node.highestSeverity = finding.severity;
          node.color = getSeverityColor(finding.severity);
        }
      }
    });

    // Update root color if there are vulnerabilities
    let highestRootSev = 'info';
    nodes.forEach(n => {
      if (n.type !== 'root') {
        const levels = ['info', 'low', 'medium', 'high', 'critical'];
        if (levels.indexOf((n.highestSeverity || 'info').toLowerCase()) > levels.indexOf(highestRootSev)) {
          highestRootSev = n.highestSeverity.toLowerCase();
        }
      }
    });
    
    if (highestRootSev !== 'info') {
      nodes[0].color = getSeverityColor(highestRootSev);
    }

    return { graphData: { nodes, links }, nodeMap: map };
  }, [findings, scan]);

  const handleNodeClick = (node) => {
    setSelectedNode(node);
  };

  return (
    <div style={{ position: 'relative', width: '100%', borderRadius: '12px', overflow: 'hidden', border: '1px solid var(--border)', background: 'var(--bg)' }}>
      <div ref={containerRef} style={{ width: '100%', height: '600px' }}>
        {dimensions.width > 0 && (
          <ForceGraph2D
            width={dimensions.width}
            height={dimensions.height}
            graphData={graphData}
            nodeLabel="name"
            nodeColor="color"
            nodeRelSize={1}
            linkColor={() => 'rgba(255,255,255,0.15)'}
            onNodeClick={handleNodeClick}
            backgroundColor="#020617"
            d3AlphaDecay={0.05}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const label = node.name;
              const fontSize = 12 / globalScale;
              ctx.font = `${fontSize}px "Share Tech Mono"`;
              
              // Draw node
              ctx.beginPath();
              ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI, false);
              ctx.fillStyle = node.color;
              ctx.fill();
              
              // Draw glow
              ctx.shadowColor = node.color;
              ctx.shadowBlur = 10;
              ctx.fill();
              ctx.shadowBlur = 0; // reset
              
              // Draw text
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
              ctx.fillText(label, node.x, node.y + node.val + (fontSize * 1.5));
            }}
          />
        )}
      </div>

      {/* Drawer */}
      <AnimatePresence>
        {selectedNode && (
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            style={{
              position: 'absolute',
              top: 0, right: 0, bottom: 0,
              width: '350px',
              background: 'rgba(11, 17, 32, 0.95)',
              backdropFilter: 'blur(16px)',
              borderLeft: '1px solid var(--border)',
              padding: '1.5rem',
              overflowY: 'auto',
              boxShadow: '-10px 0 30px rgba(0,0,0,0.5)',
              zIndex: 10
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
              <div>
                <h3 style={{ fontFamily: 'var(--display)', fontSize: '1.2rem', color: 'white', wordBreak: 'break-all' }}>
                  {selectedNode.name}
                </h3>
                <div style={{ fontSize: '0.8rem', color: 'var(--muted)', marginTop: '0.25rem' }}>
                  {selectedNode.type === 'root' ? 'Target Root' : `${selectedNode.findings.length} findings on this endpoint`}
                </div>
              </div>
              <button 
                onClick={() => setSelectedNode(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text)', cursor: 'pointer', padding: '0.2rem', fontSize: '1.2rem' }}
              >
                ✕
              </button>
            </div>

            {selectedNode.findings.length === 0 ? (
              <div style={{ color: 'var(--neon)', fontSize: '0.9rem', padding: '1rem', background: 'rgba(0,229,160,0.05)', borderRadius: '8px', border: '1px solid rgba(0,229,160,0.2)' }}>
                ✓ No vulnerabilities detected on this exact endpoint.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {selectedNode.findings.map((f, i) => (
                  <div key={i} style={{ padding: '1rem', background: 'var(--bg)', borderRadius: '8px', borderLeft: `3px solid ${getSeverityColor(f.severity)}` }}>
                    <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: getSeverityColor(f.severity), marginBottom: '0.25rem', fontFamily: 'var(--mono)' }}>
                      {f.severity}
                    </div>
                    <div style={{ fontFamily: 'var(--display)', fontWeight: 600, color: 'white', marginBottom: '0.5rem' }}>
                      {f.type}
                    </div>
                    {f.description && (
                      <div style={{ fontSize: '0.8rem', color: 'var(--muted)', lineHeight: '1.4' }}>
                        {f.description}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
      
      {/* Legend */}
      <div style={{ position: 'absolute', bottom: '1rem', left: '1rem', background: 'rgba(11,17,32,0.8)', padding: '0.75rem', borderRadius: '8px', border: '1px solid var(--border)', backdropFilter: 'blur(4px)', display: 'flex', flexDirection: 'column', gap: '0.5rem', pointerEvents: 'none' }}>
        <span style={{ fontSize: '0.7rem', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: 'var(--mono)' }}>Severity Map</span>
        {['Critical', 'High', 'Medium', 'Low', 'Safe'].map(sev => (
          <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: getSeverityColor(sev) }}></span>
            <span style={{ fontSize: '0.8rem', color: 'var(--text)' }}>{sev}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
