import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cardHover } from '../utils/motionVariants';
import CopilotChat from './CopilotChat';

function severityClass(sev) {
  const s = (sev || 'info').toLowerCase();
  return `sev sev-${s}`;
}

export default function AccordionGroup({ type, instances, mostSevere, typeScore, topRoiTypes, setEffortByType }) {
  const [isOpen, setIsOpen] = useState(false);
  const [activeCopilotFinding, setActiveCopilotFinding] = useState(null);

  // Group by description
  const byDescription = {};
  instances.forEach(finding => {
    const desc = finding.description || "No description";
    if (!byDescription[desc]) {
      byDescription[desc] = {
        description: desc,
        evidence: finding.evidence,
        param: finding.param,
        poc: finding.poc,
        urls: []
      };
    }
    byDescription[desc].urls.push({
      url: finding.url,
      severity: finding.severity,
      type: finding.type
    });
  });

  return (
    <motion.div
      className={`finding-card ${isOpen ? 'expanded' : ''}`}
      style={{ borderLeft: `4px solid var(--${mostSevere === 'critical' || mostSevere === 'high' ? 'danger' : mostSevere === 'medium' ? 'warn' : mostSevere === 'low' ? 'info' : 'muted'})` }}
      onClick={() => setIsOpen(!isOpen)}
      whileHover="whileHover"
      whileTap="whileTap"
      variants={cardHover}
    >
      <div className="finding-header">
        <span className={severityClass(mostSevere)}>{(mostSevere || 'info').toUpperCase()}</span>
        <span className="finding-type">{type}</span>
        <span style={{ color: "var(--muted)", fontSize: "0.75rem", marginLeft: 'auto' }}>
          {instances.length} instance{instances.length !== 1 ? 's' : ''} {isOpen ? "▲" : "▼"}
        </span>
      </div>

      <div className="type-roi-row" onClick={(e) => e.stopPropagation()}>
        <span className="finding-roi-score">Fix Value: {typeScore?.fixValue?.toFixed(1) || "0.0"}</span>
        {topRoiTypes.has(type) && <span className="roi-badge">Best ROI</span>}
        <label className="finding-roi-label" style={{ marginLeft: '1rem' }}>
          Effort
          <select
            value={typeScore?.effortKey || "M"}
            onChange={(e) => setEffortByType((prev) => ({ ...prev, [type]: e.target.value }))}
            className="finding-roi-select"
          >
            <option value="S">S</option>
            <option value="M">M</option>
            <option value="L">L</option>
          </select>
        </label>
      </div>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: [0.25, 0.46, 0.45, 0.94] }}
            style={{ overflow: 'hidden' }}
          >
            <div className="finding-body">
              {Object.entries(byDescription).map(([descKey, finding], idx) => (
                <div key={idx} style={{ marginBottom: idx < Object.keys(byDescription).length - 1 ? '1.5rem' : 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{
                      fontFamily: "var(--display)",
                      fontWeight: 600,
                      fontSize: "0.95rem",
                      color: "var(--text)",
                      marginBottom: "0.75rem"
                    }}>
                      {finding.description}
                    </div>
                    <button 
                      onClick={(e) => { 
                        e.stopPropagation(); 
                        setActiveCopilotFinding({ type, severity: mostSevere, ...finding }); 
                      }}
                      style={{ 
                        background: 'rgba(0, 229, 160, 0.15)',
                        border: '1px solid var(--neon)',
                        color: 'var(--neon)',
                        padding: '0.3rem 0.6rem',
                        borderRadius: '6px',
                        cursor: 'pointer',
                        fontSize: '0.75rem',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.3rem',
                        fontFamily: 'var(--display)'
                      }}
                    >
                      <span style={{ fontSize: '0.9rem' }}>🤖</span> Ask Copilot
                    </button>
                  </div>
                  
                  <div style={{ marginBottom: "0.5rem" }}>
                    <span style={{ fontSize: "0.75rem", color: "var(--muted)", textTransform: "uppercase" }}>
                      Affected Endpoints ({finding.urls.length})
                    </span>
                  </div>
                  
                  <div style={{ 
                    display: "flex",
                    flexDirection: "column",
                    marginBottom: "0.75rem"
                  }}>
                    {finding.urls.map((item, i) => (
                      <div 
                        key={i}
                        style={{ 
                          fontSize: "0.8rem", 
                          color: "var(--muted)",
                          fontFamily: "var(--mono)",
                          wordBreak: "break-all"
                        }}
                      >
                        {item.url}
                      </div>
                    ))}
                  </div>
                  
                  {finding.evidence && (
                    <>
                      <div style={{
                        fontSize: "0.75rem",
                        color: "var(--muted)",
                        textTransform: "uppercase",
                        marginBottom: "0.3rem"
                      }}>
                        Request/Response Snippet
                      </div>
                      <div className="code-block" style={{ marginBottom: "0.75rem" }}>
                        {finding.evidence}
                      </div>
                    </>
                  )}
                  
                  {finding.poc && (
                    <>
                      <div style={{
                        fontSize: "0.75rem",
                        color: "var(--muted)",
                        textTransform: "uppercase",
                        marginBottom: "0.3rem"
                      }}>
                        Remediation & PoC (Educational)
                      </div>
                      <div className="code-block">
                        {finding.poc}
                      </div>
                    </>
                  )}
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {activeCopilotFinding && (
          <div onClick={(e) => e.stopPropagation()}>
            <CopilotChat 
              finding={activeCopilotFinding} 
              onClose={() => setActiveCopilotFinding(null)} 
            />
          </div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
