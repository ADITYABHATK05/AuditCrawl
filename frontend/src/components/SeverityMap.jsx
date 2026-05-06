import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import AccordionGroup from './AccordionGroup';
import { staggerContainer, fadeSlideUp } from '../utils/motionVariants';

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function severityClass(sev) {
  const s = (sev || 'info').toLowerCase();
  return `sev sev-${s}`;
}

export default function SeverityMap({ findings, filterType, sortMode, sortedUniqueFindings, topRoiTypes, setEffortByType }) {
  // Default expanded severities
  const [expandedSevs, setExpandedSevs] = useState({
    critical: true,
    high: true,
    medium: false,
    low: false,
    info: false
  });

  const toggleSev = (sev) => {
    setExpandedSevs(prev => ({ ...prev, [sev]: !prev[sev] }));
  };

  return (
    <motion.div variants={staggerContainer} initial="hidden" animate="visible">
      {SEV_ORDER.map(sev => {
        const sevFindings = findings.filter(f => (f.severity || "info").toLowerCase() === sev);
        if (sevFindings.length === 0) return null;
        
        const filtered = sevFindings.filter(f => filterType === "all" || (f.type || "unknown") === filterType);
        if (filtered.length === 0) return null;
        
        const typesForSev = [...new Set(filtered.map(f => f.type || "unknown"))];
        const isExpanded = expandedSevs[sev];

        return (
          <motion.div key={sev} variants={fadeSlideUp} style={{ marginBottom: "2rem" }}>
            <div 
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.75rem",
                marginBottom: isExpanded ? "1.25rem" : "0",
                paddingBottom: "1rem",
                borderBottom: "2px solid var(--border)",
                cursor: "pointer",
                userSelect: "none"
              }}
              onClick={() => toggleSev(sev)}
            >
              <span className={severityClass(sev)} style={{ fontSize: "0.85rem" }}>
                {sev.toUpperCase()}
              </span>
              <span style={{ color: "var(--muted)", fontSize: "0.85rem" }}>
                {filtered.length} finding{filtered.length !== 1 ? "s" : ""}
              </span>
              <span style={{ marginLeft: "auto", color: "var(--muted)", fontSize: "0.8rem" }}>
                {isExpanded ? "▲" : "▼"}
              </span>
            </div>
            
            <AnimatePresence>
              {isExpanded && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.3, ease: [0.25, 0.46, 0.45, 0.94] }}
                  style={{ overflow: 'hidden' }}
                >
                  <div style={{ paddingTop: '0.5rem', paddingLeft: '0.5rem' }}>
                    {(sortMode === "fixValue"
                      ? [...typesForSev].sort((a, b) => {
                          const aScore = sortedUniqueFindings.find((x) => x.type === a)?.fixValue || 0;
                          const bScore = sortedUniqueFindings.find((x) => x.type === b)?.fixValue || 0;
                          return bScore - aScore;
                        })
                      : typesForSev
                    ).map(type => {
                      const typeInstances = filtered.filter(f => (f.type || "unknown") === type);
                      const typeScore = sortedUniqueFindings.find((x) => x.type === type);
                      
                      return (
                        <AccordionGroup 
                          key={type}
                          type={type}
                          instances={typeInstances}
                          mostSevere={sev}
                          typeScore={typeScore}
                          topRoiTypes={topRoiTypes}
                          setEffortByType={setEffortByType}
                        />
                      );
                    })}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        );
      })}
    </motion.div>
  );
}
