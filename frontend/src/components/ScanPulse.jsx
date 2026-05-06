import React from 'react';
import { motion } from 'framer-motion';

export default function ScanPulse({ isActive }) {
  if (!isActive) return null;
  return (
    <div className="scan-pulse-container">
      {[0, 1, 2].map(i => (
        <motion.div
          key={i}
          className="scan-pulse-ring"
          animate={{
            scale: [1, 2.5],
            opacity: [0.6, 0],
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            delay: i * 0.6,
            ease: 'easeOut',
          }}
        />
      ))}
      <div className="scan-pulse-core" />
    </div>
  );
}
