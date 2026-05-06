import React from "react";

export function SkeletonBlock({ className = '', animate = true }) {
  return (
    <div className={`skeleton-block ${animate ? 'skeleton-shimmer' : ''} ${className}`} />
  );
}

export function ScanResultsSkeleton() {
  return (
    <div className="space-y-4">
      {/* Header skeleton */}
      <div className="glass-card p-6">
        <SkeletonBlock className="h-7 w-48 mb-3" />
        <SkeletonBlock className="h-4 w-72" />
      </div>
      {/* Stats bar skeleton */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
        {Array.from({length: 6}).map((_, i) => (
          <div key={i} className="glass-card p-4">
            <SkeletonBlock className="h-8 w-12 mb-2" />
            <SkeletonBlock className="h-3 w-20" />
          </div>
        ))}
      </div>
      {/* Donut placeholder */}
      <div className="glass-card p-6 flex items-center gap-6">
        <SkeletonBlock className="w-40 h-40 rounded-full" />
        <div className="flex-1 space-y-3">
          {Array.from({length: 4}).map((_, i) => (
            <SkeletonBlock key={i} className="h-4 w-full" />
          ))}
        </div>
      </div>
      {/* Finding cards skeleton */}
      {Array.from({length: 3}).map((_, i) => (
        <div key={i} className="glass-card p-5">
          <div className="flex items-center gap-3 mb-3">
            <SkeletonBlock className="h-5 w-16 rounded" />
            <SkeletonBlock className="h-5 w-32" />
          </div>
          <SkeletonBlock className="h-3 w-full mb-2" />
          <SkeletonBlock className="h-3 w-3/4" />
        </div>
      ))}
    </div>
  );
}

export function ArchiveSkeleton() {
  return (
    <div className="glass-card p-6">
      <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-4">
        <SkeletonBlock className="h-10" />
        <SkeletonBlock className="h-10" />
        <SkeletonBlock className="h-10" />
        <SkeletonBlock className="h-10" />
      </div>
      <div className="space-y-2">
        <SkeletonBlock className="h-12" />
        <SkeletonBlock className="h-12" />
        <SkeletonBlock className="h-12" />
        <SkeletonBlock className="h-12" />
      </div>
    </div>
  );
}
