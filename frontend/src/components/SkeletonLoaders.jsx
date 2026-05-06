import React from "react";

function SkeletonBlock({ className = "" }) {
  return <div className={`animate-pulse rounded-lg bg-slate-700/50 ${className}`} />;
}

export function ScanResultsSkeleton() {
  return (
    <div className="space-y-6">
      <div className="glass-card p-6">
        <SkeletonBlock className="mb-4 h-6 w-44" />
        <SkeletonBlock className="h-4 w-80" />
      </div>
      <div className="glass-card p-6">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <SkeletonBlock className="h-16" />
          <SkeletonBlock className="h-16" />
          <SkeletonBlock className="h-16" />
        </div>
      </div>
      <div className="space-y-3">
        <SkeletonBlock className="h-28" />
        <SkeletonBlock className="h-28" />
        <SkeletonBlock className="h-28" />
      </div>
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
