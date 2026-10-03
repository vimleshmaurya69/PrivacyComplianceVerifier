import React from 'react';
import { STATUS_CONFIG, RESULT_CONFIG, normalizeStatus } from '../api/dataLoader';

export function StatusBadge({ status, size = 'sm' }) {
  if (!status) return null;

  const normalizedStatus = normalizeStatus(status);
  const conf = STATUS_CONFIG[normalizedStatus] || {
    label: normalizedStatus,
    color: 'bg-slate-800 text-slate-300 border-slate-700',
    badge: 'bg-slate-400'
  };

  const sizeClasses = size === 'lg' ? 'px-3 py-1 text-xs' : 'px-2.5 py-0.5 text-[11px]';

  return (
    <span className={`inline-flex items-center gap-1.5 font-mono font-medium rounded-full border ${conf.color} ${sizeClasses}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${conf.badge}`} />
      {conf.label}
    </span>
  );
}

export function ResultBadge({ result, size = 'sm' }) {
  if (!result) return null;

  const conf = RESULT_CONFIG[result] || {
    label: result,
    color: 'bg-slate-800 text-slate-300 border-slate-700'
  };

  const sizeClasses = size === 'lg' ? 'px-3 py-1 text-xs font-semibold' : 'px-2.5 py-0.5 text-[11px] font-medium';

  return (
    <span className={`inline-flex items-center font-mono rounded-md border ${conf.color} ${sizeClasses}`}>
      {conf.label}
    </span>
  );
}
