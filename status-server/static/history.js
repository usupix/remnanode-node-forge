'use strict';

// Shares of observed time, not a worst-state label for the entire interval.
function historyParts(bucket) {
  const measured = Number(bucket.measured_seconds);
  if (!Number.isFinite(measured) || measured <= 0 || bucket.uptime === null) return [{state:'unknown',share:1}];
  const seconds = key => Number.isFinite(Number(bucket[key])) ? Math.max(0,Number(bucket[key])) : 0;
  const down = Math.min(measured,seconds('outage_seconds'));
  const degraded = Math.min(measured-down,seconds('degraded_seconds'));
  return [['up',measured-down-degraded],['degraded',degraded],['down',down]]
    .filter(([,value]) => value > 0).map(([state,value]) => ({state,share:value/measured}));
}

if (typeof module !== 'undefined' && module.exports) module.exports = {historyParts};
