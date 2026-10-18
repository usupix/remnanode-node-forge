'use strict';
const assert = require('node:assert/strict');
const {historyParts} = require('../static/history.js');
const bucket = (measured,down=0,degraded=0,other={}) => ({measured_seconds:measured,outage_seconds:down,degraded_seconds:degraded,uptime:measured ? 100*(measured-down-degraded)/measured : null,...other});
const close = (a,b) => assert.ok(Math.abs(a-b)<1e-10,`${a} != ${b}`);

const short = historyParts(bucket(86400,120));
assert.deepEqual(short.map(p=>p.state),['up','down']);
close(short[0].share,86280/86400); close(short[1].share,120/86400);
assert.ok(short[0].share > .998,'Two minutes must not paint the entire day red');
const partialDay = historyParts(bucket(3600,120));
close(partialDay[1].share,120/3600); // Unobserved hours are not invented as uptime.
assert.deepEqual(historyParts(bucket(0)),[{state:'unknown',share:1}]);
assert.deepEqual(historyParts(bucket(86400)),[{state:'up',share:1}]);
assert.deepEqual(historyParts(bucket(86400,86400)),[{state:'down',share:1}]);
assert.deepEqual(historyParts(bucket(300,0,300)),[{state:'degraded',share:1}]);
const mixed = historyParts(bucket(600,120,60,{maintenance_seconds:300}));
assert.deepEqual(mixed.map(p=>p.state),['up','degraded','down']);
close(mixed.reduce((sum,p)=>sum+p.share,0),1);
close(mixed[0].share,.7); close(mixed[1].share,.1); close(mixed[2].share,.2);
assert.deepEqual(historyParts(bucket(300,0,0,{maintenance_seconds:300})),[{state:'up',share:1}]);
for(const data of [bucket(-2),bucket(100,150,90),bucket(100,-4,NaN),bucket(Infinity)]) {
  const parts=historyParts(data);
  assert.ok(parts.every(p=>Number.isFinite(p.share)&&p.share>=0&&p.share<=1));
  close(parts.reduce((sum,p)=>sum+p.share,0),1);
}
console.log('History proportions: all checks passed');
