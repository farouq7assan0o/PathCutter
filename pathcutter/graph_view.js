/* ===== PathCutter graph engine =====
 * Canvas renderer built for large attack graphs: sprite nodes, batched edges,
 * viewport culling, quadtree hit-testing, time-sliced force layout, level of
 * detail, shortest-path search and on-graph fix simulation.
 * Inlined into the report; depends on d3 (force, zoom, drag, quadtree). */

const NODE_COLORS = { User: '#3b82f6', Computer: '#10b981', Group: '#f59e0b', Domain: '#ef4444', GPO: '#8b5cf6', OU: '#6366f1', Container: '#64748b', CertTemplate: '#ec4899', EnterpriseCA: '#ec4899', RootCA: '#ec4899', AIACA: '#ec4899', NTAuthStore: '#ec4899', IssuancePolicy: '#f472b6',
  AZUser: '#38bdf8', AZGroup: '#fbbf24', AZServicePrincipal: '#a78bfa', AZApp: '#a78bfa', AZRole: '#f43f5e', AZTenant: '#ef4444',
  AZSubscription: '#0ea5e9', AZResourceGroup: '#64748b', AZVM: '#22c55e', AZKeyVault: '#eab308', AZResource: '#22c55e', AZFederatedIdentityCredential: '#a855f7', AZManagementGroup: '#0ea5e9',
  Cluster: '#94a3b8', Unknown: '#64748b' };
// which drawing a type uses: identities and machines in the cloud look like their on-premises relatives, with a cloud tint in the colour
const BASE_SHAPE = { AZUser: 'User', AZGroup: 'Group', AZVM: 'Computer', AZTenant: 'Domain', CertTemplate: 'GPO', IssuancePolicy: 'GPO',
  EnterpriseCA: 'Shield', RootCA: 'Shield', AIACA: 'Shield', NTAuthStore: 'Shield', AZRole: 'Shield',
  AZServicePrincipal: 'Hex', AZApp: 'Hex', AZKeyVault: 'Hex', AZResource: 'Hex', AZFederatedIdentityCredential: 'Hex', AZSubscription: 'Hex', AZResourceGroup: 'Hex', AZManagementGroup: 'Hex' };
const NODE_SIZES = { 0: 18, 1: 12, 2: 8 };
const EDGE_COLORS = {
  GenericAll: '#ef4444', GenericWrite: '#f97316', WriteDacl: '#f97316', WriteOwner: '#f97316', Owns: '#f97316',
  DCSync: '#ff2222', ForceChangePassword: '#eab308', AddMember: '#eab308', WriteSPN: '#eab308',
  AllowedToDelegate: '#ef4444', AllowedToAct: '#f97316', AddAllowedToAct: '#f97316',
  WriteKeyCredentialLink: '#ef4444', ReadLAPSPassword: '#eab308', ReadGMSAPassword: '#eab308',
  AdminTo: '#a855f7', HasSession: '#8b5cf6', CanRDP: '#8b5cf6', CanPSRemote: '#8b5cf6', ExecuteDCOM: '#8b5cf6', SQLAdmin: '#a855f7',
  GPOControlsObject: '#f97316', Enroll: '#ec4899', ManageCA: '#ec4899',
  ADCSESC1: '#ec4899', ADCSESC3: '#ec4899', ADCSESC4: '#ec4899', ADCSESC5: '#ec4899', ADCSESC6: '#ec4899', ADCSESC7: '#ec4899',
  ADCSESC9: '#ec4899', ADCSESC10: '#ec4899', ADCSESC8: '#ec4899', GPOUserRight: '#f59e0b', CoerceAndRelayNTLMToSMB: '#ef4444', CoerceAndRelayNTLMToLDAP: '#ef4444', ADCSESC16: '#ec4899', ADCSESC11: '#ec4899', AZMGAddMember: '#f43f5e', AZMGResetPassword: '#f43f5e', ADCSESC13: '#ec4899', ADCSESC15: '#ec4899', GoldenCert: '#ec4899',
  AZOwns: '#38bdf8', AZRunsAs: '#38bdf8', AZEligibleRole: '#38bdf8', AZResetPassword: '#38bdf8', AZAddSecret: '#38bdf8', AZMGGrantRole: '#f43f5e',
  AZMGAddSecret: '#f43f5e', AZAuthenticatesTo: '#a855f7', AZGetSecrets: '#eab308', AZGetKeys: '#eab308', AZGetCertificates: '#eab308', AZOwner: '#0ea5e9', AZContributor: '#0ea5e9', AZUserAccessAdmin: '#0ea5e9', AZVMAdminLogin: '#0ea5e9',
  AZManagedIdentity: '#22c55e', SyncedTo: '#22d3ee',
  MemberOf: '#334155', Contains: '#334155', TrustedBy: '#64748b', AZContains: '#334155',
};
const STRUCTURAL = new Set(['MemberOf', 'Contains', 'TrustedBy', 'AZContains']);
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
const dec = s => String(s).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, '&');

const G = {
  inited: false, nodes: [], links: [], out: [], inn: [], idIndex: new Map(),
  k: 1, tx: 0, ty: 0, w: 0, h: 0, dpr: 1,
  dirty: true, raf: 0, hover: -1, sel: -1,
  hl: null, pathInfo: null, pathStart: -1, pathEnd: -1,
  hiddenTypes: new Set(), hideStruct: false, labels: true, edgeLabels: false, hier: false,
  removed: new Set(), applied: new Set(), reach0: null, reach1: null,
  sim: null, layoutRunning: false, progress: 0, alpha0: 1, frameNo: 0, userMoved: false,
  quad: null, vis: null, fps: 0, lastHud: 0, locate: -1,
};

function edgeColor(l) { return EDGE_COLORS[l.type] || '#475569'; }
function nodeRadius(n) { return n.type === 'Cluster' ? 9 + Math.min(14, Math.log2(n.count + 1) * 2.2) : (NODE_SIZES[n.tier] || 8); }
function tierY(tier, spread) { return tier === 0 ? spread * 0.8 : tier === 1 ? 0 : -spread * 0.8; }
function mulberry32(a) { return function () { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }

/* ---------- sprites ---------- */
const SPR = 80, SPR_R = 22;
const spriteCache = {};
// Mipmapped: pick the smallest backing size that is still crisp at the on-screen size.
function spriteRes(screenPx) { return screenPx <= 22 ? 32 : screenPx <= 44 ? 64 : screenPx <= 88 ? 128 : 256; }
function getSprite(n, px) {
  const kind = n.type === 'Cluster' ? 'Cluster:' + n.kind : n.type;
  const key = kind + '|' + (n.tier === 0 ? 1 : 0) + '|' + (n.score > 50 ? 1 : 0) + '|' + px;
  if (spriteCache[key]) return spriteCache[key];
  const SPR_PX = px;
  const c = document.createElement('canvas');
  c.width = c.height = SPR_PX;
  const x = c.getContext('2d');
  x.scale(SPR_PX / SPR, SPR_PX / SPR);
  x.translate(SPR / 2, SPR / 2);
  const r = SPR_R;
  const col = n.type === 'Cluster' ? (NODE_COLORS[n.kind] || NODE_COLORS.Cluster) : (NODE_COLORS[n.type] || '#64748b');
  x.fillStyle = col; x.strokeStyle = col; x.lineCap = 'round';
  const shape = BASE_SHAPE[n.type] || n.type;
  if (shape === 'User') {
    x.beginPath(); x.arc(0, -r * 0.2, r * 0.55, 0, 6.2832); x.fill();
    x.globalAlpha = 0.55; x.beginPath(); x.moveTo(-r * 0.8, r); x.quadraticCurveTo(-r * 0.8, r * 0.15, 0, r * 0.15); x.quadraticCurveTo(r * 0.8, r * 0.15, r * 0.8, r); x.fill(); x.globalAlpha = 1;
  } else if (shape === 'Computer') {
    x.fillRect(-r, -r * 0.7, r * 2, r * 1.2);
    x.globalAlpha = 0.5; x.fillRect(-r * 0.3, r * 0.5, r * 0.6, r * 0.35);
    x.globalAlpha = 0.35; x.fillRect(-r * 0.55, r * 0.85, r * 1.1, r * 0.15); x.globalAlpha = 1;
  } else if (shape === 'Group') {
    [[-0.35, -0.15], [0.35, -0.15], [0, 0.35]].forEach(p => { x.beginPath(); x.arc(r * p[0], r * p[1], r * 0.42, 0, 6.2832); x.fill(); });
  } else if (shape === 'Shield') {
    x.beginPath(); x.moveTo(0, -r); x.lineTo(r * 0.85, -r * 0.55); x.lineTo(r * 0.85, r * 0.1); x.quadraticCurveTo(r * 0.85, r * 0.75, 0, r); x.quadraticCurveTo(-r * 0.85, r * 0.75, -r * 0.85, r * 0.1); x.lineTo(-r * 0.85, -r * 0.55); x.closePath(); x.fill();
    x.globalAlpha = 0.45; x.fillStyle = '#0f172a'; x.beginPath(); x.moveTo(-r * 0.3, 0); x.lineTo(-r * 0.05, r * 0.3); x.lineTo(r * 0.38, -r * 0.3); x.lineWidth = 2; x.strokeStyle = '#0f172a'; x.stroke(); x.globalAlpha = 1;
  } else if (shape === 'Hex') {
    x.beginPath(); for (let i = 0; i < 6; i++) { const a = i * 1.0472 + 0.5236; x.lineTo(Math.cos(a) * r, Math.sin(a) * r); } x.closePath(); x.fill();
    x.globalAlpha = 0.4; x.fillStyle = '#0f172a'; x.beginPath(); x.arc(0, 0, r * 0.3, 0, 6.2832); x.fill(); x.globalAlpha = 1;
  } else if (shape === 'Domain') {
    x.lineWidth = 2.4; x.beginPath(); x.arc(0, 0, r, 0, 6.2832); x.stroke();
    x.lineWidth = 1.1; x.globalAlpha = 0.5; x.beginPath(); x.moveTo(-r, 0); x.lineTo(r, 0); x.moveTo(0, -r); x.quadraticCurveTo(r * 0.4, 0, 0, r); x.moveTo(0, -r); x.quadraticCurveTo(-r * 0.4, 0, 0, r); x.stroke(); x.globalAlpha = 1;
  } else if (shape === 'GPO') {
    x.lineWidth = 2; x.strokeRect(-r * 0.65, -r, r * 1.3, r * 2);
    x.lineWidth = 1.1; x.globalAlpha = 0.4; x.beginPath(); [-0.4, 0, 0.4].forEach(y => { x.moveTo(-r * 0.35, r * y); x.lineTo(r * 0.35, r * y); }); x.stroke(); x.globalAlpha = 1;
  } else if (n.type === 'Cluster') {
    x.globalAlpha = 0.28; x.beginPath(); x.arc(0, 0, r, 0, 6.2832); x.fill(); x.globalAlpha = 1;
    x.lineWidth = 2; x.setLineDash([5, 4]); x.beginPath(); x.arc(0, 0, r, 0, 6.2832); x.stroke(); x.setLineDash([]);
  } else {
    x.beginPath(); x.arc(0, 0, r * 0.7, 0, 6.2832); x.fill();
  }
  if (n.tier === 0) {
    const s = r * 1.4;
    x.strokeStyle = '#ef4444'; x.lineWidth = 2.6;
    x.beginPath(); x.moveTo(0, -s); x.lineTo(s, 0); x.lineTo(0, s); x.lineTo(-s, 0); x.closePath(); x.stroke();
  }
  if (n.score > 50) {
    x.strokeStyle = '#ef4444'; x.globalAlpha = 0.5; x.lineWidth = 1.4;
    x.beginPath(); x.arc(0, 0, r * 1.6, 0, 6.2832); x.stroke(); x.globalAlpha = 1;
  }
  spriteCache[key] = c;
  return c;
}

/* ---------- init ---------- */
function gInit() {
  const N = graphData.nodes, ET = graphData.edgeTypes || [];
  G.nodes = N;
  N.forEach((n, i) => {
    n.i = i; n.label = dec(n.name); n.lc = n.label.toLowerCase(); n.r = nodeRadius(n);
    n.x = 0; n.y = 0; G.idIndex.set(n.id, i);
  });
  G.links = graphData.links.map((l, i) => ({ source: l[0], target: l[1], s: l[0], t: l[1], type: ET[l[2]], i, struct: STRUCTURAL.has(ET[l[2]]), curve: 0 }));
  G.out = N.map(() => []); G.inn = N.map(() => []);
  const pairs = {};
  G.links.forEach(l => {
    G.out[l.s].push(l.i); G.inn[l.t].push(l.i);
    const k = l.s < l.t ? l.s + '|' + l.t : l.t + '|' + l.s;
    (pairs[k] = pairs[k] || []).push(l);
  });
  Object.values(pairs).forEach(arr => { if (arr.length > 1) arr.forEach((l, j) => { l.curve = (j - (arr.length - 1) / 2) * 16; }); });
  G.vis = new Uint8Array(N.length);
  G.reach0 = reverseReach(null);
}

function reverseReach(removed) {
  const n = G.nodes.length, seen = new Uint8Array(n), q = [];
  G.nodes.forEach(nd => { if (nd.tier === 0) { seen[nd.i] = 1; q.push(nd.i); } });
  let head = 0;
  while (head < q.length) {
    const v = q[head++];
    for (const li of G.inn[v]) {
      if (removed && removed.has(li)) continue;
      const u = G.links[li].s;
      if (!seen[u]) { seen[u] = 1; q.push(u); }
    }
  }
  return seen;
}

function drawGraph() {
  if (G.inited) return;
  G.inited = true; window._graphDrawn = true;
  const container = document.getElementById('graph-container');
  const canvas = document.createElement('canvas');
  canvas.id = 'graph-canvas';
  container.insertBefore(canvas, container.firstChild);
  G.canvas = canvas; G.ctx = canvas.getContext('2d');
  G.mini = document.getElementById('graph-minimap');
  G.miniCtx = G.mini.getContext('2d');
  gInit();
  resizeCanvas();
  new ResizeObserver(() => { resizeCanvas(); requestDraw(); }).observe(container);

  G.zoom = d3.zoom().scaleExtent([0.02, 14]).on('zoom', e => {
    G.k = e.transform.k; G.tx = e.transform.x; G.ty = e.transform.y;
    if (e.sourceEvent) G.userMoved = true;
    markInteracting();
    requestDraw();
  });
  const sel = d3.select(canvas);
  sel.call(d3.drag().container(canvas)
    .subject(ev => { const n = findNode(ev.x, ev.y); return n ? { x: ev.x, y: ev.y, n } : null; })
    .on('start', ev => { G.dragging = true; if (!ev.active) G.sim.alphaTarget(0.18); G.layoutRunning = true; ev.subject.n.fx = ev.subject.n.x; ev.subject.n.fy = ev.subject.n.y; requestDraw(); })
    .on('drag', ev => { const n = ev.subject.n; n.fx = (ev.x - G.tx) / G.k; n.fy = (ev.y - G.ty) / G.k; markInteracting(); })
    .on('end', ev => { G.dragging = false; if (!ev.active) G.sim.alphaTarget(0); ev.subject.n.fx = null; ev.subject.n.fy = null; }));
  sel.call(G.zoom).on('dblclick.zoom', null);

  canvas.addEventListener('mousemove', e => {
    if (G.dragging) return;
    const [x, y] = d3.pointer(e, canvas);
    const n = findNode(x, y);
    const idx = n ? n.i : -1;
    if (idx !== G.hover) { G.hover = idx; canvas.style.cursor = n ? 'pointer' : 'grab'; requestDraw(); }
    if (n) showTooltip(e, n); else hideTooltip();
  });
  canvas.addEventListener('mouseleave', () => { G.hover = -1; hideTooltip(); requestDraw(); });
  canvas.addEventListener('click', e => {
    closeCtx();
    const [x, y] = d3.pointer(e, canvas);
    const n = findNode(x, y);
    if (n) selectNode(n.i); else clearSelection();
  });
  canvas.addEventListener('contextmenu', e => {
    e.preventDefault();
    const [x, y] = d3.pointer(e, canvas);
    const n = findNode(x, y);
    if (n) showContextMenu(e, n);
  });
  document.addEventListener('click', e => { if (!e.target.closest('.ctx-menu')) closeCtx(); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && document.getElementById('graph').classList.contains('active')) { clearSelection(); closeCtx(); }
  });
  initMinimap();
  initSimPanel();
  initSearch();
  startLayout();
}

function resizeCanvas() {
  const c = document.getElementById('graph-container');
  if (!c.clientWidth) return;
  G.w = c.clientWidth; G.h = c.clientHeight || 700;
  G.dpr = Math.min(2, window.devicePixelRatio || 1);
  G.canvas.width = Math.round(G.w * G.dpr); G.canvas.height = Math.round(G.h * G.dpr);
}

/* ---------- layout (time-sliced so the UI never freezes) ---------- */
function startLayout() {
  const nodes = G.nodes, n = nodes.length, big = n > 1500;
  const spread = Math.sqrt(n + 1) * 34;
  const rng = mulberry32(7);
  nodes.forEach(d => { d.x = (rng() - 0.5) * spread * 2; d.y = tierY(d.tier, spread) + (rng() - 0.5) * spread * 0.5; });
  G.spread = spread;
  G.sim = d3.forceSimulation(nodes).alphaDecay(big ? 0.05 : 0.025).alphaMin(0.004).velocityDecay(0.4)
    .force('link', d3.forceLink(G.links).distance(l => l.struct ? 30 : (big ? 55 : 75)).strength(l => l.struct ? 0.6 : 0.3))
    .force('charge', d3.forceManyBody().strength(d => d.tier === 0 ? -300 : (d.type === 'Cluster' ? -90 : -45)).theta(0.9).distanceMax(500))
    .force('x', d3.forceX(0).strength(0.015))
    .force('y', d3.forceY(d => tierY(d.tier, spread)).strength(0.04));
  if (!big) G.sim.force('collide', d3.forceCollide(d => d.r + 3));
  G.sim.stop();
  G.alpha0 = G.sim.alpha();
  G.layoutRunning = true; G.big = big;
  document.getElementById('graph-loading').style.display = 'block';
  fitGraph(false);
  requestDraw();
}

function onLayoutDone() {
  document.getElementById('graph-loading').style.display = 'none';
  rebuildQuad(); miniRebuild();
  if (!G.userMoved) fitGraph(true);
  if (G.pendingLocate != null) { const i = G.pendingLocate; G.pendingLocate = null; locateFix(i); }
}

function rebuildQuad() { G.quad = d3.quadtree(G.nodes, d => d.x, d => d.y); }

function findNode(sx, sy) {
  if (!G.quad) return null;
  const wx = (sx - G.tx) / G.k, wy = (sy - G.ty) / G.k;
  const n = G.quad.find(wx, wy, 40 / G.k + 24);
  if (!n) return null;
  const d = Math.hypot(n.x - wx, n.y - wy);
  return d <= n.r + 5 / G.k ? n : null;
}

/* ---------- main loop ---------- */
function markInteracting() {
  G.interacting = true;
  clearTimeout(G.idleTimer);
  G.idleTimer = setTimeout(() => { G.interacting = false; requestDraw(); }, 180);
}

function requestDraw() { G.dirty = true; if (!G.raf) G.raf = requestAnimationFrame(frame); }

function frame(ts) {
  G.raf = 0;
  if (G.lastTs) { const dt = ts - G.lastTs; if (dt > 0) G.fps = G.fps * 0.9 + (1000 / dt) * 0.1; }
  G.lastTs = ts;
  G.frameNo++;
  if (G.layoutRunning) {
    const t0 = performance.now(), budget = G.big ? 14 : 8;
    while (performance.now() - t0 < budget && G.sim.alpha() > G.sim.alphaMin()) G.sim.tick();
    const a = G.sim.alpha(), am = G.sim.alphaMin();
    G.progress = Math.max(0, Math.min(1, Math.log(Math.max(a, am) / G.alpha0) / Math.log(am / G.alpha0)));
    document.getElementById('gl-fill').style.width = (G.progress * 100).toFixed(0) + '%';
    document.getElementById('gl-text').textContent = 'Laying out ' + G.nodes.length.toLocaleString() + ' nodes... ' + (G.progress * 100).toFixed(0) + '%';
    if (G.frameNo % 6 === 0) rebuildQuad();
    if (G.frameNo % 24 === 0) { miniRebuild(); if (!G.userMoved) fitGraph(false); }
    if (a <= am && !G.dragging) { G.layoutRunning = false; onLayoutDone(); }
    G.dirty = true;
  } else if (G.dragging) { rebuildQuad(); }
  if (G.dirty) { draw(); }
  if (G.layoutRunning || G.dirty || G.pathInfo || G.locate >= 0) {
    if (G.pathInfo || G.locate >= 0) G.dirty = true; else G.dirty = false;
    G.raf = requestAnimationFrame(frame);
  }
}

/* ---------- drawing ---------- */
const CHUNK = 250, ARROW_MAX = 2500;
const SEG = new Float64Array(4);
// Liang-Barsky: clip a segment to a rectangle. Keeps raster coordinates bounded,
// which avoids the CPU fallback GPU canvases take for far off-screen geometry.
function clipLine(ax, ay, bx, by, x0, y0, x1, y1) {
  let t0 = 0, t1 = 1; const dx = bx - ax, dy = by - ay;
  for (let i = 0; i < 4; i++) {
    let p, q;
    if (i === 0) { p = -dx; q = ax - x0; } else if (i === 1) { p = dx; q = x1 - ax; } else if (i === 2) { p = -dy; q = ay - y0; } else { p = dy; q = y1 - ay; }
    if (p === 0) { if (q < 0) return false; }
    else { const r = q / p; if (p < 0) { if (r > t1) return false; if (r > t0) t0 = r; } else { if (r < t0) return false; if (r < t1) t1 = r; } }
  }
  SEG[0] = ax + t0 * dx; SEG[1] = ay + t0 * dy; SEG[2] = ax + t1 * dx; SEG[3] = ay + t1 * dy;
  return true;
}
function isLinkHidden(l) { return G.hiddenTypes.has(l.type) || (G.hideStruct && l.struct); }

function draw() {
  G.dirty = false;
  const ctx = G.ctx, w = G.w, h = G.h, k = G.k, tx = G.tx, ty = G.ty, nodes = G.nodes, links = G.links;
  ctx.setTransform(G.dpr, 0, 0, G.dpr, 0, 0);
  ctx.fillStyle = '#0a0f1e'; ctx.fillRect(0, 0, w, h);
  ctx.save(); ctx.translate(tx, ty); ctx.scale(k, k);
  const x0 = -tx / k, y0 = -ty / k, x1 = (w - tx) / k, y1 = (h - ty) / k;
  const vis = G.vis; let visCount = 0;
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i], m = n.r + 6;
    const v = n.x + m >= x0 && n.x - m <= x1 && n.y + m >= y0 && n.y - m <= y1 ? 1 : 0;
    vis[i] = v; visCount += v;
  }
  const heavy = nodes.length > 2500 || links.length > 6000;
  const fast = (G.interacting || G.layoutRunning) && heavy;
  const stride = fast && links.length > 12000 ? 3 : 1;
  const hl = G.hl, anyRem = G.removed.size > 0, reach1 = G.reach1;
  const t = performance.now(), P = G.prof = { start: t };
  const mark = name => { if (G.syncProf) ctx.getImageData(0, 0, 1, 1); P[name] = performance.now(); };

  /* edges */
  const buckets = new Map(), arrowB = new Map(), ghosts = [];
  let visEdges = 0, preCount = 0;
  if (k > 0.55) for (let i = 0; i < links.length; i++) { const l = links[i]; if (!l.struct && vis[l.s] && vis[l.t] && !isLinkHidden(l)) preCount++; }
  const showArrows = !fast && k > 0.55 && preCount < ARROW_MAX;
  for (let i = 0; i < links.length; i++) {
    const l = links[i];
    if (isLinkHidden(l)) continue;
    if (fast && ((l.struct && !(hl && hl.links.has(l.i))) || (stride > 1 && !(hl && hl.links.has(l.i)) && i % stride))) continue;
    const a = nodes[l.s], b = nodes[l.t];
    let ax_ = a.x, ay_ = a.y, bx_ = b.x, by_ = b.y;
    const inside = vis[l.s] && vis[l.t];
    if (!inside) {
      if (!clipLine(a.x, a.y, b.x, b.y, x0 - 30 / k, y0 - 30 / k, x1 + 30 / k, y1 + 30 / k)) continue;
      ax_ = SEG[0]; ay_ = SEG[1]; bx_ = SEG[2]; by_ = SEG[3];
    }
    visEdges++;
    if (anyRem && G.removed.has(l.i)) { ghosts.push(l); continue; }
    let color = edgeColor(l), alpha, width;
    if (hl) {
      if (hl.links.has(l.i)) { alpha = 0.95; width = l.struct ? 1.4 : 3; } else { alpha = 0.035; width = 0.7; }
    } else if (anyRem && reach1 && !reach1[l.t]) {
      alpha = 0.07; width = 0.8;
    } else { alpha = l.struct ? 0.16 : 0.55; width = l.struct ? 0.8 : 1.7; }
    width = Math.max(width, 0.7 / k);
    const key = color + alpha + '|' + width.toFixed(2);
    let bk = buckets.get(key);
    if (!bk) { bk = { color, alpha, width, paths: [new Path2D()], cur: 0, n: 0 }; buckets.set(key, bk); }
    if (bk.n >= CHUNK) { bk.paths.push(new Path2D()); bk.cur++; bk.n = 0; }
    const bp = bk.paths[bk.cur]; bk.n++;
    if (l.curve && k > 0.5 && inside) {
      const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
      bp.moveTo(a.x, a.y);
      bp.quadraticCurveTo((a.x + b.x) / 2 - dy / len * l.curve, (a.y + b.y) / 2 + dx / len * l.curve, b.x, b.y);
    } else { bp.moveTo(ax_, ay_); bp.lineTo(bx_, by_); }
    if (showArrows && alpha > 0.3 && !l.struct && vis[l.t]) {
      const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy);
      if (len > 1) {
        const ux = dx / len, uy = dy / len, sz = Math.min(12, Math.max(3.5, 8 / k));
        const tipx = b.x - ux * (b.r + 2), tipy = b.y - uy * (b.r + 2);
        const akey = color + alpha;
        let ab = arrowB.get(akey);
        if (!ab) { ab = { color, alpha, paths: [new Path2D()], cur: 0, n: 0 }; arrowB.set(akey, ab); }
        if (ab.n >= CHUNK) { ab.paths.push(new Path2D()); ab.cur++; ab.n = 0; }
        const ap = ab.paths[ab.cur]; ab.n++;
        ap.moveTo(tipx, tipy);
        ap.lineTo(tipx - ux * sz - uy * sz * 0.45, tipy - uy * sz + ux * sz * 0.45);
        ap.lineTo(tipx - ux * sz + uy * sz * 0.45, tipy - uy * sz - ux * sz * 0.45);
        ap.closePath();
      }
    }
  }
  P.edgeBuild = performance.now(); ctx.lineCap = 'round';
  buckets.forEach(bk => { ctx.globalAlpha = bk.alpha; ctx.strokeStyle = bk.color; ctx.lineWidth = bk.width; bk.paths.forEach(pp => ctx.stroke(pp)); });
  arrowB.forEach(ab => { ctx.globalAlpha = Math.min(1, ab.alpha + 0.1); ctx.fillStyle = ab.color; ab.paths.forEach(pp => ctx.fill(pp)); });

  mark('edgeStroke');
  /* animated path overlay */
  if (G.pathInfo) {
    ctx.globalAlpha = 1; ctx.lineWidth = 3.2 / Math.min(k, 1.5); ctx.setLineDash([9 / Math.min(k, 1.5), 6 / Math.min(k, 1.5)]);
    ctx.lineDashOffset = -(t / 45) / Math.min(k, 1.5);
    ctx.strokeStyle = '#ffffff'; ctx.beginPath();
    G.pathInfo.links.forEach(li => { const l = links[li], a = nodes[l.s], b = nodes[l.t]; ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); });
    ctx.stroke(); ctx.setLineDash([]);
  }
  /* removed (fixed) edges: red dashed ghost with an X */
  if (ghosts.length) {
    ctx.globalAlpha = 0.85; ctx.strokeStyle = '#ef4444'; ctx.lineWidth = Math.max(1.4, 1.6 / k); ctx.setLineDash([5 / k, 4 / k]);
    ctx.beginPath();
    ghosts.forEach(l => { const a = nodes[l.s], b = nodes[l.t]; ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); });
    ctx.stroke(); ctx.setLineDash([]);
    if (k > 0.35) {
      const s = Math.max(4, 6 / k); ctx.lineWidth = Math.max(1.5, 2 / k); ctx.beginPath();
      ghosts.forEach(l => { const a = nodes[l.s], b = nodes[l.t], mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2; ctx.moveTo(mx - s, my - s); ctx.lineTo(mx + s, my + s); ctx.moveTo(mx + s, my - s); ctx.lineTo(mx - s, my + s); });
      ctx.stroke();
    }
  }
  if (G.locate >= 0) {
    const l = links[G.locate], a = nodes[l.s], b = nodes[l.t], pulse = (Math.sin(t / 180) + 1) / 2;
    ctx.globalAlpha = 0.9; ctx.strokeStyle = '#facc15'; ctx.lineWidth = (3 + pulse * 3) / Math.min(k, 2);
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
  }

  /* nodes */
  ctx.globalAlpha = 1;
  const lowDetail = fast || k < 0.3 || visCount > 7000;
  const dimmedList = [], normalList = [], hotList = [];
  for (let i = 0; i < nodes.length; i++) {
    if (!vis[i]) continue;
    if (hl && !hl.nodes.has(i)) dimmedList.push(i);
    else if (hl) hotList.push(i);
    else normalList.push(i);
  }
  const drawSet = (list, alpha) => {
    if (!list.length) return;
    ctx.globalAlpha = alpha;
    if (lowDetail) {
      const dots = new Map();
      list.forEach(i => {
        const n = nodes[i], c = n.type === 'Cluster' ? NODE_COLORS[n.kind] || '#94a3b8' : (n.tier === 0 ? '#ef4444' : NODE_COLORS[n.type] || '#64748b');
        let p = dots.get(c); if (!p) { p = new Path2D(); dots.set(c, p); }
        const rr = Math.max(n.r * (n.tier === 0 ? 0.9 : 0.6), 2 / k);
        p.moveTo(n.x + rr, n.y); p.arc(n.x, n.y, rr, 0, 6.2832);
      });
      dots.forEach((p, c) => { ctx.fillStyle = c; ctx.fill(p); });
    } else {
      list.forEach(i => { const n = nodes[i], sz = SPR * n.r / SPR_R; ctx.drawImage(getSprite(n, spriteRes(sz * k * G.dpr)), n.x - sz / 2, n.y - sz / 2, sz, sz); });
    }
  };
  drawSet(dimmedList, 0.1); drawSet(normalList, 1); drawSet(hotList, 1);
  ctx.globalAlpha = 1;

  mark('nodes');
  /* rings: secured-by-fix, path ends, selection, hover */
  const ring = (i, color, wpx, extra) => { const n = nodes[i]; ctx.strokeStyle = color; ctx.lineWidth = wpx / k; ctx.beginPath(); ctx.arc(n.x, n.y, n.r + (extra || 5) / k + 2, 0, 6.2832); ctx.stroke(); };
  if (anyRem && reach1) {
    ctx.strokeStyle = '#22c55e'; ctx.lineWidth = 2 / k; ctx.beginPath();
    for (let i = 0; i < nodes.length; i++) if (vis[i] && G.reach0[i] && !reach1[i] && nodes[i].tier !== 0) { const n = nodes[i]; ctx.moveTo(n.x + n.r + 3, n.y); ctx.arc(n.x, n.y, n.r + 3, 0, 6.2832); }
    ctx.stroke();
  }
  if (G.pathStart >= 0) ring(G.pathStart, '#22c55e', 3, 7);
  if (G.pathEnd >= 0) ring(G.pathEnd, '#f97316', 3, 7);
  if (G.sel >= 0) ring(G.sel, '#ffffff', 2.2, 6);
  if (G.hover >= 0 && G.hover !== G.sel) ring(G.hover, '#60a5fa', 2, 4);
  ctx.restore();

  /* labels (screen space, collision-culled) */
  ctx.setTransform(G.dpr, 0, 0, G.dpr, 0, 0);
  ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic';
  if (k >= 0.4 && !fast) {
    ctx.font = '600 11px system-ui, sans-serif'; ctx.fillStyle = '#ffffff'; ctx.lineJoin = 'round';
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (n.type !== 'Cluster' || !vis[i] || (hl && !hl.nodes.has(i))) continue;
      ctx.fillText(String(n.count), n.x * k + tx, n.y * k + ty + 4);
    }
  }
  if (G.labels && !fast) {
    const cand = [];
    for (let i = 0; i < nodes.length; i++) {
      if (!vis[i]) continue;
      const n = nodes[i];
      let pr = 0;
      if (i === G.sel || i === G.hover || i === G.pathStart || i === G.pathEnd) pr = 100;
      else if (hl && hl.nodes.has(i) && k > 0.5) pr = 50 + n.score / 10;
      else if (hl && !hl.nodes.has(i)) continue;
      else if (n.tier === 0 && k >= 0.35) pr = 40;
      else if (k >= 1.1 && n.score > 25) pr = 20 + n.score / 10;
      else if (k >= 2.4) pr = 5;
      if (pr) cand.push([pr, i]);
    }
    cand.sort((a, b) => b[0] - a[0]);
    const taken = new Set(); let drawn = 0;
    ctx.font = '11px system-ui, sans-serif';
    for (const [pr, i] of cand) {
      if (drawn > 300) break;
      const n = nodes[i], sx = n.x * k + tx, sy = n.y * k + ty - n.r * k - 6;
      const key = Math.floor(sx / 150) + ':' + Math.floor(sy / 15);
      if (pr < 100 && taken.has(key)) continue;
      taken.add(key); drawn++;
      const txt = n.label.length > 24 ? n.label.slice(0, 22) + '..' : n.label;
      const tw = txt.length * 5.7 + 6;
      ctx.fillStyle = 'rgba(8,12,24,0.78)'; ctx.fillRect(sx - tw / 2, sy - 11, tw, 14);
      ctx.fillStyle = pr >= 100 ? '#ffffff' : n.tier === 0 ? '#fca5a5' : '#cbd5e1';
      ctx.fillText(txt, sx, sy);
    }
  }
  if (G.edgeLabels && k > 1.3) {
    ctx.font = '9px system-ui, sans-serif'; let c = 0;
    for (const l of links) {
      if (l.struct || isLinkHidden(l) || (hl && !hl.links.has(l.i))) continue;
      const a = nodes[l.s], b = nodes[l.t];
      if (!(vis[l.s] && vis[l.t])) continue;
      ctx.fillStyle = edgeColor(l);
      ctx.fillText(l.type, ((a.x + b.x) / 2) * k + tx, ((a.y + b.y) / 2) * k + ty - 3);
      if (++c > 250) break;
    }
  }
  mark('labels');
  drawMinimap();
  P.end = performance.now();
  const now = performance.now();
  if (now - G.lastHud > 500) { G.lastHud = now; updateHud(); }
}

/* ---------- HUD / minimap ---------- */
function updateHud() {
  const m = graphData.meta || {}, el = document.getElementById('graph-hud');
  let t = G.nodes.length.toLocaleString() + ' nodes | ' + G.links.length.toLocaleString() + ' edges | ' + Math.round(G.fps) + ' fps';
  if (m.hidden_in_clusters) t += '<br>' + m.hidden_in_clusters.toLocaleString() + ' leaf objects collapsed into clusters';
  if (m.truncated) t += '<br>Top ' + m.shown.toLocaleString() + ' of ' + m.in_paths.toLocaleString() + ' path-relevant nodes shown (use --graph-nodes to raise)';
  t += '<br>' + (m.graph_total || 0).toLocaleString() + ' objects in the AD graph | zoom ' + G.k.toFixed(2) + 'x';
  el.innerHTML = t;
}

function miniRebuild() {
  const mw = G.mini.width, mh = G.mini.height, nodes = G.nodes;
  if (!nodes.length) return;
  let ax = Infinity, bx = -Infinity, ay = Infinity, by = -Infinity;
  nodes.forEach(n => { if (n.x < ax) ax = n.x; if (n.x > bx) bx = n.x; if (n.y < ay) ay = n.y; if (n.y > by) by = n.y; });
  const bw = Math.max(1, bx - ax), bh = Math.max(1, by - ay), s = Math.min((mw - 12) / bw, (mh - 12) / bh);
  const ox = (mw - bw * s) / 2 - ax * s, oy = (mh - bh * s) / 2 - ay * s;
  const base = document.createElement('canvas'); base.width = mw; base.height = mh;
  const c = base.getContext('2d');
  nodes.forEach(n => { c.fillStyle = n.tier === 0 ? '#ef4444' : (NODE_COLORS[n.type] || '#64748b'); const r = n.tier === 0 ? 2.2 : 1.2; c.fillRect(n.x * s + ox - r / 2, n.y * s + oy - r / 2, r, r); });
  G.miniInfo = { s, ox, oy, base };
}

function drawMinimap() {
  const mi = G.miniInfo; if (!mi) return;
  const c = G.miniCtx, mw = G.mini.width, mh = G.mini.height;
  c.clearRect(0, 0, mw, mh); c.drawImage(mi.base, 0, 0);
  const x0 = (-G.tx / G.k) * mi.s + mi.ox, y0 = (-G.ty / G.k) * mi.s + mi.oy;
  c.strokeStyle = '#60a5fa'; c.lineWidth = 1.2; c.strokeRect(x0, y0, (G.w / G.k) * mi.s, (G.h / G.k) * mi.s);
}

function initMinimap() {
  const move = e => {
    const mi = G.miniInfo; if (!mi) return;
    const r = G.mini.getBoundingClientRect();
    const wx = ((e.clientX - r.left) * (G.mini.width / r.width) - mi.ox) / mi.s;
    const wy = ((e.clientY - r.top) * (G.mini.height / r.height) - mi.oy) / mi.s;
    G.userMoved = true;
    d3.select(G.canvas).call(G.zoom.transform, d3.zoomIdentity.translate(G.w / 2 - wx * G.k, G.h / 2 - wy * G.k).scale(G.k));
  };
  let down = false;
  G.mini.addEventListener('mousedown', e => { down = true; move(e); });
  window.addEventListener('mousemove', e => { if (down) move(e); });
  window.addEventListener('mouseup', () => { down = false; });
}

/* ---------- viewport helpers ---------- */
function fitGraph(animate) {
  if (!G.nodes.length) return;
  const xs = G.nodes.map(n => n.x).sort((a, b) => a - b), ys = G.nodes.map(n => n.y).sort((a, b) => a - b);
  const lo = Math.floor(xs.length * 0.01), hi = Math.max(lo, Math.ceil(xs.length * 0.99) - 1);
  const ax = xs[lo], bx = xs[hi], ay = ys[lo], by = ys[hi];
  const bw = Math.max(80, bx - ax), bh = Math.max(80, by - ay);
  const k = Math.min(G.w / (bw * 1.15), G.h / (bh * 1.2), 3);
  const tr = d3.zoomIdentity.translate(G.w / 2 - ((ax + bx) / 2) * k, G.h / 2 - ((ay + by) / 2) * k).scale(k);
  const s = d3.select(G.canvas);
  if (animate) s.transition().duration(450).call(G.zoom.transform, tr); else s.call(G.zoom.transform, tr);
}
function resetGraph() { G.userMoved = false; clearSelection(); fitGraph(true); }
function zoomToNode(arg) {
  if (!G.inited) drawGraph();
  const i = typeof arg === 'number' ? arg : G.idIndex.get(arg.id);
  if (i == null) return;
  const n = G.nodes[i], k = Math.max(G.k, 2.2);
  G.userMoved = true;
  d3.select(G.canvas).transition().duration(550).call(G.zoom.transform, d3.zoomIdentity.translate(G.w / 2 - n.x * k, G.h / 2 - n.y * k).scale(k));
  selectNode(i, true);
}
function zoomToBox(ids) {
  const ns = ids.map(i => G.nodes[i]); if (!ns.length) return;
  const ax = Math.min(...ns.map(n => n.x)), bx = Math.max(...ns.map(n => n.x)), ay = Math.min(...ns.map(n => n.y)), by = Math.max(...ns.map(n => n.y));
  const k = Math.min(G.w / (Math.max(120, bx - ax) * 1.4), G.h / (Math.max(120, by - ay) * 1.5), 4);
  G.userMoved = true;
  d3.select(G.canvas).transition().duration(550).call(G.zoom.transform, d3.zoomIdentity.translate(G.w / 2 - ((ax + bx) / 2) * k, G.h / 2 - ((ay + by) / 2) * k).scale(k));
}

/* ---------- controls ---------- */
function toggleLabels() { G.labels = !G.labels; requestDraw(); }
function toggleEdgeLabels() { G.edgeLabels = !G.edgeLabels; requestDraw(); }
function toggleStructural() { G.hideStruct = !G.hideStruct; showToast(G.hideStruct ? 'Hiding MemberOf / Contains edges' : 'Showing all edges'); requestDraw(); }
function toggleLayout() {
  G.hier = !G.hier;
  G.sim.force('y', d3.forceY(d => tierY(d.tier, G.spread)).strength(G.hier ? 0.22 : 0.04));
  G.sim.alpha(0.6); G.alpha0 = 0.6; G.layoutRunning = true; G.userMoved = false;
  document.getElementById('graph-loading').style.display = 'block';
  showToast(G.hier ? 'Tier layout: Tier 0 at the bottom' : 'Free layout');
  requestDraw();
}
function exportGraphPNG() {
  G.canvas.toBlob(b => { const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = 'pathcutter-graph.png'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000); });
}

/* ---------- tooltip ---------- */
function showTooltip(e, n) {
  const tt = document.getElementById('graph-tooltip');
  const c = NODE_COLORS[n.type] || '#64748b';
  let sub = n.type + ' - Tier ' + n.tier + (n.score > 0 ? ' - Risk: ' + n.score : '');
  if (n.type === 'Cluster') sub = n.count + ' ' + n.kind.toLowerCase() + 's, all with ' + esc(n.via) + ' to ' + n.target;
  tt.innerHTML = '<div class="tt-name" style="color:' + c + '">' + n.name + '</div><div class="tt-type">' + sub + '</div>';
  tt.style.display = 'block';
  const rect = document.getElementById('graph-container').getBoundingClientRect();
  tt.style.left = (e.clientX - rect.left + 14) + 'px'; tt.style.top = (e.clientY - rect.top - 8) + 'px';
}
function hideTooltip() { document.getElementById('graph-tooltip').style.display = 'none'; }

/* ---------- selection, highlight, paths ---------- */
function shortestPath(src, goalFn) {
  const n = G.nodes.length, prev = new Int32Array(n).fill(-2), pl = new Int32Array(n).fill(-1), q = [src];
  prev[src] = -1; let head = 0;
  while (head < q.length) {
    const u = q[head++];
    if (u !== src && goalFn(u)) {
      const ns = [u], ls = []; let c = u;
      while (prev[c] >= 0) { ls.push(pl[c]); c = prev[c]; ns.push(c); }
      return { nodes: ns.reverse(), links: ls.reverse() };
    }
    for (const li of G.out[u]) {
      const l = G.links[li];
      if (G.removed.has(li) || G.hiddenTypes.has(l.type)) continue;
      if (prev[l.t] !== -2) continue;
      prev[l.t] = u; pl[l.t] = li; q.push(l.t);
    }
  }
  return null;
}

function neighborhood(i, hops) {
  const nodes = new Set([i]); let frontier = [i];
  for (let h = 0; h < hops; h++) {
    const next = [];
    frontier.forEach(u => {
      G.out[u].forEach(li => { const v = G.links[li].t; if (!nodes.has(v)) { nodes.add(v); next.push(v); } });
      G.inn[u].forEach(li => { const v = G.links[li].s; if (!nodes.has(v)) { nodes.add(v); next.push(v); } });
    });
    frontier = next;
  }
  const links = new Set();
  G.links.forEach(l => { if (nodes.has(l.s) && nodes.has(l.t)) links.add(l.i); });
  return { nodes, links };
}

function setPathHighlight(p, title) {
  G.pathInfo = p;
  G.hl = { nodes: new Set(p.nodes), links: new Set(p.links) };
  showPathBar(p, title);
  zoomToBox(p.nodes);
  requestDraw();
}

function showPathBar(p, title) {
  const bar = document.getElementById('graph-pathbar');
  let h = '<div class="pb-head"><span>' + esc(title) + ' - ' + p.links.length + ' hop' + (p.links.length === 1 ? '' : 's') + '</span><button class="btn btn-sm btn-outline" id="pb-clear">Clear</button></div>';
  p.nodes.forEach((ni, j) => {
    const n = G.nodes[ni];
    h += '<div class="pb-step"><b style="color:' + (NODE_COLORS[n.type] || '#94a3b8') + '">' + n.name + '</b>';
    if (j < p.links.length) { const l = G.links[p.links[j]]; h += ' <span class="pb-edge" style="color:' + edgeColor(l) + '">' + esc(l.type) + ' &#8595;</span>'; }
    h += '</div>';
  });
  bar.innerHTML = h; bar.style.display = 'block';
  document.getElementById('pb-clear').onclick = clearSelection;
}

function clearSelection() {
  G.sel = -1; G.hl = null; G.pathInfo = null; G.pathStart = -1; G.pathEnd = -1; G.locate = -1;
  const d = document.querySelector('.node-detail'); if (d) d.remove();
  document.getElementById('graph-pathbar').style.display = 'none';
  requestDraw();
}
function resetHighlights() { clearSelection(); }

function selectNode(i, keepView) {
  G.sel = i; G.pathInfo = null; G.locate = -1;
  document.getElementById('graph-pathbar').style.display = 'none';
  const nb = neighborhood(i, 1), sp = shortestPath(i, u => G.nodes[u].tier === 0);
  if (sp) { sp.nodes.forEach(x => nb.nodes.add(x)); sp.links.forEach(x => nb.links.add(x)); }
  G.hl = nb;
  showNodeDetail(i, sp);
  requestDraw();
}

function showNodeDetail(i, sp) {
  const old = document.querySelector('.node-detail'); if (old) old.remove();
  const n = G.nodes[i];
  if (sp === undefined) sp = shortestPath(i, u => G.nodes[u].tier === 0);
  const div = document.createElement('div');
  div.className = 'node-detail'; div.onclick = e => e.stopPropagation();
  const c = NODE_COLORS[n.type] || '#64748b';
  let h = '<span class="close">&times;</span><h4 style="color:' + c + '">' + n.name + '</h4>';
  h += '<div class="stat"><span>Type</span><span>' + esc(n.type === 'Cluster' ? 'Cluster of ' + n.kind + 's' : n.type) + '</span></div>';
  h += '<div class="stat"><span>Tier</span><span class="tier-badge tier-' + n.tier + '">T' + n.tier + '</span></div>';
  h += '<div class="stat"><span>Risk score</span><span style="color:' + (n.score > 60 ? '#ef4444' : n.score > 30 ? '#eab308' : '#94a3b8') + '">' + n.score + '</span></div>';
  h += '<div class="stat"><span>Outbound / inbound edges</span><span>' + G.out[i].length + ' / ' + G.inn[i].length + '</span></div>';
  if (n.tier === 0) h += '<div class="stat"><span>Attack paths in</span><span>' + G.inn[i].length + ' direct</span></div>';
  else h += '<div class="stat"><span>To Tier 0</span><span style="color:' + (sp ? '#ef4444' : '#22c55e') + '">' + (sp ? sp.links.length + ' hops' : 'no path') + '</span></div>';
  if (n.type === 'Cluster') {
    h += '<div style="margin-top:8px;font-size:0.75rem;color:var(--text-dim)">' + n.count + ' ' + esc(n.kind.toLowerCase()) + 's share a single <b>' + esc(n.via) + '</b> edge to ' + n.target + '. Collapsed to keep the graph readable.</div><div class="member-list">';
    h += n.members.map(m => '<div>' + m + '</div>').join('');
    if (n.count > n.members.length) h += '<div style="color:var(--text-dimmer)">+ ' + (n.count - n.members.length) + ' more</div>';
    h += '</div>';
  } else if (G.out[i].length) {
    h += '<div class="path-list"><strong style="font-size:0.72rem;color:var(--text-dim)">OUTBOUND ATTACK EDGES</strong>';
    G.out[i].map(li => G.links[li]).filter(l => !l.struct).slice(0, 8).forEach(l => {
      h += '<div class="path-item"><span style="color:' + edgeColor(l) + '">' + esc(l.type) + '</span> &#8594; ' + G.nodes[l.t].name + '</div>';
    });
    h += '</div>';
  }
  h += '<div class="btn-row"><button class="btn btn-sm" data-a="t0">Path to Tier 0</button><button class="btn btn-sm btn-outline" data-a="start">Set path start</button><button class="btn btn-sm btn-outline" data-a="end">Set path end</button>' +
       '<button class="btn btn-sm btn-outline" data-a="iso1">1 hop</button><button class="btn btn-sm btn-outline" data-a="iso2">2 hops</button><button class="btn btn-sm btn-outline" data-a="explorer">Path Explorer</button></div>';
  div.innerHTML = h;
  div.querySelector('.close').onclick = clearSelection;
  div.querySelectorAll('button[data-a]').forEach(b => b.onclick = () => nodeAction(b.dataset.a, i));
  document.getElementById('graph-container').appendChild(div);
}

function nodeAction(a, i) {
  closeCtx();
  if (a === 't0') {
    const p = shortestPath(i, u => G.nodes[u].tier === 0);
    if (!p) { showToast('No path to Tier 0 from this node' + (G.removed.size ? ' (with the simulated fixes applied)' : '')); return; }
    G.sel = i; setPathHighlight(p, 'Shortest path to Tier 0');
  } else if (a === 'start') { G.pathStart = i; G.pathEnd = G.pathEnd === i ? -1 : G.pathEnd; showToast('Path start set. Right-click another node: Set path end.'); tryPair(); requestDraw(); }
  else if (a === 'end') { G.pathEnd = i; G.pathStart = G.pathStart === i ? -1 : G.pathStart; showToast('Path end set.'); tryPair(); requestDraw(); }
  else if (a === 'iso1' || a === 'iso2') { G.sel = i; G.pathInfo = null; G.hl = neighborhood(i, a === 'iso1' ? 1 : 2); zoomToBox([...G.hl.nodes]); requestDraw(); }
  else if (a === 'explorer') goToPath(G.nodes[i].label.split('@')[0]);
  else if (a === 'copyname') copyText(G.nodes[i].label);
  else if (a === 'copyid') copyText(G.nodes[i].id);
}

function tryPair() {
  if (G.pathStart < 0 || G.pathEnd < 0) return;
  const p = shortestPath(G.pathStart, u => u === G.pathEnd);
  if (!p) { showToast('No attack path between those two nodes'); return; }
  setPathHighlight(p, 'Shortest path');
}

function showContextMenu(e, n) {
  closeCtx();
  const menu = document.createElement('div');
  menu.className = 'ctx-menu';
  const rect = document.getElementById('graph-container').getBoundingClientRect();
  menu.style.left = Math.min(e.clientX - rect.left, G.w - 200) + 'px'; menu.style.top = Math.min(e.clientY - rect.top, G.h - 260) + 'px';
  const items = [['Show details', 'details'], ['Shortest path to Tier 0', 't0'], ['Set as path start', 'start'], ['Set as path end', 'end'], null,
                 ['Isolate 1 hop', 'iso1'], ['Isolate 2 hops', 'iso2'], ['Find in Path Explorer', 'explorer'], null, ['Copy name', 'copyname'], ['Copy SID / id', 'copyid']];
  let h = '<div style="padding:6px 14px;font-weight:600;color:' + (NODE_COLORS[n.type] || '#94a3b8') + ';font-size:0.85rem;border-bottom:1px solid var(--border)">' + n.name + '</div>';
  items.forEach(it => { h += it ? '<div class="ctx-item" data-a="' + it[1] + '">' + it[0] + '</div>' : '<div class="ctx-sep"></div>'; });
  menu.innerHTML = h;
  menu.querySelectorAll('[data-a]').forEach(el => el.onclick = ev => { ev.stopPropagation(); if (el.dataset.a === 'details') { closeCtx(); selectNode(n.i); } else nodeAction(el.dataset.a, n.i); });
  document.getElementById('graph-container').appendChild(menu);
}
function closeCtx() { const m = document.querySelector('.ctx-menu'); if (m) m.remove(); }

function goToPath(sourceName) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="paths"]').classList.add('active');
  document.getElementById('paths').classList.add('active');
  document.getElementById('path-search').value = sourceName;
  renderPathList(sourceName);
}

function highlightPathInGraph(nodeIds) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="graph"]').classList.add('active');
  document.getElementById('graph').classList.add('active');
  if (!G.inited) drawGraph();
  const idx = nodeIds.map(id => G.idIndex.get(id)).filter(v => v != null);
  const links = [];
  for (let j = 0; j + 1 < idx.length; j++) {
    const li = G.out[idx[j]].find(x => G.links[x].t === idx[j + 1]);
    if (li != null) links.push(li);
  }
  if (!idx.length) { showToast('This path is inside a collapsed cluster or outside the displayed graph'); return; }
  setTimeout(() => setPathHighlight({ nodes: idx, links }, 'Attack path'), 120);
}

/* ---------- fix simulation ---------- */
function graphSetApplied(idxSet) {
  if (!G.inited) { G.pendingApplied = new Set(idxSet); return; }
  G.applied = new Set(idxSet); G.removed = new Set();
  G.applied.forEach(i => { const li = fixesData[i] && fixesData[i].graph_link; if (li != null && li >= 0) G.removed.add(li); });
  G.reach1 = G.removed.size ? reverseReach(G.removed) : null;
  if (G.pathInfo) { G.pathInfo = null; G.hl = null; document.getElementById('graph-pathbar').style.display = 'none'; }
  updateSimPanel(); requestDraw();
}

function updateSimPanel() {
  const total = fixesData.length, sl = document.getElementById('gs-slider');
  let consecutive = 0; while (G.applied.has(consecutive)) consecutive++;
  if (consecutive === G.applied.size) sl.value = G.applied.size;
  document.getElementById('gs-count').textContent = G.applied.size + ' / ' + total;
  let atRisk = 0, secured = 0;
  G.nodes.forEach(n => { if (n.tier !== 0 && G.reach0[n.i]) { const wgt = n.count || 1; atRisk += wgt; if (G.reach1 && !G.reach1[n.i]) secured += wgt; } });
  const el = document.getElementById('gs-result');
  if (!G.applied.size) el.innerHTML = '<b style="color:var(--danger)">' + atRisk.toLocaleString() + '</b> objects can reach Tier 0. Drag to apply top fixes.';
  else el.innerHTML = '<b>' + secured.toLocaleString() + '</b> of ' + atRisk.toLocaleString() + ' exposed objects (' + (atRisk ? Math.round(secured / atRisk * 100) : 0) + '%) can no longer reach Tier 0. <span style="color:var(--text-dimmer)">' + (atRisk - secured).toLocaleString() + ' still can.</span>';
}

function initSimPanel() {
  const sl = document.getElementById('gs-slider');
  sl.max = fixesData.length;
  if (!fixesData.length) document.getElementById('graph-sim').style.display = 'none';
  sl.addEventListener('input', () => {
    const v = parseInt(sl.value, 10);
    if (window.whatifApplyTopN) whatifApplyTopN(v); else graphSetApplied(new Set(Array.from({ length: v }, (_, i) => i)));
  });
  const sel = document.getElementById('gs-locate');
  fixesData.forEach((f, i) => { const o = document.createElement('option'); o.value = i; o.textContent = '#' + f.rank + '  ' + dec(f.source) + ' -> ' + dec(f.target) + ' [' + f.edge_type + ']'; sel.appendChild(o); });
  sel.addEventListener('change', () => { if (sel.value !== '') locateFix(parseInt(sel.value, 10)); });
  G.applied = G.pendingApplied || new Set();
  graphSetApplied(G.applied);
}

function locateFix(i) {
  const f = fixesData[i], li = f && f.graph_link;
  if (li == null || li < 0) { showToast('That edge is not shown on the graph (outside the displayed nodes)'); return; }
  const l = G.links[li];
  G.sel = -1; G.pathInfo = null; G.locate = li;
  G.hl = { nodes: new Set([l.s, l.t]), links: new Set([li]) };
  zoomToBox([l.s, l.t]); requestDraw();
}

/* ---------- search ---------- */
function initSearch() {
  const input = document.getElementById('graph-search-input'), results = document.getElementById('graph-search-results');
  let activeIdx = -1;
  input.addEventListener('input', () => {
    const q = input.value.toLowerCase().trim();
    results.innerHTML = ''; activeIdx = -1;
    if (q.length < 2) { results.style.display = 'none'; return; }
    const found = [];
    for (const n of G.nodes) { if (n.lc.includes(q)) found.push([n, null]); if (found.length >= 12) break; }
    if (found.length < 12) for (const n of G.nodes) {
      if (n.type !== 'Cluster') continue;
      const m = n.members.find(x => dec(x).toLowerCase().includes(q));
      if (m) found.push([n, m]); if (found.length >= 12) break;
    }
    if (!found.length) { results.style.display = 'none'; return; }
    found.forEach(([n, member], i) => {
      const div = document.createElement('div'); div.className = 'sr';
      div.innerHTML = '<span>' + (member ? member + ' <span class="sr-type">in ' + n.name + '</span>' : n.name) + '</span><span class="sr-type">' + esc(n.type) + ' T' + n.tier + '</span>';
      div.addEventListener('click', () => { results.style.display = 'none'; input.value = member ? dec(member) : n.label; zoomToNode(n.i); });
      div.addEventListener('mouseenter', () => { results.querySelectorAll('.sr').forEach(s => s.classList.remove('active')); div.classList.add('active'); activeIdx = i; });
      results.appendChild(div);
    });
    results.style.display = 'block';
  });
  input.addEventListener('keydown', e => {
    const items = results.querySelectorAll('.sr'); if (!items.length) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); activeIdx = Math.min(activeIdx + 1, items.length - 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); activeIdx = Math.max(activeIdx - 1, 0); }
    else if (e.key === 'Enter') { e.preventDefault(); items[Math.max(0, activeIdx)].click(); return; }
    else if (e.key === 'Escape') { results.style.display = 'none'; return; }
    else return;
    items.forEach(s => s.classList.remove('active')); if (activeIdx >= 0) items[activeIdx].classList.add('active');
  });
  document.addEventListener('click', e => { if (!e.target.closest('#graph-search')) results.style.display = 'none'; });
}

/* ---------- edge type filter ---------- */
let edgeFilterVisible = false;
function toggleEdgeFilter() {
  edgeFilterVisible = !edgeFilterVisible;
  const panel = document.getElementById('edge-filter');
  if (edgeFilterVisible) { buildEdgeFilter(); panel.style.display = 'block'; } else panel.style.display = 'none';
}
function buildEdgeFilter() {
  const panel = document.getElementById('edge-filter');
  if (!G.inited) drawGraph();
  const counts = {};
  G.links.forEach(l => { counts[l.type] = (counts[l.type] || 0) + 1; });
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  let h = '<div class="ef-title">EDGE FILTERS</div><label style="margin-bottom:4px"><input type="checkbox" id="ef-all" checked> <strong>All</strong></label><div class="ef-sep"></div>';
  sorted.forEach(([t, c]) => {
    h += '<label><input type="checkbox" data-edge="' + esc(t) + '"' + (G.hiddenTypes.has(t) ? '' : ' checked') + '><span style="width:14px;height:3px;background:' + (EDGE_COLORS[t] || '#475569') + ';display:inline-block;border-radius:2px"></span><span>' + esc(t) + '</span> <span style="color:var(--text-dimmer)">(' + c + ')</span></label>';
  });
  panel.innerHTML = h;
  panel.querySelectorAll('input[data-edge]').forEach(cb => cb.addEventListener('change', () => { if (cb.checked) G.hiddenTypes.delete(cb.dataset.edge); else G.hiddenTypes.add(cb.dataset.edge); requestDraw(); }));
  document.getElementById('ef-all').addEventListener('change', e => {
    panel.querySelectorAll('input[data-edge]').forEach(cb => { cb.checked = e.target.checked; if (e.target.checked) G.hiddenTypes.delete(cb.dataset.edge); else G.hiddenTypes.add(cb.dataset.edge); });
    requestDraw();
  });
}
