// Small force-directed layout (Fruchterman-Reingold style), written for this console: no library.
// Pure and deterministic (nodes start on a circle in input order), so it can be unit tested without a DOM.
export function forceLayout(nodes, edges, { width = 900, height = 560, iterations = 300, padding = 30, minGap = 12 } = {}) {
  const n = nodes.length;
  if (n === 0) return nodes;
  const index = new Map(nodes.map((node, i) => [node.id, i]));
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) / 2 - padding;
  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / n;
    node.x = cx + radius * 0.8 * Math.cos(angle);
    node.y = cy + radius * 0.8 * Math.sin(angle);
  });
  if (n === 1) {
    nodes[0].x = cx;
    nodes[0].y = cy;
    return nodes;
  }
  const seen = new Set();
  const links = [];
  for (const e of edges) {
    // one spring per host pair, however many threat types connect them
    if (!index.has(e.source) || !index.has(e.target) || e.source === e.target) continue;
    const key = e.source < e.target ? `${e.source}|${e.target}` : `${e.target}|${e.source}`;
    if (seen.has(key)) continue;
    seen.add(key);
    links.push([index.get(e.source), index.get(e.target)]);
  }
  const k = Math.sqrt((width * height) / n) * (n < 40 ? 0.8 : 0.4);
  const cutoff = k * 6;
  const dx = new Float64Array(n);
  const dy = new Float64Array(n);
  for (let iter = 0; iter < iterations; iter += 1) {
    dx.fill(0);
    dy.fill(0);
    for (let i = 0; i < n; i += 1) {
      for (let j = i + 1; j < n; j += 1) {
        let ex = nodes[i].x - nodes[j].x;
        let ey = nodes[i].y - nodes[j].y;
        let dist = Math.hypot(ex, ey);
        if (dist < 0.01) {
          ex = ((i * 7 + j) % 5) - 2 || 1; // coincident nodes: deterministic nudge
          ey = ((i + j * 3) % 5) - 2 || 1;
          dist = Math.hypot(ex, ey);
        }
        if (dist > cutoff) continue; // long-range repulsion would push everything to the border
        const force = (k * k) / dist;
        const fx = (ex / dist) * force;
        const fy = (ey / dist) * force;
        dx[i] += fx;
        dy[i] += fy;
        dx[j] -= fx;
        dy[j] -= fy;
      }
    }
    for (const [a, b] of links) {
      const ex = nodes[a].x - nodes[b].x;
      const ey = nodes[a].y - nodes[b].y;
      const dist = Math.max(Math.hypot(ex, ey), 0.01);
      const force = (dist * dist) / k;
      const fx = (ex / dist) * force;
      const fy = (ey / dist) * force;
      dx[a] -= fx;
      dy[a] -= fy;
      dx[b] += fx;
      dy[b] += fy;
    }
    const temperature = (Math.min(width, height) / 20) * (1 - iter / iterations) + 0.5;
    for (let i = 0; i < n; i += 1) {
      dx[i] += (cx - nodes[i].x) * 0.12; // gentle gravity keeps disconnected components on screen
      dy[i] += (cy - nodes[i].y) * 0.12;
      const len = Math.max(Math.hypot(dx[i], dy[i]), 0.01);
      const step = Math.min(len, temperature);
      nodes[i].x = Math.min(width - padding, Math.max(padding, nodes[i].x + (dx[i] / len) * step));
      nodes[i].y = Math.min(height - padding, Math.max(padding, nodes[i].y + (dy[i] / len) * step));
    }
  }
  separate(nodes, { width, height, padding, minGap });
  fit(nodes, { width, height, padding });
  return nodes;
}

// Scale the finished layout up (never down) so it uses the available area.
function fit(nodes, { width, height, padding }) {
  const xs = nodes.map((n) => n.x);
  const ys = nodes.map((n) => n.y);
  const minX = Math.min(...xs);
  const minY = Math.min(...ys);
  const bw = Math.max(...xs) - minX;
  const bh = Math.max(...ys) - minY;
  const scales = [];
  if (bw > 0) scales.push((width - 2 * padding) / bw);
  if (bh > 0) scales.push((height - 2 * padding) / bh);
  if (!scales.length) return;
  const scale = Math.max(1, Math.min(...scales));
  const offsetX = (width - bw * scale) / 2;
  const offsetY = (height - bh * scale) / 2;
  for (const n of nodes) {
    n.x = offsetX + (n.x - minX) * scale;
    n.y = offsetY + (n.y - minY) * scale;
  }
}

// Final pass: nodes pinned against the border (or stacked) are pushed apart until none is closer than minGap.
function separate(nodes, { width, height, padding, minGap }) {
  const n = nodes.length;
  for (let pass = 0; pass < 120; pass += 1) {
    let moved = false;
    for (let i = 0; i < n; i += 1) {
      for (let j = i + 1; j < n; j += 1) {
        let ex = nodes[i].x - nodes[j].x;
        let ey = nodes[i].y - nodes[j].y;
        let d = Math.hypot(ex, ey);
        if (d >= minGap) continue;
        if (d < 0.01) {
          ex = (i % 2 ? 1 : -1) * (1 + (i % 3));
          ey = (j % 2 ? 1 : -1) * (1 + (j % 3));
          d = Math.hypot(ex, ey);
        }
        const push = (minGap - d) / 2 + 0.5;
        nodes[i].x = Math.min(width - padding, Math.max(padding, nodes[i].x + (ex / d) * push));
        nodes[i].y = Math.min(height - padding, Math.max(padding, nodes[i].y + (ey / d) * push));
        nodes[j].x = Math.min(width - padding, Math.max(padding, nodes[j].x - (ex / d) * push));
        nodes[j].y = Math.min(height - padding, Math.max(padding, nodes[j].y - (ey / d) * push));
        moved = true;
      }
    }
    if (!moved) return;
  }
}
