// Run by tests/test_phase7b.py with node: exercises the force layout without a browser. Prints one JSON line.
import { forceLayout } from "../../dashboard/static/js/layout.js";

const clone = (o) => JSON.parse(JSON.stringify(o));
const dist = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
const opts = { width: 900, height: 560, iterations: 300 };

// two tight clusters (a-b-c triangle, d-e-f triangle) plus an isolated node
const nodes = ["a", "b", "c", "d", "e", "f", "z"].map((id) => ({ id, count: 1 }));
const edges = [["a", "b"], ["b", "c"], ["a", "c"], ["d", "e"], ["e", "f"], ["d", "f"]].map(([source, target]) => ({ source, target, count: 1 }));
const first = forceLayout(clone(nodes), edges, opts);
const second = forceLayout(clone(nodes), edges, opts);
const byId = Object.fromEntries(first.map((n) => [n.id, n]));

const big = Array.from({ length: 200 }, (_, i) => ({ id: `n${i}`, count: 1 }));
const bigEdges = Array.from({ length: 400 }, (_, i) => ({ source: `n${i % 200}`, target: `n${(i * 7 + 3) % 200}`, count: 1 }));
const t0 = performance.now();
const laid = forceLayout(clone(big), bigEdges, opts);
const ms = performance.now() - t0;

const starNodes = [...Array.from({ length: 5 }, (_, i) => ({ id: `s${i}`, count: 50 })), ...Array.from({ length: 200 }, (_, i) => ({ id: `t${i}`, count: 3 }))];
const starEdges = Array.from({ length: 200 }, (_, i) => ({ source: `s${i % 5}`, target: `t${i}`, count: 3 }));
const star = forceLayout(clone(starNodes), starEdges, opts);
const pinned = star.filter((n) => n.x <= 30.01 || n.x >= 869.99 || n.y <= 30.01 || n.y >= 529.99).length;

const same = forceLayout([{ id: "x" }, { id: "y" }], [], opts); // identical start must not collapse
const single = forceLayout([{ id: "only" }], [], opts);

console.log(
  JSON.stringify({
    deterministic: JSON.stringify(first) === JSON.stringify(second),
    inBounds: first.every((n) => n.x >= 0 && n.x <= 900 && n.y >= 0 && n.y <= 560) && laid.every((n) => Number.isFinite(n.x) && n.x >= 0 && n.x <= 900 && n.y >= 0 && n.y <= 560),
    clustersTighter: dist(byId.a, byId.b) < dist(byId.a, byId.e) && dist(byId.d, byId.e) < dist(byId.d, byId.b),
    noOverlap: laid.every((n, i) => laid.slice(i + 1).every((m) => dist(n, m) >= 10)),
    twoNodesApart: dist(same[0], same[1]) > 20,
    singleCentered: single[0].x === 450 && single[0].y === 280,
    empty: forceLayout([], [], opts).length === 0,
    starMostlyInside: pinned <= star.length * 0.05,
    starNoOverlap: star.every((n, i) => star.slice(i + 1).every((m) => dist(n, m) >= 10)),
    ms200: ms,
  }),
);
