// Attack graph: source -> target nodes for the current filter, drawn as SVG with a hand-written force layout.
import { api } from "../api.js";
import { clear, h, svg } from "../dom.js";
import { forceLayout } from "../layout.js";
import { fmtNumber, go, hashFor, isoMinus } from "../util.js";

const W = 900;
const H = 560;
const LABELLED_NODES = 15;
const THREATS = ["PORT_SCAN", "SYN_FLOOD", "VOLUMETRIC", "ML_ANOMALY"];
const RANGES = [["1h", 3600e3], ["6h", 6 * 3600e3], ["24h", 24 * 3600e3], ["7d", 7 * 24 * 3600e3]];
const FILTERS = ["threat_type", "severity", "source_ip", "destination_ip", "since", "until", "status", "dport", "q", "scan_type"];

export function renderGraph(main, params) {
  const filters = {};
  for (const key of FILTERS) if (params.get(key)) filters[key] = params.get(key);
  const note = h("p", { class: "muted", role: "status" }, "Loading…");
  const stage = h("div", { class: "panel" });
  const list = h("div", { class: "panel" });
  let disposed = false;

  const apply = (changes) => go("/graph", { ...filters, ...changes }, { replace: true });
  const select = (key, label, options) =>
    h("div", { class: "field" }, h("label", { for: `g-${key}` }, label), h("select", { id: `g-${key}`, onChange: (e) => apply({ [key]: e.target.value }) }, h("option", { value: "" }, "Any"), ...options.map((o) => h("option", { value: o, selected: filters[key] === o }, o))));

  const controls = h(
    "div",
    { class: "panel row" },
    select("threat_type", "Threat type", THREATS),
    select("severity", "Severity", ["HIGH", "MEDIUM", "LOW"]),
    h("div", { class: "row", role: "group", "aria-label": "Time range" }, ...RANGES.map(([label, ms]) => h("button", { class: "btn btn-sm", type: "button", onClick: () => apply({ since: isoMinus(ms), until: "" }) }, `Last ${label}`))),
    h("a", { class: "btn btn-sm", href: hashFor("/alerts", filters) }, "Edit all filters in the alert list"),
  );

  function draw(data) {
    const nodes = data.nodes.map((n) => ({ ...n }));
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    forceLayout(nodes, data.edges, { width: W, height: H, iterations: reduced ? 200 : 300 });
    const max = Math.max(1, ...nodes.map((n) => n.count));
    const radius = (n) => 5 + 11 * Math.sqrt(n.count / max);
    const maxEdge = Math.max(1, ...data.edges.map((e) => e.count));
    const root = svg("svg", { class: "graph", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Attack graph with ${nodes.length} hosts and ${data.edges.length} connections. A table of hosts follows.` });
    for (const e of data.edges) {
      const a = byId.get(e.source);
      const b = byId.get(e.target);
      root.append(svg("line", { class: `edge edge-${e.threat_type}`, x1: a.x.toFixed(1), y1: a.y.toFixed(1), x2: b.x.toFixed(1), y2: b.y.toFixed(1), "stroke-width": (1 + 3 * (e.count / maxEdge)).toFixed(2) }, svg("title", null, `${e.source} → ${e.target}: ${e.count} ${e.threat_type}`)));
    }
    const top = new Set(nodes.slice(0, LABELLED_NODES).map((n) => n.id));
    for (const n of nodes) {
      const circle = svg("circle", { class: `node node-${n.role}`, cx: n.x.toFixed(1), cy: n.y.toFixed(1), r: radius(n).toFixed(1), onClick: () => filterBy(n) }, svg("title", null, `${n.id}: ${n.count} alerts (${n.role})`));
      root.append(circle);
      if (top.has(n.id)) root.append(svg("text", { class: "node-label", x: (n.x + radius(n) + 3).toFixed(1), y: (n.y + 4).toFixed(1) }, n.id));
    }
    const used = THREATS.filter((t) => data.edges.some((e) => e.threat_type === t));
    const legend = h("ul", { class: "legend", "aria-label": "Edge legend" }, ...used.map((t) => h("li", null, svg("svg", { width: 40, height: 10, "aria-hidden": "true" }, svg("line", { class: `edge edge-${t}`, x1: 0, y1: 5, x2: 40, y2: 5, "stroke-width": 3 })), ` ${t}`)), h("li", { class: "muted" }, "Node size = alert count. Click a node to filter the alert list."));
    clear(stage).append(root, legend);

    const rows = nodes.map((n) =>
      h("tr", null, h("td", { class: "mono" }, n.id), h("td", null, fmtNumber(n.count)), h("td", null, n.role),
        h("td", null, h("button", { class: "btn btn-sm", type: "button", disabled: n.role === "target", onClick: () => go("/alerts", { ...filters, source_ip: n.id }) }, "Alerts from")),
        h("td", null, h("button", { class: "btn btn-sm", type: "button", disabled: n.role === "source", onClick: () => go("/alerts", { ...filters, destination_ip: n.id }) }, "Alerts to"))),
    );
    clear(list).append(h("h2", null, "Hosts"), h("div", { class: "table-wrap live-scroll", tabindex: "0", role: "region", "aria-label": "Hosts in the graph" }, h("table", null, h("thead", null, h("tr", null, ...["Host", "Alerts", "Role", "", ""].map((t) => h("th", { scope: "col" }, t)))), h("tbody", null, ...rows))));
    note.textContent = `${nodes.length} hosts, ${data.edges.length} connections since ${new Date(data.since).toLocaleString(undefined, { hour12: false })}.${data.truncated ? ` Showing the top ${nodes.length} of ${data.total_nodes} hosts.` : ""}`;
  }

  function filterBy(node) {
    // a node that attacks is filtered as a source; a pure target as a destination
    if (node.role === "target") go("/alerts", { ...filters, destination_ip: node.id });
    else go("/alerts", { ...filters, source_ip: node.id });
  }

  clear(main).append(h("div", { class: "page-head" }, h("h1", null, "Attack graph"), note), controls, stage, list);
  api.get("/api/v1/graph", filters)
    .then(({ data }) => {
      if (disposed) return;
      if (!data.nodes.length) {
        clear(stage).append(h("p", { class: "empty" }, "No connections match this filter."));
        clear(list);
        note.textContent = "";
        return;
      }
      draw(data);
    })
    .catch(() => {
      note.textContent = "Could not load the graph.";
    });
  return () => {
    disposed = true;
  };
}
