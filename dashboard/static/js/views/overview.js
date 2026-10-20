import { api, bus } from "../api.js";
import { clear, h, svg } from "../dom.js";
import { fmtNumber, fmtPercent, go, hashFor, isoMinus } from "../util.js";

const REFRESH_MS = 30000;
const W = 800;
const H = 170;
const PAD = { l: 38, r: 8, t: 8, b: 22 };
const RANGES = [
  ["1h", 3600e3],
  ["6h", 6 * 3600e3],
  ["24h", 24 * 3600e3],
  ["7d", 7 * 24 * 3600e3],
];

export function renderOverview(main, params) {
  const since = params.get("since") || "";
  const until = params.get("until") || "";
  const rangeParams = { since, until };
  const tiles = h("div", { class: "grid grid-kpi" });
  const timelineBox = h("div", { class: "panel" });
  const sourcesBox = h("div", { class: "panel" });
  const portsBox = h("div", { class: "panel" });
  const live = h("p", { class: "muted", id: "overview-meta" });
  let metrics = null;
  let latest = null;
  let disposed = false;

  const linkTo = (extra) => hashFor("/alerts", { ...rangeParams, ...extra });

  function kpi(label, value, sub, href, cls = "") {
    const body = [h("div", { class: "kpi-label" }, label), h("div", { class: "kpi-value" }, value), h("div", { class: "kpi-sub" }, sub)];
    return href ? h("a", { class: `kpi ${cls}`, href }, ...body) : h("div", { class: `kpi ${cls}` }, ...body);
  }

  function renderTiles() {
    const o = latest;
    if (!o) return;
    const drop = metrics && metrics.received ? metrics.dropped / metrics.received : null;
    clear(tiles).append(
      ...["HIGH", "MEDIUM", "LOW"].map((sev) =>
        kpi(`${sev} alerts`, fmtNumber(o.severity[sev]), "in selected window", linkTo({ severity: sev }), `kpi-${sev}`),
      ),
      kpi("Open", fmtNumber(o.open), `${fmtNumber(o.triage.new)} new · ${fmtNumber(o.resolved)} resolved`, linkTo({ status: "new" })),
      kpi("Sensor throughput", metrics ? `${fmtNumber(metrics.pps_10s)} pps` : "–", metrics && metrics.sensor_online ? "sensor online" : "sensor offline", "#/health"),
      kpi("Drop rate", fmtPercent(drop), metrics ? `${fmtNumber(metrics.dropped)} of ${fmtNumber(metrics.received)} packets` : "–", "#/health"),
    );
  }

  function rangeButtons() {
    return h(
      "div",
      { class: "row", role: "group", "aria-label": "Time range" },
      ...RANGES.map(([label, ms]) =>
        h("button", { class: "btn btn-sm", type: "button", onClick: () => go("/overview", { since: isoMinus(ms) }, { replace: true }) }, `Last ${label}`),
      ),
      since || until ? h("button", { class: "btn btn-sm", type: "button", onClick: () => go("/overview", {}, { replace: true }) }, "Clear selection") : null,
      h("a", { class: "btn btn-sm", href: linkTo({}) }, "View alerts in range"),
    );
  }

  function renderTimeline() {
    const o = latest;
    if (!o) return;
    const points = o.timeline;
    const t0 = Date.parse(o.since);
    const t1 = Date.parse(o.until);
    const span = Math.max(1, t1 - t0);
    const max = Math.max(1, ...points.map((p) => p.count));
    const plotW = W - PAD.l - PAD.r;
    const plotH = H - PAD.t - PAD.b;
    const x = (t) => PAD.l + ((t - t0) / span) * plotW;
    const barW = Math.max(1.5, (o.bucket_minutes * 60e3 / span) * plotW - 0.5);
    const root = svg("svg", { class: "timeline", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Alerts per ${o.bucket_minutes} minute(s), ${o.total} in total. Drag to select a time range.` });
    root.append(svg("line", { class: "axis", x1: PAD.l, x2: W - PAD.r, y1: H - PAD.b, y2: H - PAD.b }));
    for (const p of points) {
      const bh = (p.count / max) * plotH;
      root.append(svg("rect", { class: "bar", x: x(Date.parse(p.t)).toFixed(1), y: (H - PAD.b - bh).toFixed(1), width: barW.toFixed(1), height: bh.toFixed(1) }, svg("title", null, `${p.t}: ${p.count}`)));
    }
    root.append(
      svg("text", { x: 4, y: PAD.t + 8 }, String(max)),
      svg("text", { x: 4, y: H - PAD.b }, "0"),
      svg("text", { x: PAD.l, y: H - 6 }, new Date(t0).toLocaleString(undefined, { hour12: false })),
      svg("text", { x: W - PAD.r, y: H - 6, "text-anchor": "end" }, new Date(t1).toLocaleString(undefined, { hour12: false })),
    );
    const brush = svg("rect", { class: "brush", x: 0, y: PAD.t, width: 0, height: plotH, visibility: "hidden" });
    root.append(brush);

    let startX = null;
    const toSvgX = (e) => {
      const box = root.getBoundingClientRect();
      return Math.min(W - PAD.r, Math.max(PAD.l, ((e.clientX - box.left) / box.width) * W));
    };
    const toTime = (px) => new Date(t0 + ((px - PAD.l) / plotW) * span);
    root.addEventListener("pointerdown", (e) => {
      startX = toSvgX(e);
      root.setPointerCapture(e.pointerId);
      brush.setAttribute("visibility", "visible");
      brush.setAttribute("x", startX);
      brush.setAttribute("width", 0);
    });
    root.addEventListener("pointermove", (e) => {
      if (startX === null) return;
      const cx = toSvgX(e);
      brush.setAttribute("x", Math.min(startX, cx));
      brush.setAttribute("width", Math.abs(cx - startX));
    });
    root.addEventListener("pointerup", (e) => {
      if (startX === null) return;
      const endX = toSvgX(e);
      const a = Math.min(startX, endX);
      const b = Math.max(startX, endX);
      startX = null;
      brush.setAttribute("visibility", "hidden");
      if (b - a < 4) return;
      const iso = (d) => d.toISOString().replace(/\.\d+Z$/, "Z");
      go("/overview", { since: iso(toTime(a)), until: iso(toTime(b)) }, { replace: true });
    });
    clear(timelineBox).append(h("h2", null, "Alerts over time"), rangeButtons(), root);
  }

  function bars(box, title, items, filterKey) {
    const max = Math.max(1, ...items.map((i) => i.count));
    const list = h("ul", { class: "barlist" });
    for (const item of items) {
      const fill = h("span", { class: "fill" });
      fill.style.setProperty("--w", `${(item.count / max) * 100}%`);
      list.append(
        h(
          "li",
          null,
          h(
            "button",
            { type: "button", "aria-label": `${item.value} ${fmtNumber(item.count)} alerts. Filter the alert list.`, onClick: () => go("/alerts", { ...rangeParams, [filterKey]: item.value }) },
            h("span", { class: "mono" }, String(item.value)),
            " ",
            h("span", { class: "track" }, fill),
            " ",
            h("span", null, fmtNumber(item.count)),
          ),
        ),
      );
    }
    clear(box).append(h("h2", null, title), items.length ? list : h("p", { class: "empty" }, "No data in this window."));
  }

  async function load() {
    try {
      const [{ data: overview }, { data: m }] = await Promise.all([api.get("/api/v1/overview", rangeParams), api.get("/api/v1/metrics")]);
      if (disposed) return;
      latest = overview;
      metrics = m;
      renderTiles();
      renderTimeline();
      bars(sourcesBox, "Top sources", overview.top_sources, "source_ip");
      bars(portsBox, "Top targeted ports", overview.top_ports, "dport");
      live.textContent = `${fmtNumber(overview.total)} alerts from ${new Date(overview.since).toLocaleString(undefined, { hour12: false })} to ${new Date(overview.until).toLocaleString(undefined, { hour12: false })}.`;
    } catch {
      /* api.js already toasts 403/429 and routes 401 to the login screen */
    }
  }

  const onMetrics = (e) => {
    metrics = { ...(metrics || {}), ...e.detail };
    renderTiles();
  };
  bus.addEventListener("stream:metrics", onMetrics);
  const timer = setInterval(load, REFRESH_MS);

  clear(main).append(h("div", { class: "page-head" }, h("h1", null, "Overview"), live), tiles, timelineBox, h("div", { class: "grid grid-2" }, sourcesBox, portsBox));
  load();
  return () => {
    disposed = true;
    clearInterval(timer);
    bus.removeEventListener("stream:metrics", onMetrics);
  };
}
