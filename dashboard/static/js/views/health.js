// Sensor health: current numbers, 30-minute sparklines, offline banner and a drop-rate warning.
import { api, bus } from "../api.js";
import { clear, h, svg } from "../dom.js";
import { fmtNumber, fmtPercent, fmtTime, loadFailure } from "../util.js";

const REFRESH_MS = 10000;
const SW = 320;
const SH = 70;

function sparkline(label, values, unit) {
  const max = Math.max(1, ...values);
  const min = Math.min(0, ...values);
  const span = max - min || 1;
  const step = values.length > 1 ? (SW - 6) / (values.length - 1) : 0;
  const points = values.map((v, i) => `${(3 + i * step).toFixed(1)},${(SH - 4 - ((v - min) / span) * (SH - 10)).toFixed(1)}`).join(" ");
  const last = values.length ? values[values.length - 1] : null;
  return h(
    "div",
    { class: "panel" },
    h("h2", null, label),
    h("div", { class: "kpi-value" }, last === null ? "–" : `${fmtNumber(Math.round(last * 10) / 10)}${unit}`),
    svg(
      "svg",
      { class: "spark", viewBox: `0 0 ${SW} ${SH}`, role: "img", "aria-label": `${label} over the last 30 minutes: latest ${last === null ? "no data" : Math.round(last * 10) / 10}, minimum ${Math.min(...values, 0)}, maximum ${max}` },
      svg("polyline", { class: "spark-line", points, fill: "none" }),
    ),
    h("div", { class: "kpi-sub" }, `min ${fmtNumber(Math.round(Math.min(...(values.length ? values : [0])) * 10) / 10)} · max ${fmtNumber(Math.round(max * 10) / 10)}`),
  );
}

export function renderHealth(main) {
  const banners = h("div");
  const loadError = h("p", { class: "banner", role: "alert", id: "load-error", hidden: true });
  const numbers = h("div", { class: "grid grid-kpi" });
  const charts = h("div", { class: "grid grid-2" });
  const meta = h("p", { class: "muted" });
  let disposed = false;
  let latest = null;

  function paintNumbers(m) {
    clear(numbers).append(
      ...[
        ["Sensor", m.sensor_online ? "Online" : "Offline", m.last_seen ? `last heartbeat ${fmtTime(m.last_seen)}` : "no heartbeat yet"],
        ["Packets received", fmtNumber(m.received), "since sensor start"],
        ["Packets dropped", fmtNumber(m.dropped), "queue full"],
        ["Queue depth", fmtNumber(m.queue_depth), "packets waiting"],
        ["Tracked state", fmtNumber(m.state_size), `${fmtNumber(m.evictions)} evictions`],
        ["Webhook failures", fmtNumber(m.webhook_failures), "since sensor start"],
      ].map(([label, value, sub]) => h("div", { class: "kpi" }, h("div", { class: "kpi-label" }, label), h("div", { class: "kpi-value" }, value), h("div", { class: "kpi-sub" }, sub))),
    );
    const out = [];
    if (!m.sensor_online) out.push(h("p", { class: "banner", role: "alert" }, "The sensor is offline: no heartbeat in the last 30 seconds. Alerts will not appear until it is back."));
    clear(banners).append(...out);
  }

  async function load() {
    try {
      const [{ data: m }, { data: hist }] = await Promise.all([api.get("/api/v1/sensor/status"), api.get("/api/v1/sensor/history", { minutes: 30 })]);
      if (disposed) return;
      loadError.hidden = true;
      latest = m;
      paintNumbers(m);
      const pts = hist.points;
      const drops = pts.map((p, i) => (i === 0 ? 0 : Math.max(0, p.dropped - pts[i - 1].dropped)));
      clear(charts).append(
        sparkline("Throughput (packets/s)", pts.map((p) => p.pps_10s), " pps"),
        sparkline("Dropped packets per heartbeat", drops, ""),
        sparkline("Queue depth", pts.map((p) => p.queue_depth), ""),
        sparkline("Tracked state entries", pts.map((p) => p.state_size), ""),
      );
      const rate = hist.drop_rate;
      if (rate !== null && rate > hist.drop_warn_ratio) {
        banners.prepend(h("p", { class: "banner", role: "alert" }, `Drop rate ${fmtPercent(rate)} over the last ${hist.window_minutes} minutes is above the ${fmtPercent(hist.drop_warn_ratio)} threshold. The sensor cannot keep up; detections may be missed.`));
      }
      meta.textContent = `${pts.length} heartbeats in the last ${hist.window_minutes} minutes. Window drop rate: ${fmtPercent(rate)}.`;
    } catch (err) {
      if (disposed || (err && err.status === 401)) return; // 401: api.js sends the user to the login screen
      loadError.textContent = loadFailure("sensor status", err);
      loadError.hidden = false;
    }
  }

  const onMetrics = (e) => {
    if (latest) {
      latest = { ...latest, ...e.detail };
      paintNumbers(latest);
    }
  };
  bus.addEventListener("stream:metrics", onMetrics);
  const timer = setInterval(load, REFRESH_MS);
  clear(main).append(h("div", { class: "page-head" }, h("h1", null, "Sensor health"), meta), loadError, banners, numbers, charts);
  load();
  return () => {
    disposed = true;
    clearInterval(timer);
    bus.removeEventListener("stream:metrics", onMetrics);
  };
}
