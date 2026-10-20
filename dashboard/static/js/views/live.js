import { api, bus } from "../api.js";
import { announce, clear, h } from "../dom.js";
import { streamState } from "../stream.js";
import { alertRow, headRow, selection } from "./common.js";
import { openDrawer } from "./drawer.js";

const MAX_ROWS = 200;
const FRESH_MS = 3000;

export function renderLive(main, _params, ctx) {
  const tbody = h("tbody");
  const thead = h("thead", null, headRow("", "", () => {}));
  const select = selection(tbody);
  const status = h("span", { class: "badge", id: "live-count" }, "0 new this session");
  const pauseBtn = h("button", { class: "btn", type: "button", "aria-pressed": "false" }, "Pause live");
  const resume = h("p", { class: "banner", hidden: true, role: "status" });
  let paused = false;
  let buffered = [];
  let shown = 0;
  let disposed = false;

  const addRows = (alerts, fresh) => {
    // newest first; the table sits in a fixed-height scroll area so rows arriving never move the page layout
    for (const alert of [...alerts].sort((a, b) => b.id - a.id)) {
      const row = alertRow(alert, (a) => openDrawer(a));
      if (fresh) {
        row.classList.add("fresh");
        setTimeout(() => row.classList.remove("fresh"), FRESH_MS);
      }
      tbody.prepend(row);
    }
    while (tbody.rows.length > MAX_ROWS) tbody.lastElementChild.remove();
  };

  const onAlerts = (e) => {
    if (disposed) return;
    if (paused) {
      buffered.push(...e.detail);
      resume.hidden = false;
      resume.textContent = `${buffered.length} new alert${buffered.length === 1 ? "" : "s"} waiting. Resume live to show them.`;
      return;
    }
    shown += e.detail.length;
    status.textContent = `${shown} new this session`;
    addRows(e.detail, true);
    announce(`${e.detail.length} new alert${e.detail.length === 1 ? "" : "s"}`);
  };

  pauseBtn.addEventListener("click", () => {
    paused = !paused;
    pauseBtn.setAttribute("aria-pressed", String(paused));
    pauseBtn.textContent = paused ? "Resume live" : "Pause live";
    if (!paused && buffered.length) {
      shown += buffered.length;
      status.textContent = `${shown} new this session`;
      addRows(buffered, true);
      buffered = [];
      resume.hidden = true;
    }
  });

  bus.addEventListener("stream:alerts", onAlerts);
  ctx.shortcuts.set({
    j: () => select.next(),
    k: () => select.prev(),
    Enter: () => {
      const row = select.current();
      if (row) row.click();
    },
  });

  clear(main).append(
    h("div", { class: "page-head" }, h("h1", null, "Live"), h("div", { class: "row" }, status, pauseBtn)),
    h("p", { class: "muted" }, `Stream status: ${streamState()}. New alerts appear at the top.`),
    resume,
    h("div", { class: "table-wrap live-scroll", tabindex: "0", role: "region", "aria-label": "Live alerts" }, h("table", null, thead, tbody)),
  );
  api
    .get("/api/v1/alerts", { limit: 50, sort: "id", order: "desc" })
    .then(({ data }) => {
      if (disposed) return;
      addRows(data, false);
      if (!data.length) tbody.append(h("tr", null, h("td", { colspan: "7", class: "empty" }, "No alerts yet. New ones will appear here.")));
    })
    .catch(() => {});
  return () => {
    disposed = true;
    bus.removeEventListener("stream:alerts", onAlerts);
    ctx.shortcuts.clear();
  };
}
