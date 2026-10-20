import { api } from "../api.js";
import { clear, debounce, h } from "../dom.js";
import { fmtNumber, go } from "../util.js";
import { alertRow, headRow, selection } from "./common.js";
import { openDrawer } from "./drawer.js";

const FILTER_KEYS = ["threat_type", "scan_type", "severity", "status", "source_ip", "destination_ip", "q", "since", "until", "dport"];
const PAGE_SIZES = ["50", "100", "200", "500"];
const OPTIONS = {
  threat_type: ["PORT_SCAN", "SYN_FLOOD", "VOLUMETRIC", "ML_ANOMALY"],
  scan_type: ["VERTICAL", "HORIZONTAL", "SLOW", "SLOW_VERTICAL", "SLOW_HORIZONTAL"],
  severity: ["HIGH", "MEDIUM", "LOW"],
  status: ["new", "acknowledged", "investigating", "resolved_tp", "resolved_fp"],
};
const LABELS = { threat_type: "Threat type", scan_type: "Scan type", severity: "Severity", status: "Triage status", source_ip: "Source IP or CIDR", destination_ip: "Destination IP or CIDR", q: "Search message", dport: "Dest. port" };
const IPISH = /^[0-9a-fA-F:.]+(\/\d{1,3})?$/;

// datetime-local <-> ISO helpers (inputs show local time, URL keeps UTC)
const toLocalInput = (iso) => {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
};
const fromLocalInput = (value) => (value ? new Date(value).toISOString().replace(/\.\d+Z$/, "Z") : "");

export function renderAlerts(main, params, ctx) {
  const state = {};
  for (const key of FILTER_KEYS) state[key] = params.get(key) || "";
  state.sort = params.get("sort") || "detected_at";
  state.order = params.get("order") === "asc" ? "asc" : "desc";
  state.limit = PAGE_SIZES.includes(params.get("limit")) ? params.get("limit") : "100";
  state.page = Math.max(1, Number.parseInt(params.get("page") || "1", 10) || 1);

  const exportLinks = () => {
    const query = new URLSearchParams();
    for (const key of FILTER_KEYS) if (state[key]) query.set(key, state[key]);
    query.set("sort", state.sort);
    query.set("order", state.order);
    const link = (format, label) => {
      query.set("format", format);
      return h("a", { class: "btn btn-sm", href: `/api/v1/alerts/export?${query}`, download: "", title: "Exports every alert matching the current filters, up to the server's row cap" }, label);
    };
    return h("div", { class: "row", role: "group", "aria-label": "Export" }, link("csv", "Export CSV"), link("json", "Export JSON"));
  };
  const tbody = h("tbody");
  const thead = h("thead");
  const summary = h("p", { class: "muted", role: "status" });
  const pager = h("div", { class: "pager" });
  const errorBox = h("p", { class: "error", role: "alert" });
  const select = selection(tbody);
  let disposed = false;
  let inFlight = 0;

  const push = (changes, resetPage = true) => {
    const next = { ...state, ...changes };
    if (resetPage && !("page" in changes)) next.page = 1;
    const query = {};
    for (const key of [...FILTER_KEYS, "sort", "order"]) if (next[key] && !(key === "sort" && next[key] === "detected_at") && !(key === "order" && next[key] === "desc")) query[key] = next[key];
    if (next.limit !== "100") query.limit = next.limit;
    if (next.page > 1) query.page = next.page;
    go("/alerts", query, { replace: true });
  };

  function control(key) {
    const id = `f-${key}`;
    let input;
    if (OPTIONS[key]) {
      input = h("select", { id, onChange: (e) => push({ [key]: e.target.value }) }, h("option", { value: "" }, "Any"), ...OPTIONS[key].map((o) => h("option", { value: o, selected: state[key] === o }, o)));
    } else {
      const apply = debounce((e) => {
        const v = e.target.value.trim();
        if ((key === "source_ip" || key === "destination_ip") && v && !IPISH.test(v)) {
          e.target.setAttribute("aria-invalid", "true");
          return;
        }
        e.target.removeAttribute("aria-invalid");
        push({ [key]: v });
      }, 300);
      input = h("input", { id, type: key === "dport" ? "number" : "search", min: key === "dport" ? "0" : null, max: key === "dport" ? "65535" : null, value: state[key], maxlength: "100", autocomplete: "off", onInput: apply });
    }
    return h("div", { class: "field" }, h("label", { for: id }, LABELS[key]), input);
  }

  const timeField = (key, label) =>
    h("div", { class: "field" }, h("label", { for: `f-${key}` }, label), h("input", { id: `f-${key}`, type: "datetime-local", value: toLocalInput(state[key]), onChange: (e) => push({ [key]: fromLocalInput(e.target.value) }) }));

  const filters = h(
    "form",
    { class: "panel row", role: "search", "aria-label": "Alert filters", onSubmit: (e) => e.preventDefault() },
    ...["q", "threat_type", "scan_type", "severity", "status", "source_ip", "destination_ip", "dport"].map(control),
    timeField("since", "From (local time)"),
    timeField("until", "To (local time)"),
    h("div", { class: "field field-narrow" }, h("label", { for: "f-limit" }, "Rows per page"), h("select", { id: "f-limit", onChange: (e) => push({ limit: e.target.value }) }, ...PAGE_SIZES.map((s) => h("option", { value: s, selected: state.limit === s }, s)))),
    h("button", { class: "btn", type: "button", onClick: () => go("/alerts", {}, { replace: true }) }, "Reset filters"),
  );

  async function load() {
    const ticket = ++inFlight;
    errorBox.textContent = "";
    const limit = Number(state.limit);
    const query = { sort: state.sort, order: state.order, limit, offset: (state.page - 1) * limit };
    for (const key of FILTER_KEYS) if (state[key]) query[key] = state[key];
    try {
      const { data, headers } = await api.get("/api/v1/alerts", query);
      if (disposed || ticket !== inFlight) return;
      const total = Number(headers.get("X-Total-Count") || data.length);
      clear(thead).append(headRow(state.sort, state.order, (key) => push({ sort: key, order: state.sort === key && state.order === "desc" ? "asc" : "desc" })));
      clear(tbody);
      select.reset();
      if (!data.length) tbody.append(h("tr", null, h("td", { colspan: "7", class: "empty" }, "No alerts match these filters.")));
      for (const alert of data) tbody.append(alertRow(alert, (a) => openDrawer(a, { onTriaged: () => load() })));
      const from = total ? query.offset + 1 : 0;
      summary.textContent = `Showing ${fmtNumber(from)}–${fmtNumber(query.offset + data.length)} of ${fmtNumber(total)} alerts`;
      const pages = Math.max(1, Math.ceil(total / limit));
      clear(pager).append(
        h("button", { class: "btn btn-sm", type: "button", disabled: state.page <= 1, onClick: () => push({ page: state.page - 1 }, false) }, "Previous"),
        h("span", null, `Page ${state.page} of ${fmtNumber(pages)}`),
        h("button", { class: "btn btn-sm", type: "button", disabled: state.page >= pages, onClick: () => push({ page: state.page + 1 }, false) }, "Next"),
      );
    } catch (e) {
      if (!disposed) errorBox.textContent = e.status === 400 ? `Invalid filter: ${e.message}` : "Could not load alerts.";
    }
  }

  // keyboard: registered with the global shortcut layer
  ctx.shortcuts.set({
    j: () => select.next(),
    k: () => select.prev(),
    Enter: () => {
      const row = select.current();
      if (row) row.click();
    },
    a: async () => {
      const row = select.current();
      if (!row || (ctx.session.role !== "analyst" && ctx.session.role !== "admin")) return;
      try {
        await api.post(`/api/v1/alerts/${row.dataset.id}/triage`, { status: "acknowledged" });
        load();
      } catch {
        /* surfaced by api.js (403/429) or ignored */
      }
    },
    "/": () => document.getElementById("f-q").focus(),
  });

  clear(main).append(
    h("div", { class: "page-head" }, h("h1", null, "Alerts"), summary, exportLinks()),
    filters,
    h("div", { class: "table-wrap", tabindex: "0", role: "region", "aria-label": "Alert table" }, h("table", null, thead, tbody)),
    errorBox,
    pager,
  );
  load();
  return () => {
    disposed = true;
    ctx.shortcuts.clear();
  };
}
