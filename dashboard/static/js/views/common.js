import { h } from "../dom.js";
import { STATUS_LABEL, fmtTime } from "../util.js";

export const sevBadge = (sev) => h("span", { class: `sev sev-${sev}` }, sev);
export const threatLabel = (a) => (a.scan_type ? `${a.threat_type} · ${a.scan_type}` : a.threat_type);
export const destLabel = (a) => (a.destination_ip ? `${a.destination_ip}${a.destination_port ? `:${a.destination_port}` : ""}` : "–");

export const ALERT_HEADERS = [
  ["detected_at", "Time"],
  ["severity", "Severity"],
  ["threat_type", "Threat"],
  ["source_ip", "Source"],
  ["destination_ip", "Destination"],
  ["status", "Status"],
  [null, "Message"],
];

export function alertRow(alert, onOpen) {
  const open = () => onOpen(alert);
  const row = h(
    "tr",
    { dataset: { id: alert.id }, "aria-selected": "false", tabindex: "-1", onClick: open },
    h("td", null, h("button", { class: "rowlink", type: "button", onClick: (e) => { e.stopPropagation(); open(); } }, fmtTime(alert.detected_at))),
    h("td", null, sevBadge(alert.severity)),
    h("td", null, threatLabel(alert)),
    h("td", { class: "mono" }, alert.source_ip || "–"),
    h("td", { class: "mono" }, destLabel(alert)),
    h("td", null, h("span", { class: "badge" }, STATUS_LABEL[alert.triage_status] || alert.triage_status)),
    h("td", { class: "wrap" }, alert.message || ""),
  );
  return row;
}

export function headRow(sortKey, order, onSort) {
  return h(
    "tr",
    null,
    ...ALERT_HEADERS.map(([key, label]) => {
      if (!key) return h("th", { scope: "col" }, label);
      const active = sortKey === key;
      return h(
        "th",
        { scope: "col", "aria-sort": active ? (order === "asc" ? "ascending" : "descending") : "none" },
        h("button", { type: "button", onClick: () => onSort(key) }, label, active ? (order === "asc" ? " ▲" : " ▼") : ""),
      );
    }),
  );
}

// Roving selection for tables: returns controller used by keyboard shortcuts.
export function selection(tbody) {
  let index = -1;
  const rows = () => [...tbody.querySelectorAll("tr[data-id]")];
  const set = (next) => {
    const all = rows();
    if (!all.length) return;
    index = Math.max(0, Math.min(all.length - 1, next));
    all.forEach((r, i) => r.setAttribute("aria-selected", String(i === index)));
    all[index].scrollIntoView({ block: "nearest" });
  };
  return {
    next: () => set(index + 1),
    prev: () => set(index < 0 ? 0 : index - 1),
    current: () => rows()[index] || null,
    reset: () => {
      index = -1;
    },
  };
}
