// Alert detail drawer: evidence, chips, ML score, related alerts, triage history and role-aware triage controls.
import { api, session } from "../api.js";
import { $, append, announce, clear, h, toast, trapFocus } from "../dom.js";

import { STATUS_LABEL, fmtTime, go, isoMinus } from "../util.js";
import { destLabel, sevBadge, threatLabel } from "./common.js";

const A = (el, ...children) => append(el, children); // unlike Element.append, skips null children
const STATUSES = Object.keys(STATUS_LABEL);
const NOTE_MAX = 2000;
let current = null;

export function closeDrawer() {
  if (current) current.close();
}

function kv(entries) {
  const dl = h("dl", { class: "kv" });
  for (const [key, value] of entries) {
    dl.append(h("dt", null, key), h("dd", null, value === null || value === undefined || value === "" ? "–" : value));
  }
  return dl;
}

function evidenceTable(evidence) {
  if (!evidence || typeof evidence !== "object") return h("p", { class: "muted" }, evidence ? String(evidence) : "No evidence recorded.");
  const rows = Object.entries(evidence)
    .filter(([, v]) => !Array.isArray(v) || v.every((x) => typeof x === "object"))
    .map(([k, v]) => [k, typeof v === "object" && v !== null ? JSON.stringify(v) : v]);
  return rows.length ? kv(rows) : h("p", { class: "muted" }, "No scalar evidence fields.");
}

function chipsFor(evidence) {
  const groups = [];
  for (const [key, label] of [["sample_ports", "Sample ports"], ["sample_targets", "Sample hosts"]]) {
    const values = evidence && Array.isArray(evidence[key]) ? evidence[key] : [];
    if (values.length) groups.push(h("div", null, h("div", { class: "muted" }, label), ...values.map((v) => h("span", { class: "chip" }, String(v)))));
  }
  return groups;
}

export async function openDrawer(alert, { onTriaged } = {}) {
  closeDrawer();
  const root = $("#overlay-root");
  const body = h("div");
  const title = h("h2", { id: "drawer-title" }, `Alert #${alert.id}`);
  const closeBtn = h("button", { class: "btn btn-sm", type: "button", onClick: () => close() }, "Close");
  const drawer = h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-labelledby": "drawer-title" }, h("div", { class: "drawer-head" }, title, closeBtn), body);
  const backdrop = h("div", { class: "backdrop", onClick: () => close() });
  root.append(backdrop, drawer);
  const release = trapFocus(drawer, () => close());
  closeBtn.focus();

  function close() {
    release();
    backdrop.remove();
    drawer.remove();
    current = null;
  }
  current = { close };

  const canTriage = session.role === "analyst" || session.role === "admin";
  let triage = null;
  let history = [];
  let related = [];
  const [t, r] = await Promise.allSettled([
    api.get(`/api/v1/alerts/${alert.id}/triage`),
    alert.source_ip ? api.get("/api/v1/alerts", { source_ip: alert.source_ip, since: isoMinus(24 * 3600e3), limit: 11, sort: "detected_at", order: "desc" }) : Promise.resolve({ data: [] }),
  ]);
  if (current === null) return; // closed while loading
  if (t.status === "fulfilled") {
    triage = t.value.data.triage;
    history = t.value.data.history;
  }
  if (r.status === "fulfilled") related = r.value.data.filter((a) => a.id !== alert.id).slice(0, 10);

  const state = triage ? triage.status : alert.triage_status || "new";

  const triageBox = h("section", { "aria-labelledby": "triage-h" }, h("h2", { id: "triage-h" }, "Triage"));
  if (!canTriage) {
    A(triageBox,kv([["Status", STATUS_LABEL[state]], ["Assignee", triage && triage.assignee], ["Note", triage && triage.note]]), h("p", { class: "muted" }, "Your role is read-only for triage."));
  } else {
    const status = h("select", { id: "tri-status" }, ...STATUSES.map((s) => h("option", { value: s, selected: s === state }, STATUS_LABEL[s])));
    const assignee = h("input", { id: "tri-assignee", list: "assignees", maxlength: "64", value: (triage && triage.assignee) || "", autocomplete: "off" });
    const list = h("datalist", { id: "assignees" });
    const note = h("textarea", { id: "tri-note", maxlength: String(NOTE_MAX) }, (triage && triage.note) || "");
    const error = h("p", { class: "error", role: "alert" });
    const save = async (override) => {
      error.textContent = "";
      try {
        const { data } = await api.post(`/api/v1/alerts/${alert.id}/triage`, { status: override || status.value, assignee: assignee.value.trim() || null, note: note.value || null });
        toast(`Alert #${alert.id}: ${STATUS_LABEL[data.status]}`);
        announce(`Alert ${alert.id} set to ${STATUS_LABEL[data.status]}`, 0);
        alert.triage_status = data.status;
        alert.assignee = data.assignee;
        if (onTriaged) onTriaged(alert);
        close();
      } catch (e) {
        error.textContent = e.message || "Could not save.";
      }
    };
    api.get("/api/v1/assignees", {}, { quiet: true }).then(({ data }) => list.append(...data.map((n) => h("option", { value: n })))).catch(() => {});
    A(triageBox,
      h("div", { class: "grid" },
        h("div", null, h("label", { for: "tri-status" }, "Status"), status),
        h("div", null, h("label", { for: "tri-assignee" }, "Assignee (username)"), assignee, list),
        h("div", null, h("label", { for: "tri-note" }, `Note (plain text, up to ${NOTE_MAX} characters)`), note),
        error,
        h("div", { class: "row" },
          h("button", { class: "btn btn-primary", type: "button", onClick: () => save() }, "Save"),
          state === "new" ? h("button", { class: "btn", type: "button", onClick: () => save("acknowledged") }, "Acknowledge") : null,
        ),
      ),
    );
  }

  const historyBox = h("section", null, h("h2", null, "Triage history"));
  A(historyBox,
    history.length
      ? h("ul", { class: "history" }, ...history.map((e) => h("li", null, h("div", null, `${STATUS_LABEL[e.detail.from] || e.detail.from} → ${STATUS_LABEL[e.detail.to] || e.detail.to}`), h("div", { class: "muted" }, `${e.actor} · ${fmtTime(e.ts)}${e.detail.assignee ? ` · assigned to ${e.detail.assignee}` : ""}`), e.detail.note ? h("div", null, e.detail.note) : null)))
      : h("p", { class: "muted" }, "No triage activity yet."),
  );

  const relatedBox = h("section", null, h("h2", null, `Related alerts from ${alert.source_ip || "this source"} (24 h)`));
  A(relatedBox,
    related.length
      ? h("ul", { class: "history" }, ...related.map((a) => h("li", null, h("button", { class: "rowlink", type: "button", onClick: () => openDrawer(a, { onTriaged }) }, `#${a.id} ${threatLabel(a)}`), h("span", { class: "muted" }, ` · ${fmtTime(a.detected_at)}`))))
      : h("p", { class: "muted" }, "No other alerts from this source in the last 24 hours."),
    alert.source_ip ? h("button", { class: "btn btn-sm", type: "button", onClick: () => { close(); go("/alerts", { source_ip: alert.source_ip }); } }, "Filter list by this source") : null,
  );

  const ml = alert.ml_score !== null && alert.ml_score !== undefined ? kv([["ML score", Number(alert.ml_score).toFixed(3)], ["ML label", alert.ml_label]]) : null;
  A(clear(body),
    h("div", { class: "row" }, sevBadge(alert.severity), h("strong", null, threatLabel(alert))),
    h("section", null, kv([
      ["Detected", fmtTime(alert.detected_at)],
      ["Source", alert.source_ip],
      ["Destination", destLabel(alert)],
      ["Protocol", alert.protocol],
      ["Confidence", alert.confidence],
      ["Sensor", alert.sensor_id],
      ["Message", alert.message],
    ])),
    ml ? h("section", null, h("h2", null, "Machine learning"), ml) : null,
    h("section", null, h("h2", null, "Evidence"), evidenceTable(alert.evidence), ...chipsFor(alert.evidence)),
    triageBox,
    historyBox,
    relatedBox,
  );
}
