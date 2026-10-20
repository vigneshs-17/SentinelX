// Admin console (admin role): users, API keys, audit log. Every destructive action needs a second click.
import { api, request } from "../api.js";
import { $, clear, h, toast, trapFocus } from "../dom.js";
import { fmtTime, go } from "../util.js";

const TABS = [["users", "Users"], ["keys", "API keys"], ["audit", "Audit log"]];
const AUDIT_PAGE = 100;

function confirmButton(label, confirmLabel, action, cls = "btn btn-sm") {
  let armed = null;
  const button = h("button", { class: cls, type: "button" }, label);
  button.addEventListener("click", async () => {
    if (!armed) {
      button.textContent = confirmLabel;
      armed = setTimeout(() => {
        armed = null;
        button.textContent = label;
      }, 4000);
      return;
    }
    clearTimeout(armed);
    armed = null;
    button.textContent = label;
    await action();
  });
  return button;
}

function field(id, label, input) {
  return h("div", { class: "field" }, h("label", { for: id }, label), input);
}

function resetPasswordDialog(user, onDone) {
  const password = h("input", { id: "rp-password", type: "password", autocomplete: "new-password", minlength: "12", maxlength: "1024", required: true });
  const error = h("p", { class: "error", role: "alert" });
  const backdrop = h("div", { class: "backdrop" });
  const dialog = h(
    "div",
    { class: "dialog", role: "dialog", "aria-modal": "true", "aria-labelledby": "rp-title" },
    h("h2", { id: "rp-title" }, `Reset password for ${user.username}`),
    h("p", { class: "muted" }, "All of the user's sessions end immediately. Minimum 12 characters."),
    h("form", { novalidate: true, onSubmit: async (e) => {
      e.preventDefault();
      try {
        await api.post(`/api/v1/users/${user.id}/reset-password`, { password: password.value });
        close();
        toast(`Password changed for ${user.username}`);
        onDone();
      } catch (err) {
        error.textContent = err.message || "Could not change the password.";
      }
    } }, field("rp-password", "New password", password), error, h("div", { class: "row" }, h("button", { class: "btn btn-primary", type: "submit" }, "Change password"), h("button", { class: "btn", type: "button", onClick: () => close() }, "Cancel"))),
  );
  $("#overlay-root").append(backdrop, dialog);
  const release = trapFocus(dialog, () => close());
  backdrop.addEventListener("click", () => close());
  password.focus();
  function close() {
    release();
    dialog.remove();
    backdrop.remove();
  }
}

async function usersTab(box) {
  const { data: users } = await api.get("/api/v1/users");
  const reload = () => usersTab(box);
  const username = h("input", { id: "nu-name", autocomplete: "off", maxlength: "64", required: true });
  const role = h("select", { id: "nu-role" }, ...["viewer", "analyst", "admin"].map((r) => h("option", { value: r }, r)));
  const password = h("input", { id: "nu-pass", type: "password", autocomplete: "new-password", maxlength: "1024", required: true });
  const error = h("p", { class: "error", role: "alert" });
  const form = h("form", { class: "panel row", novalidate: true, "aria-label": "Create user", onSubmit: async (e) => {
    e.preventDefault();
    error.textContent = "";
    try {
      await api.post("/api/v1/users", { username: username.value.trim(), password: password.value, role: role.value });
      toast(`User ${username.value.trim()} created`);
      reload();
    } catch (err) {
      error.textContent = err.message;
    }
  } }, field("nu-name", "Username", username), field("nu-role", "Role", role), field("nu-pass", "Password (12+ characters)", password), h("button", { class: "btn btn-primary", type: "submit" }, "Create user"), error);
  const rows = users.map((u) =>
    h("tr", null,
      h("td", null, u.username), h("td", null, u.role), h("td", null, u.disabled ? "Disabled" : "Active"), h("td", null, u.last_login_at ? fmtTime(new Date(u.last_login_at * 1000).toISOString()) : "never"),
      h("td", null, h("div", { class: "row" },
        u.disabled
          ? h("button", { class: "btn btn-sm", type: "button", onClick: async () => { await api.post(`/api/v1/users/${u.id}/enable`).catch(() => {}); reload(); } }, "Enable")
          : confirmButton("Disable", "Confirm disable", async () => { await api.post(`/api/v1/users/${u.id}/disable`).catch((e) => toast(e.message)); reload(); }),
        h("button", { class: "btn btn-sm", type: "button", onClick: () => resetPasswordDialog(u, reload) }, "Reset password"),
        confirmButton("Revoke sessions", "Confirm revoke", async () => { const { data } = await api.post(`/api/v1/users/${u.id}/revoke-sessions`).catch(() => ({ data: { revoked: 0 } })); toast(`${data.revoked} session(s) ended`); }),
      )),
    ),
  );
  clear(box).append(form, h("div", { class: "table-wrap" }, h("table", null, h("thead", null, h("tr", null, ...["Username", "Role", "Status", "Last sign-in", "Actions"].map((t) => h("th", { scope: "col" }, t)))), h("tbody", null, ...rows))));
}

async function keysTab(box) {
  const { data: keys } = await api.get("/api/v1/apikeys");
  const reload = () => keysTab(box);
  const name = h("input", { id: "nk-name", maxlength: "64", required: true, autocomplete: "off" });
  const role = h("select", { id: "nk-role" }, ...["viewer", "analyst"].map((r) => h("option", { value: r }, r)));
  const shown = h("div");
  const error = h("p", { class: "error", role: "alert" });
  const form = h("form", { class: "panel row", novalidate: true, "aria-label": "Create API key", onSubmit: async (e) => {
    e.preventDefault();
    error.textContent = "";
    try {
      const { data } = await api.post("/api/v1/apikeys", { name: name.value.trim(), role: role.value });
      const dismiss = () => { clear(shown); reload(); };
      clear(shown).append(h("div", { class: "callout", role: "alert" },
        h("strong", null, "Copy this key now. It is shown once and cannot be recovered."),
        h("code", { class: "mono keybox" }, data.key),
        h("div", { class: "row" },
          h("button", { class: "btn btn-sm", type: "button", onClick: async () => { try { await navigator.clipboard.writeText(data.key); toast("Key copied"); } catch { toast("Copy failed: select the key and copy it manually"); } } }, "Copy key"),
          h("button", { class: "btn btn-sm", type: "button", onClick: dismiss }, "I have stored it"))));
    } catch (err) {
      error.textContent = err.message;
    }
  } }, field("nk-name", "Key name", name), field("nk-role", "Role", role), h("button", { class: "btn btn-primary", type: "submit" }, "Create key"), error);
  const rows = keys.map((k) =>
    h("tr", null, h("td", null, k.name), h("td", { class: "mono" }, `${k.prefix}…`), h("td", null, k.role), h("td", null, k.created_by),
      h("td", null, k.last_used_at ? fmtTime(new Date(k.last_used_at * 1000).toISOString()) : "never"),
      h("td", null, k.revoked_at ? "Revoked" : "Active"),
      h("td", null, k.revoked_at ? "" : confirmButton("Revoke", "Confirm revoke", async () => { await request("DELETE", `/api/v1/apikeys/${k.id}`).catch((e) => toast(e.message)); reload(); })),
    ),
  );
  clear(box).append(form, shown, h("div", { class: "table-wrap" }, h("table", null, h("thead", null, h("tr", null, ...["Name", "Prefix", "Role", "Created by", "Last used", "Status", ""].map((t) => h("th", { scope: "col" }, t)))), h("tbody", null, ...rows))));
}

async function auditTab(box, params) {
  const state = { action: params.get("action") || "", actor: params.get("actor") || "", target: params.get("target") || "", since: params.get("since") || "" };
  let offset = 0;
  const tbody = h("tbody");
  const more = h("button", { class: "btn", type: "button" }, "Load more");
  const status = h("p", { class: "muted", role: "status" });
  const inputs = {};
  const filterField = (key, label, type = "text") => {
    inputs[key] = h("input", { id: `au-${key}`, type, value: state[key], maxlength: "128", autocomplete: "off" });
    return field(`au-${key}`, label, inputs[key]);
  };
  const form = h("form", { class: "panel row", role: "search", "aria-label": "Audit filters", onSubmit: (e) => {
    e.preventDefault();
    const next = { tab: "audit" };
    for (const key of Object.keys(state)) if (inputs[key].value.trim()) next[key] = inputs[key].value.trim();
    go("/admin", next, { replace: true });
  } }, filterField("action", "Action (e.g. login.failure)"), filterField("actor", "Actor"), filterField("target", "Target"), filterField("since", "Since (ISO-8601 with offset)"), h("button", { class: "btn btn-primary", type: "submit" }, "Filter"));

  async function page() {
    const query = { limit: AUDIT_PAGE, offset };
    for (const [key, value] of Object.entries(state)) if (value) query[key] = value;
    try {
      const { data } = await api.get("/api/v1/audit", query);
      for (const row of data) {
        tbody.append(h("tr", null, h("td", null, fmtTime(row.ts)), h("td", null, row.actor), h("td", { class: "mono" }, row.source_ip || "–"), h("td", null, row.action), h("td", null, row.target || "–"), h("td", { class: "wrap mono" }, row.detail ? JSON.stringify(row.detail) : "")));
      }
      offset += data.length;
      more.hidden = data.length < AUDIT_PAGE;
      status.textContent = `${offset} entries loaded.`;
    } catch (err) {
      status.textContent = err.status === 400 ? `Invalid filter: ${err.message}` : "Could not load the audit log.";
    }
  }
  more.addEventListener("click", page);
  clear(box).append(form, status, h("div", { class: "table-wrap live-scroll", tabindex: "0", role: "region", "aria-label": "Audit log" }, h("table", null, h("thead", null, h("tr", null, ...["Time", "Actor", "Source IP", "Action", "Target", "Detail"].map((t) => h("th", { scope: "col" }, t)))), tbody)), more);
  await page();
}

export function renderAdmin(main, params, ctx) {
  if (ctx.session.role !== "admin") {
    clear(main).append(h("div", { class: "page-head" }, h("h1", null, "Admin")), h("p", { class: "banner", role: "alert" }, "You don't have permission for this."));
    return () => {};
  }
  const tab = TABS.some(([id]) => id === params.get("tab")) ? params.get("tab") : "users";
  const box = h("div", { class: "grid" });
  const nav = h("div", { class: "row", role: "group", "aria-label": "Admin sections" }, ...TABS.map(([id, label]) => h("button", { class: "btn", type: "button", "aria-pressed": String(id === tab), onClick: () => go("/admin", { tab: id }, { replace: true }) }, label)));
  clear(main).append(h("div", { class: "page-head" }, h("h1", null, "Admin")), nav, box);
  const loader = { users: usersTab, keys: keysTab, audit: (b) => auditTab(b, params) }[tab];
  loader(box).catch(() => {});
  return () => {};
}
