// App shell: routing, session bootstrap, navigation, stream status, tab-title unread count, keyboard shortcuts.
import { ApiError, api, bus, request, session } from "./api.js";
import { $, announce, clear, h, trapFocus } from "./dom.js";
import { go, initTheme, parseHash } from "./util.js";
import { startStream, stopStream } from "./stream.js";
import { renderAdmin } from "./views/admin.js";
import { renderAlerts } from "./views/alerts.js";
import { closeDrawer } from "./views/drawer.js";
import { renderGraph } from "./views/graph.js";
import { renderHealth } from "./views/health.js";
import { renderLive } from "./views/live.js";
import { renderLogin } from "./views/login.js";
import { renderOverview } from "./views/overview.js";

const ROUTES = {
  "/overview": { title: "Overview", render: renderOverview },
  "/live": { title: "Live", render: renderLive },
  "/alerts": { title: "Alerts", render: renderAlerts },
  "/graph": { title: "Graph", render: renderGraph },
  "/health": { title: "Sensor health", render: renderHealth },
  "/admin": { title: "Admin", render: renderAdmin, adminOnly: true },
};
const TITLE = "SentinelX";

// ---- keyboard shortcuts: views register handlers, this layer owns the keydown listener ----
let handlers = {};
const shortcuts = {
  set: (map) => {
    handlers = map;
  },
  clear: () => {
    handlers = {};
  },
};
let helpRelease = null;

function showHelp() {
  if (helpRelease) return;
  const rows = [
    ["j / k", "Next / previous row"],
    ["Enter", "Open the selected alert"],
    ["a", "Acknowledge the selected alert (analyst and admin)"],
    ["/", "Focus the message search"],
    ["?", "Show this help"],
    ["Esc", "Close the drawer or this dialog"],
  ];
  const dialog = h("div", { class: "dialog", role: "dialog", "aria-modal": "true", "aria-labelledby": "help-title" }, h("h2", { id: "help-title" }, "Keyboard shortcuts"), h("div", { class: "shortcuts" }, ...rows.flatMap(([k, d]) => [h("kbd", null, k), h("span", null, d)])), h("p", null, h("button", { class: "btn", type: "button", id: "help-close" }, "Close")));
  const backdrop = h("div", { class: "backdrop" });
  $("#overlay-root").append(backdrop, dialog);
  const finish = trapFocus(dialog, close);
  function close() {
    finish();
    dialog.remove();
    backdrop.remove();
    helpRelease = null;
  }
  helpRelease = close;
  backdrop.addEventListener("click", close);
  $("#help-close").addEventListener("click", close);
  $("#help-close").focus();
}

document.addEventListener("keydown", (e) => {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  const target = e.target;
  const typing = target instanceof HTMLElement && (target.matches("input, textarea, select") || target.isContentEditable);
  if (typing) return;
  // Enter on a focused button or link must activate it natively, not trigger the "open selected row" shortcut.
  if (e.key === "Enter" && target instanceof Element && target.closest("button, a, [role=\"button\"]")) return;
  if (document.querySelector(".drawer, .dialog") && e.key !== "?") return;
  if (e.key === "?") {
    e.preventDefault();
    showHelp();
  } else if (handlers[e.key]) {
    e.preventDefault();
    handlers[e.key]();
  }
});

// ---- tab title unread count ----
let unread = 0;
const updateTitle = () => {
  document.title = unread ? `(${unread}) ${TITLE}` : TITLE;
};
bus.addEventListener("stream:alerts", (e) => {
  const looking = !document.hidden && parseHash().route === "/live";
  if (!looking) {
    unread += e.detail.length;
    updateTitle();
  }
});
const clearUnread = () => {
  if (!document.hidden && parseHash().route === "/live") {
    unread = 0;
    updateTitle();
  }
};
document.addEventListener("visibilitychange", clearUnread);

// ---- stream status pill ----
const PILL = { live: "Live", reconnecting: "Reconnecting", polling: "Polling", connecting: "Connecting" };
bus.addEventListener("stream:state", (e) => {
  const pill = $("#stream-status");
  pill.dataset.state = e.detail;
  pill.textContent = PILL[e.detail];
});

// ---- routing ----
const main = $("#main");
let dispose = null;

function renderNav(route) {
  const nav = clear($("#nav"));
  for (const [path, def] of Object.entries(ROUTES)) {
    if (def.adminOnly && session.role !== "admin") continue;
    nav.append(h("a", { href: `#${path}`, "aria-current": route === path ? "page" : null }, def.title));
  }
}

function showShell(visible) {
  $("#topbar").hidden = !visible;
  if (visible) {
    $("#whoami").textContent = `${session.user} (${session.role})`;
  }
}

async function route() {
  if (dispose) dispose();
  dispose = null;
  closeDrawer();
  const focusId = document.activeElement && document.activeElement.id;
  const caret = document.activeElement && "selectionStart" in document.activeElement ? document.activeElement.selectionStart : null;
  const { route: path, params } = parseHash();
  if (!session.user) {
    showShell(false);
    dispose = renderLogin(main, { onSuccess: () => bootstrapped() });
    document.title = `Sign in · ${TITLE}`;
    return;
  }
  const def = ROUTES[path];
  if (!def) {
    go("/overview", {}, { replace: true });
    return;
  }
  showShell(true);
  renderNav(path);
  document.title = `${def.title} · ${TITLE}`;
  dispose = def.render(main, params, { shortcuts, session });
  clearUnread();
  if (focusId) {
    const again = document.getElementById(focusId);
    if (again) {
      again.focus();
      if (caret !== null && "setSelectionRange" in again && again.type !== "number") again.setSelectionRange(caret, caret);
    }
  }
}

function bootstrapped() {
  startStream();
  if (!parseHash().route || parseHash().route === "/login") go("/overview", {}, { replace: true });
  else route();
}

async function boot() {
  initTheme($("#theme-toggle"));
  $("#logout").addEventListener("click", async () => {
    try {
      await request("POST", "/api/v1/logout", { body: {} });
    } catch {
      /* already signed out */
    }
    signedOut();
  });
  window.addEventListener("hashchange", route);
  try {
    const { data } = await api.get("/api/v1/session", {}, { quiet: true });
    session.user = data.name;
    session.role = data.role;
    session.csrf = data.csrf_token;
    bootstrapped();
  } catch (e) {
    if (!(e instanceof ApiError) || e.status !== 401) announce("Could not reach the server.");
    route();
  }
}

function signedOut() {
  stopStream();
  session.user = session.role = session.csrf = null;
  closeDrawer();
  if (parseHash().route !== "/login") location.hash = "#/login";
  route();
}
bus.addEventListener("unauthorized", () => {
  if (session.user) signedOut();
});

boot();
