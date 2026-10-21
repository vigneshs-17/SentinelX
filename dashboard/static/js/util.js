// Hash routing with filter state in the URL, formatting, theme.
export function parseHash() {
  const raw = location.hash.replace(/^#/, "") || "/overview";
  const [path, query = ""] = raw.split("?");
  return { route: path || "/overview", params: new URLSearchParams(query) };
}

export function hashFor(route, params) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params || {})) {
    if (value !== undefined && value !== null && value !== "") query.set(key, String(value));
  }
  const text = query.toString();
  return `#${route}${text ? `?${text}` : ""}`;
}

export function go(route, params, { replace = false } = {}) {
  const target = hashFor(route, params);
  if (replace) history.replaceState(null, "", target);
  else location.hash = target;
  if (replace) window.dispatchEvent(new HashChangeEvent("hashchange"));
}

export const fmtNumber = (n) => (n === null || n === undefined ? "–" : Number(n).toLocaleString());

export function fmtTime(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { hour12: false });
}

export const fmtPercent = (ratio) => (Number.isFinite(ratio) ? `${(ratio * 100).toFixed(ratio < 0.1 ? 2 : 1)}%` : "–");

export function isoMinus(ms, from = Date.now()) {
  return new Date(from - ms).toISOString().replace(/\.\d+Z$/, "Z");
}

export const STATUS_LABEL = {
  new: "New",
  acknowledged: "Acknowledged",
  investigating: "Investigating",
  resolved_tp: "Resolved: true positive",
  resolved_fp: "Resolved: false positive",
};

// Theme: remembered in localStorage when available, otherwise follows prefers-color-scheme.
export function initTheme(button) {
  const apply = (theme) => {
    document.documentElement.setAttribute("data-theme", theme);
    const dark = theme === "dark";
    button.setAttribute("aria-pressed", String(dark));
    button.textContent = dark ? "Dark" : "Light";
  };
  let saved = null;
  try {
    saved = localStorage.getItem("sx-theme");
  } catch {
    saved = null;
  }
  const initial = saved || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  apply(initial);
  button.addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    apply(next);
    try {
      localStorage.setItem("sx-theme", next);
    } catch {
      /* storage unavailable: the choice just is not remembered */
    }
  });
}

/**
 * Text for a failed request, shown to the user instead of swallowing the error. A browser extension that blocks the
 * request makes fetch() throw a bare TypeError ("Failed to fetch"), so say that is a possible cause.
 */
export function loadFailure(what, err) {
  const detail = err && err.status ? `${err.message} (HTTP ${err.status})` : "the request did not complete; a browser extension such as an ad blocker may be blocking it";
  return `Could not load ${what}: ${detail}. Retrying automatically.`;
}
