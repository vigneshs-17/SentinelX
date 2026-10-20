// DOM helpers. Text always goes through textContent / createTextNode; markup is never parsed from strings.
const SVG_NS = "http://www.w3.org/2000/svg";

function applyProps(el, props) {
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") el.setAttribute("class", value);
    else if (key === "text") el.textContent = value;
    else if (key === "dataset") Object.assign(el.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2).toLowerCase(), value);
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, String(value));
  }
}

export function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  applyProps(el, props);
  return append(el, children);
}

export function svg(tag, props, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  applyProps(el, props);
  return append(el, children);
}

export function clear(node) {
  node.replaceChildren();
  return node;
}

export const $ = (selector, root = document) => root.querySelector(selector);

export function toast(message, ms = 5000) {
  const box = $("#toasts");
  const item = h("div", { class: "toast", role: "status" }, message);
  box.append(item);
  setTimeout(() => item.remove(), ms);
}

let announceTimer = null;
let pendingAnnouncement = "";
export function announce(message, throttleMs = 5000) {
  // Polite live region, throttled so a burst of alerts is one sentence, not a flood.
  pendingAnnouncement = message;
  if (announceTimer) return;
  const region = $("#announcer");
  region.textContent = pendingAnnouncement;
  announceTimer = setTimeout(() => {
    announceTimer = null;
    if (pendingAnnouncement && region.textContent !== pendingAnnouncement) region.textContent = pendingAnnouncement;
  }, throttleMs);
}

export function debounce(fn, ms) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

// Focus trap for dialogs/drawers: Tab cycles inside `root`; returns a release function.
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
export function trapFocus(root, onEscape) {
  const previous = document.activeElement;
  const onKey = (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      onEscape();
      return;
    }
    if (e.key !== "Tab") return;
    const items = [...root.querySelectorAll(FOCUSABLE)].filter((n) => !n.hidden && n.offsetParent !== null);
    if (!items.length) {
      e.preventDefault();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    } else if (!root.contains(document.activeElement)) {
      e.preventDefault();
      first.focus();
    }
  };
  document.addEventListener("keydown", onKey, true);
  return () => {
    document.removeEventListener("keydown", onKey, true);
    if (previous && previous.focus) previous.focus();
  };
}
