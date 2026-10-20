// The single fetch wrapper: CSRF on writes, and uniform handling of 401 / 403 / 429.
import { toast } from "./dom.js";

export const bus = new EventTarget();
export const session = { user: null, role: null, csrf: null };

export class ApiError extends Error {
  constructor(status, message, retryAfter) {
    super(message);
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

function toQuery(query) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query || {})) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

export async function request(method, path, { query, body, signal, quiet = false } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && session.csrf) headers["X-CSRF-Token"] = session.csrf;
  const response = await fetch(path + toQuery(query), {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    signal,
  });
  let data = null;
  if (response.status !== 204) {
    try {
      data = await response.json();
    } catch {
      data = null;
    }
  }
  if (response.ok) return { data, headers: response.headers };

  const retry = Number(response.headers.get("Retry-After")) || null;
  const error = new ApiError(response.status, (data && data.message) || response.statusText, retry);
  if (response.status === 401 && path !== "/login") bus.dispatchEvent(new CustomEvent("unauthorized"));
  else if (!quiet && response.status === 403) toast("You don't have permission for this.");
  else if (!quiet && response.status === 429 && path !== "/login") toast(`Too many requests. Retry in ${retry ?? "a few"} seconds.`);
  throw error;
}

export const api = {
  get: (path, query, options) => request("GET", path, { query, ...options }),
  post: (path, body, options) => request("POST", path, { body: body ?? {}, ...options }),
};
