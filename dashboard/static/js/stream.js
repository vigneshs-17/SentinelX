// Live updates: Server-Sent Events read with fetch (so HTTP status codes are visible), reconnect with backoff,
// and a polling fallback when the stream is refused (429) or keeps failing.
import { api, bus } from "./api.js";

const BACKOFF_MS = [1000, 2000, 4000, 8000, 16000, 30000];
const POLL_MS = 5000;
const RETRY_STREAM_MS = 60000;
const FAILURES_BEFORE_POLLING = 3;

let controller = null;
let running = false;
let seenId = null;
let state = "connecting";

function setState(next) {
  if (next === state) return;
  state = next;
  bus.dispatchEvent(new CustomEvent("stream:state", { detail: next }));
}

export const streamState = () => state;

async function fetchNew() {
  if (seenId === null) return;
  const { data } = await api.get("/api/v1/alerts", { min_id: seenId, limit: 100, sort: "id", order: "asc" }, { quiet: true });
  if (data.length) {
    seenId = data[data.length - 1].id;
    bus.dispatchEvent(new CustomEvent("stream:alerts", { detail: data }));
  }
}

function handleEvent(block) {
  const line = block.split("\n").find((l) => l.startsWith("data: "));
  if (!line) return;
  const payload = JSON.parse(line.slice(6));
  bus.dispatchEvent(new CustomEvent("stream:metrics", { detail: payload.metrics }));
  if (seenId === null) {
    seenId = payload.latest_alert_id;
    return;
  }
  if (payload.new_alert_ids.length) fetchNew().catch(() => {});
}

async function readStream(signal) {
  const response = await fetch(`/api/v1/stream${seenId === null ? "" : `?after_id=${seenId}`}`, {
    credentials: "same-origin",
    headers: { Accept: "text/event-stream" },
    signal,
  });
  if (response.status === 401) {
    bus.dispatchEvent(new CustomEvent("unauthorized"));
    throw Object.assign(new Error("unauthorized"), { fatal: true });
  }
  if (!response.ok) throw Object.assign(new Error(`stream refused: ${response.status}`), { status: response.status });
  setState("live");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buffer += decoder.decode(value, { stream: true });
    let index;
    while ((index = buffer.indexOf("\n\n")) >= 0) {
      handleEvent(buffer.slice(0, index));
      buffer = buffer.slice(index + 2);
    }
  }
}

function sleep(ms, signal) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => {
      clearTimeout(t);
      resolve();
    });
  });
}

async function poll(signal) {
  setState("polling");
  const until = Date.now() + RETRY_STREAM_MS;
  while (!signal.aborted && Date.now() < until) {
    try {
      if (seenId === null) {
        const { data } = await api.get("/api/v1/alerts", { limit: 1, sort: "id", order: "desc" }, { quiet: true });
        seenId = data.length ? data[0].id : 0;
      } else {
        await fetchNew();
      }
    } catch (error) {
      if (error.status === 401) return;
    }
    await sleep(POLL_MS, signal);
  }
}

export function startStream() {
  if (running) return;
  running = true;
  controller = new AbortController();
  const { signal } = controller;
  (async () => {
    let failures = 0;
    while (!signal.aborted) {
      try {
        await readStream(signal);
        failures = 0; // clean end of stream: reconnect immediately
      } catch (error) {
        if (signal.aborted || error.fatal) return;
        failures += 1;
        if (error.status === 429 || failures >= FAILURES_BEFORE_POLLING) {
          await poll(signal);
          failures = 0;
          continue;
        }
        setState("reconnecting");
        await sleep(BACKOFF_MS[Math.min(failures - 1, BACKOFF_MS.length - 1)], signal);
      }
    }
  })();
}

export function stopStream() {
  running = false;
  seenId = null;
  if (controller) controller.abort();
  controller = null;
  setState("connecting");
}
