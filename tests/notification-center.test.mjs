import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { setImmediate as settle } from "node:timers/promises";
import { runInNewContext } from "node:vm";
import test from "node:test";
import ts from "typescript";

const require = createRequire(import.meta.url);
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const sources = await Promise.all(["role-workspaces", "notification-center"].map(async (name) => {
  const source = await readFile(new URL(`../app/${name}.tsx`, import.meta.url), "utf8");
  return ts.transpileModule(source, { compilerOptions: { jsx: ts.JsxEmit.React, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
}));

const operation = {
  id: "op/a?b", serverName: "Storage server A", action: "storage.delete", parameters: { path: "/dev/fixture-data", mountpoint: "/srv/fixture-data" },
  reason: "Approved maintenance ticket 123", requestedBy: "alice", requestedById: "alice-id", status: "pending", createdAt: "2026-09-12T10:00:00Z", expiresAt: "2099-01-01T00:00:00Z",
};
const recording = {
  id: "rec/a?b", sessions: [{ label: "SSH fixture session A" }, { label: "RDP fixture session B" }], reason: "Retention ticket 456",
  requestedBy: "alice-id", requestedByUsername: "alice", status: "pending", createdAt: "2026-09-12T11:00:00Z",
};

function text(node) {
  if (node == null || typeof node === "boolean") return "";
  if (typeof node !== "object") return String(node);
  return React.Children.toArray(node.props?.children).map(text).join(" ");
}
function findAll(node, match) {
  if (!node || typeof node !== "object") return [];
  return [...(match(node) ? [node] : []), ...React.Children.toArray(node.props?.children).flatMap((child) => findAll(child, match))];
}

// Run the actual component handlers and approval adapters. Deferred fetch ignores
// abort deliberately: servers and JSON decoding may finish after cancellation.
async function harness(overrides = {}) {
  let slot = 0, tree, dirty = true, mounted = true, now = Date.parse("2026-09-12T12:00:00Z"), timerId = 0, writesAfterUnmount = 0;
  const slots = [], effects = [], timers = new Map(), listeners = new Map(), calls = [], confirms = [], messages = [];
  const props = { token: "fixture-token", role: "admin", userId: "bob-id", permissions: ["deletions.approve", "recordings.delete"], openApprovals() {}, notify(message) { messages.push(message); }, ...overrides };
  const sameDeps = (previous, next) => previous && next && previous.length === next.length && previous.every((value, index) => Object.is(value, next[index]));
  const hooks = { ...React,
    useState(initial) {
      const index = slot++;
      const entry = slots[index] ??= { value: typeof initial === "function" ? initial() : initial };
      return [entry.value, (next) => {
        if (!mounted) writesAfterUnmount++;
        const value = typeof next === "function" ? next(entry.value) : next;
        if (!Object.is(value, entry.value)) { entry.value = value; dirty = true; }
      }];
    },
    useRef(initial) { const index = slot++; return slots[index] ??= { current: initial }; },
    useCallback(callback, deps) {
      const index = slot++;
      if (!sameDeps(slots[index]?.deps, deps)) slots[index] = { callback, deps };
      return slots[index].callback;
    },
    useEffect(effect, deps) {
      const index = slot++;
      if (!sameDeps(slots[index]?.deps, deps)) {
        const previous = slots[index];
        const entry = slots[index] = { deps, cleanup: null };
        effects.push(() => { previous?.cleanup?.(); entry.cleanup = effect(); });
      }
    },
  };
  const api = {};
  const component = {};
  const fakeWindow = {
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, { callback, delay, repeat: false }); return id; },
    setInterval(callback, delay) { const id = ++timerId; timers.set(id, { callback, delay, repeat: true }); return id; },
    clearTimeout(id) { timers.delete(id); }, clearInterval(id) { timers.delete(id); },
    addEventListener(name, callback) { const entries = listeners.get(name) ?? new Set(); entries.add(callback); listeners.set(name, entries); },
    removeEventListener(name, callback) { listeners.get(name)?.delete(callback); },
    confirm(message) { confirms.push(message); return result.confirmAnswer; },
  };
  const fetch = (url, options = {}) => new Promise((resolve, reject) => { calls.push({ url, options, resolve, reject, done: false }); });
  class ClockDate extends Date {
    constructor(...values) { super(...(values.length ? values : [now])); }
    static now() { return now; }
  }
  const globals = { React, fetch, window: fakeWindow, Date: ClockDate, Error, AbortController, Element: class {}, require: (name) => name === "react" ? hooks : name === "./role-workspaces" ? api : require(name) };
  runInNewContext(sources[0], { ...globals, exports: api });
  runInNewContext(sources[1], { ...globals, exports: component });
  function render() {
    for (let passes = 0; dirty && mounted; passes++) {
      assert.ok(passes < 20, "hook fixture did not settle");
      dirty = false; slot = 0;
      tree = component.NotificationCenter(props);
      while (effects.length) effects.shift()();
    }
  }
  async function flush() { for (let pass = 0; pass < 3; pass++) { await settle(); render(); } }
  async function trigger(delay) {
    for (const [id, timer] of [...timers]) {
      if (timer.delay !== delay) continue;
      if (!timer.repeat) timers.delete(id);
      timer.callback();
    }
    await flush();
  }
  const result = {
    calls, confirms, messages, confirmAnswer: true,
    get html() { render(); return renderToStaticMarkup(tree); },
    get items() { render(); return findAll(tree, (node) => node.props?.className === "notif-item"); },
    get toasts() { render(); return findAll(tree, (node) => node.props?.className === "notif-toast"); },
    get posts() { return calls.filter((call) => call.options.method === "POST"); },
    get pendingGets() { return calls.filter((call) => !call.done && call.options.method !== "POST"); },
    get writesAfterUnmount() { return writesAfterUnmount; },
    get timerCount() { return timers.size; },
    setNow(value) { now = Date.parse(value); dirty = true; },
    button(label, within) {
      render();
      const buttons = findAll(within ?? tree, (node) => node.type === "button" && text(node) === label);
      assert.ok(buttons.length, `Missing button: ${label}`);
      return buttons[0];
    },
    async click(button) { button.props.onClick({ stopPropagation() {} }); await flush(); },
    async open() {
      render();
      const bell = findAll(tree, (node) => node.props?.className === "icon-button bell")[0];
      await this.click(bell);
    },
    poll() { return trigger(20_000); },
    deadline() { return trigger(10_000); },
    async reply(call, data, status = 200) { call.done = true; call.resolve(Response.json(data, { status })); await flush(); },
    async fail(call) { call.done = true; call.reject(new Error("Fixture network unavailable")); await flush(); },
    async replyLists(operations = [operation], recordings = [recording], requests = this.pendingGets) {
      for (const call of requests) {
        call.done = true;
        call.resolve(Response.json({ items: call.url.includes("recording-deletion") ? recordings : operations }));
      }
      await flush();
    },
    unmount() {
      for (const entry of slots) entry?.cleanup?.();
      mounted = false;
    },
    flush,
  };
  render();
  await trigger(0);
  return result;
}

async function ready(overrides) { const view = await harness(overrides); await view.replyLists(); await view.open(); return view; }

test("notification approval presents every destructive target, parameters and reason before confirmation", async () => {
  const view = await ready();
  assert.equal(view.items.length, 2);
  for (const expected of [operation.serverName, operation.parameters.path, operation.parameters.mountpoint, operation.reason, ...recording.sessions.map((item) => item.label), recording.reason]) assert.ok(view.html.includes(expected), expected);
  view.confirmAnswer = false;
  for (const item of view.items) await view.click(view.button("Duyệt", item));
  assert.equal(view.posts.length, 0, "Cancel must never submit a destructive approval");
  assert.equal(view.confirms.length, 2);
  const operationConfirm = view.confirms.find((message) => message.includes(operation.serverName));
  for (const expected of [operation.parameters.path, operation.parameters.mountpoint, operation.reason]) assert.ok(operationConfirm.includes(expected), expected);
  const recordingConfirm = view.confirms.find((message) => message.includes(recording.sessions[0].label));
  assert.ok(recordingConfirm.includes(recording.sessions[1].label));
  assert.ok(recordingConfirm.includes(recording.reason));
  view.unmount();
});

test("notification hides expired requests and never offers self-review or unauthorized review", async () => {
  const expired = await harness();
  await expired.replyLists([{ ...operation, expiresAt: "2020-01-01T00:00:00Z" }], []);
  await expired.open();
  assert.equal(expired.items.length, 0);
  assert.match(expired.html, /Không có yêu cầu nào/);
  expired.unmount();
  for (const overrides of [{ userId: "alice-id" }, { role: "operator" }, { permissions: ["deletions.request"] }]) {
    const view = await ready(overrides);
    assert.equal(view.items.length, 2);
    assert.equal(findAll(view.items[0], (node) => node.type === "button" && ["Duyệt", "Từ chối"].includes(text(node))).length, 0);
    assert.equal(findAll(view.items[1], (node) => node.type === "button" && ["Duyệt", "Từ chối"].includes(text(node))).length, 0);
    assert.equal(view.posts.length, 0);
    view.unmount();
  }
});

test("notification rechecks expiry before posting a previously rendered approval", async () => {
  const view = await ready();
  const row = view.items.find((item) => text(item).includes(operation.serverName));
  const button = view.button("Duyệt", row);
  view.setNow("2100-01-01T00:00:00Z");
  await view.click(button);
  assert.equal(view.posts.length, 0);
  assert.equal(view.confirms.length, 0);
  view.unmount();
});

test("notification preserves shared review endpoints, encoded identifiers and authorization payloads", async () => {
  for (const kind of ["operation", "recording"]) for (const decision of ["approve", "reject"]) {
    const view = await ready();
    const row = view.items.find((item) => text(item).includes(kind === "operation" ? operation.serverName : recording.sessions[0].label));
    await view.click(view.button(decision === "approve" ? "Duyệt" : "Từ chối", row));
    assert.equal(view.posts.length, 1);
    const request = view.posts[0];
    assert.equal(request.url, kind === "operation" ? `/api/v1/deletion-approvals/${encodeURIComponent(operation.id)}/review` : `/api/v1/recording-deletion-requests/${encodeURIComponent(recording.id)}/${decision}`);
    assert.equal(request.options.body, kind === "operation" ? JSON.stringify({ decision }) : undefined);
    assert.equal(request.options.headers.Authorization, "Bearer fixture-token");
    assert.equal(request.options.headers["Content-Type"], "application/json");
    await view.reply(request, { status: "approved" });
    assert.equal(view.items.length, 1, "Handled item disappears before refresh finishes");
    await view.replyLists([], []);
    view.unmount();
  }
});

test("notification ignores pre-review replies so handled requests cannot reappear", async () => {
  const view = await ready();
  await view.poll();
  const old = [...view.pendingGets];
  assert.equal(old.length, 2);
  const row = view.items.find((item) => text(item).includes(operation.serverName));
  await view.click(view.button("Duyệt", row));
  assert.ok(old.every((request) => request.options.signal.aborted));
  await view.reply(view.posts[0], { status: "approved" });
  const fresh = view.pendingGets.filter((request) => !old.includes(request));
  assert.equal(fresh.length, 2);
  await view.replyLists([], [recording], fresh);
  assert.equal(view.items.length, 1);
  await view.replyLists([operation], [recording], old);
  assert.equal(view.items.length, 1);
  assert.ok(!view.html.includes(operation.parameters.path));
  view.unmount();
});

test("failed notification refresh preserves existing requests and exposes retry instead of false empty state", async () => {
  const view = await ready();
  await view.poll();
  const requests = [...view.pendingGets];
  await view.reply(requests[0], { detail: "Fixture service unavailable" }, 503);
  await view.replyLists([], [], requests.slice(1));
  assert.equal(view.items.length, 2);
  assert.match(view.html, /role="alert"/);
  assert.doesNotMatch(view.html, /Không có yêu cầu nào đang chờ xử lý/);
  const row = view.items.find((item) => text(item).includes(operation.serverName));
  assert.equal(view.button("Duyệt", row).props.disabled, true);
  await view.click(view.button("Duyệt", row));
  assert.equal(view.posts.length, 0);
  await view.click(view.button("Thử tải lại"));
  await view.replyLists();
  assert.doesNotMatch(view.html, /role="alert"/);
  assert.equal(view.button("Duyệt", view.items[0]).props.disabled, false);
  view.unmount();
});

test("notification serializes review across both queues and refreshes after a rejected request", async () => {
  const view = await ready();
  const first = view.button("Duyệt", view.items[0]);
  const second = view.button("Duyệt", view.items[1]);
  await view.click(first);
  await view.click(second); // An old handler or double click must also be guarded.
  assert.equal(view.posts.length, 1);
  assert.equal(view.confirms.length, 1);
  assert.ok(view.items.every((item) => view.button("Duyệt", item).props.disabled));
  await view.reply(view.posts[0], { detail: "Request already reviewed" }, 409);
  assert.equal(view.pendingGets.length, 2);
  await view.replyLists([], []);
  assert.equal(view.items.length, 0);
  assert.ok(view.messages.includes("Request already reviewed"));
  view.unmount();
});

test("notification toasts disappear after another view handles the request", async () => {
  const view = await harness();
  await view.replyLists([], []);
  await view.poll(); await view.replyLists();
  assert.equal(view.toasts.length, 2);
  await view.poll(); await view.replyLists([], []);
  assert.equal(view.toasts.length, 0);
  view.unmount();
});

test("notification ignores in-flight success and failure after unmount and clears polling", async () => {
  for (const failed of [false, true]) {
    const view = await harness();
    const requests = [...view.pendingGets];
    view.unmount();
    assert.ok(requests.every((request) => request.options.signal.aborted));
    if (failed) await view.fail(requests[0]);
    await view.replyLists([], [], requests.filter((request) => !request.done));
    assert.equal(view.writesAfterUnmount, 0);
    assert.equal(view.timerCount, 0);
  }
});


test("notification distinguishes first-load failure from an empty approval queue", async () => {
  const view = await harness();
  await view.open();
  assert.match(view.html, /Đang tải thông báo/);
  assert.doesNotMatch(view.html, /Không có yêu cầu nào/);
  const requests = [...view.pendingGets];
  await view.fail(requests[0]);
  await view.replyLists([], [], requests.slice(1));
  assert.match(view.html, /role="alert"/);
  assert.doesNotMatch(view.html, /Không có yêu cầu nào/);
  await view.click(view.button("Thử tải lại")); await view.replyLists([], []);
  assert.match(view.html, /Không có yêu cầu nào/);
  assert.doesNotMatch(view.html, /role="alert"/);
  view.unmount();
});

test("notification timeout discards late success without erasing the last approval queue", async () => {
  const view = await ready();
  await view.poll();
  const requests = [...view.pendingGets];
  await view.deadline();
  assert.ok(requests.every((request) => request.options.signal.aborted));
  await view.replyLists([], [], requests);
  assert.equal(view.items.length, 2);
  assert.match(view.html, /role="alert"/);
  view.unmount();
});

test("notification ignores stale request errors after a successful newer refresh", async () => {
  const view = await ready();
  await view.poll(); const old = [...view.pendingGets];
  await view.poll(); const fresh = view.pendingGets.filter((request) => !old.includes(request));
  await view.replyLists([], [], fresh);
  assert.match(view.html, /Không có yêu cầu nào/);
  await view.fail(old[0]); await view.replyLists([], [], old.slice(1));
  assert.doesNotMatch(view.html, /role="alert"/);
  assert.match(view.html, /Không có yêu cầu nào/);
  view.unmount();
});

test("notification does not refresh, notify or write state when review completes after unmount", async () => {
  for (const failed of [false, true]) {
    const view = await ready();
    await view.click(view.button("Duyệt", view.items[0]));
    view.unmount();
    if (failed) await view.fail(view.posts[0]);
    else await view.reply(view.posts[0], { status: "approved" });
    assert.equal(view.pendingGets.length, 0);
    assert.equal(view.messages.length, 0);
    assert.equal(view.writesAfterUnmount, 0);
    assert.equal(view.timerCount, 0);
  }
});
