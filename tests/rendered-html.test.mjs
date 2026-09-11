import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { setImmediate as waitForImmediate } from "node:timers/promises";
import { runInNewContext } from "node:vm";
import test from "node:test";
import { createRequire } from "node:module";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(new Request("http://localhost/", { headers: { accept: "text/html" } }), { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } }, { waitUntil() {}, passThroughOnException() {} });
}

test("manual connection Add controls render only for Admin and Operator", async () => {
  const { default: ts } = await import("typescript");
  const require = createRequire(import.meta.url);
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const source = await readFile(new URL("../app/managed-targets.tsx", import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: { jsx: ts.JsxEmit.React, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  const exports = {};
  runInNewContext(compiled, { exports, React, require: (name) => name === "./server-resource-tabs" ? { ModalShell: () => null } : name.startsWith("./managed-") ? {} : require(name) });
  for (const kind of ["network", "web"]) {
    for (const role of ["admin", "operator", "viewer", "connector"]) {
      const html = renderToStaticMarkup(React.createElement(exports.ManagedTargetsView, { kind, role, token: "test", notify() {}, share() {} }));
      assert.equal(html.includes("＋ Thêm kết nối"), ["admin", "operator"].includes(role), `${kind}/${role}`);
      assert.match(html, /Đang tải danh sách kết nối/);
      assert.doesNotMatch(html, /Chưa có kết nối/);
      assert.doesNotMatch(html, /href="https?:/);
    }
  }
});

test("manual SSH and web connect controls remain visible to authorized roles", async () => {
  const { default: ts } = await import("typescript");
  const require = createRequire(import.meta.url);
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const source = await readFile(new URL("../app/managed-targets.tsx", import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: { jsx: ts.JsxEmit.React, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  for (const kind of ["network", "web"]) {
    for (const role of ["admin", "operator", "viewer", "connector"]) {
      const target = { id: "test", name: "Switch test", kind, address: "10.80.2.7", config: null, connectionReady: kind === "network" };
      const values = [[target], null, null, "", "", "", "ready", false, null];
      let index = 0;
      const hooks = { ...React, useState: () => [values[index++], () => {}] };
      const exports = {};
      runInNewContext(compiled, { exports, React, require: (name) => name === "react" ? hooks : {} });
      const html = renderToStaticMarkup(React.createElement(exports.ManagedTargetsView, { kind, role, token: "test", notify() {}, share() {} }));
      assert.equal(html.includes("↗ Kết nối"), role !== "viewer", `${kind}/${role}`);
      assert.doesNotMatch(html, /href="https?:/);
      if (kind === "web") { assert.match(html, /Cần kiểm tra dịch vụ phiên/); assert.match(html, /Máy người dùng chỉ cần truy cập Operation Portal/); }
    }
  }
});

test("managed session popup submits only selected credential ID and handles popup or API errors", async () => {
  const { default: ts } = await import("typescript");
  const require = createRequire(import.meta.url);
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const source = await readFile(new URL("../app/managed-session-modal.tsx", import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: { jsx: ts.JsxEmit.React, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  for (const outcome of ["ok", "forbidden", "popup-blocked", "external-url"]) {
    const values = [[{ id: "credential-id", username: "switch-user", label: "switch-user" }], "credential-id", false, false, ""];
    let index = 0, requests = 0, closed = false, notified = false;
    const errors = [];
    const popup = { opener: {}, location: { href: "about:blank" }, close() { closed = true; } };
    const hooks = { ...React, useEffect() {}, useState: () => { const slot = index++; return [values[slot], (value) => { if (slot === 4) errors.push(value); }]; } };
    const exports = {};
    runInNewContext(compiled, {
      exports, React, URL,
      require: (name) => name === "react" ? hooks : { ModalShell: (props) => React.createElement("div", null, Reflect.get(props, "children")) },
      window: { open: () => outcome === "popup-blocked" ? null : popup, location: { origin: "https://ops.example.test" }, localStorage: { removeItem() {} } },
      fetch: async (_url, options) => {
        requests++;
        assert.deepEqual(JSON.parse(options.body), { server_id: "target-id", protocol: "ssh", credential_id: "credential-id" });
        return outcome === "forbidden" ? Response.json({ detail: "share revoked" }, { status: 403 }) : Response.json({ url: outcome === "external-url" ? "https://outside.example/" : "/guacamole/#/client/test" });
      },
    });
    const tree = exports.ManagedSessionModal({ target: { id: "target-id", name: "Switch", kind: "network" }, token: "test", close() {}, notify() { notified = true; } });
    const html = renderToStaticMarkup(tree);
    assert.match(html, /switch-user/);
    assert.doesNotMatch(html, /type="password"|name="password"|<input/);
    await tree.props.children.props.onSubmit({ preventDefault() {} });
    assert.equal(requests, outcome === "popup-blocked" ? 0 : 1);
    assert.equal(notified, outcome === "ok");
    if (outcome === "ok") assert.equal(popup.location.href, "https://ops.example.test/guacamole/#/client/test");
    else assert.ok(errors.at(-1));
    if (["forbidden", "external-url"].includes(outcome)) assert.equal(closed, true);
  }
});

test("managed target API distinguishes missing deployment from empty data and form errors", async () => {
  const { default: ts } = await import("typescript");
  const source = await readFile(new URL("../app/managed-target-api.ts", import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  const exports = {};
  runInNewContext(compiled, { exports });
  for (const operation of ["list", "create"]) {
    await assert.rejects(exports.readManagedTargetResponse(Response.json({ detail: "Not Found" }, { status: 404 }), operation), /cập nhật đồng bộ API/);
    await assert.rejects(exports.readManagedTargetResponse(new Response("<h1>Not Found</h1>", { status: 404 }), operation), /HTTP 404/);
  }
  await assert.rejects(exports.readManagedTargetResponse(Response.json({}, { status: 404 }), "edit"), /Kết nối không còn tồn tại/);
  await assert.rejects(exports.readManagedTargetResponse(new Response("<html>dashboard</html>"), "list"), /proxy/);
  await assert.rejects(exports.readManagedTargetResponse(Response.json({}), "list"), /định dạng API/);
  await assert.rejects(exports.readManagedTargetResponse(Response.json({}, { status: 401 }), "list"), /đăng nhập lại/);
  await assert.rejects(exports.readManagedTargetResponse(Response.json({}, { status: 403 }), "create"), /không có quyền/);
  const empty = await exports.readManagedTargetResponse(Response.json({ items: [] }), "list");
  assert.equal(empty.items.length, 0);
});

test("Admin and Operator create forms accept initial credentials without exposing saved passwords on edit", async () => {
  const { default: ts } = await import("typescript");
  const require = createRequire(import.meta.url);
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const source = await readFile(new URL("../app/managed-targets.tsx", import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: { jsx: ts.JsxEmit.React, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  for (const kind of ["network", "web"]) {
    for (const role of ["admin", "operator"]) {
      for (const creating of [true, false]) {
        let index = 0;
        const editing = creating ? "new" : { id: "existing", config: { name: "existing", kind, url: "https://vcenter.example.test/ui/", address: "10.80.2.7", port: 22, ssh_legacy_compatibility: true } };
        const values = [[], editing, null, "", "", "", "ready", false];
        const hooks = { ...React, useState: () => [values[index++], () => {}] };
        const exports = {};
        runInNewContext(compiled, { exports, React, require: (name) => name === "react" ? hooks : name === "./server-resource-tabs" ? { ModalShell: (props) => React.createElement("div", null, Reflect.get(props, "children")) } : {} });
        const html = renderToStaticMarkup(React.createElement(exports.ManagedTargetsView, { kind, role, token: "test", notify() {}, share() {} }));
        assert.equal(html.includes('name="username"'), creating, `${kind}/${role}/${creating}`);
        assert.equal(html.includes('type="password"'), creating);
        assert.equal(html.includes('name="address"'), kind === "network");
        assert.equal(html.includes('name="port"'), kind === "network");
        assert.equal(html.includes('name="url"'), kind === "web");
        assert.equal(html.includes('name="web_allowed_origins"'), kind === "web");
        assert.doesNotMatch(html, /name="web_ignore_https_errors"|Cho phép chứng thư HTTPS không hợp lệ/);
        if (kind === "web") {
          assert.match(html, /URL website \(HTTP hoặc HTTPS\)/);
          assert.match(html, /tự xử lý chứng thư/);
          assert.equal(/<textarea(?=[^>]*name="web_allowed_origins")(?=[^>]*readonly)[^>]*>/i.test(html), role !== "admin");
        }
        assert.doesNotMatch(html, /name="ssh_legacy_compatibility"|Chỉ bật cho thiết bị cũ/);
        assert.equal(html.includes("SSH tự thương lượng"), kind === "network");
        assert.doesNotMatch(html, /ssh_host_key|SSH public host key/);
      }
    }
  }
});

test("managed form needs no SSH toggle and never submits obsolete flags from saved targets", async () => {
  const { default: ts } = await import("typescript");
  const require = createRequire(import.meta.url);
  const React = require("react");
  const source = await readFile(new URL("../app/managed-targets.tsx", import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: { jsx: ts.JsxEmit.React, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  function findForm(node) {
    if (!node || typeof node !== "object") return null;
    if (node.type === "form") return node;
    for (const child of React.Children.toArray(node.props?.children)) {
      const found = findForm(child);
      if (found) return found;
    }
    return null;
  }
  for (const kind of ["network", "web"]) {
    for (const creating of [true, false]) {
      for (const oldFlag of [undefined, true, false]) {
        const editing = creating ? "new" : { id: "existing", config: { kind, ssh_legacy_compatibility: oldFlag } };
        const values = [[], editing, null, "", "", "", "ready", false, null];
        let index = 0;
        const submitted = [];
        const exports = {};
        const hooks = { ...React, useEffect() {}, useCallback: (fn) => fn, useState: () => [values[index++], () => {}] };
        runInNewContext(compiled, {
          exports, React,
          require: (name) => name === "react" ? hooks : name === "./managed-target-api" ? { readManagedTargetResponse: (response) => response.json() } : { ModalShell: () => null },
          FormData: class { constructor(values) { this.values = values; } get(key) { return this.values[key] ?? null; } },
          fetch: async (_url, options) => { if (options.body) submitted.push(JSON.parse(options.body)); return Response.json({ items: [], saved: true }); },
        });
        const tree = exports.ManagedTargetsView({ kind, role: "operator", token: "test", notify() {}, share() {} });
        await findForm(tree).props.onSubmit({ preventDefault() {}, currentTarget: { name: "Switch", address: "10.80.2.7", port: "22", url: "https://console.example.test/", username: "fixture", password: "fixture" } });
        assert.equal(submitted.length, 1);
        assert.equal("ssh_legacy_compatibility" in submitted[0], false);
        assert.equal(Boolean(submitted[0].credential), creating);
      }
    }
  }
});

test("managed catalog never shows empty-state text during loading or API failure", async () => {
  const { default: ts } = await import("typescript");
  const require = createRequire(import.meta.url);
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const source = await readFile(new URL("../app/managed-targets.tsx", import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: { jsx: ts.JsxEmit.React, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  for (const state of ["loading", "error", "ready"]) {
    let index = 0;
    // Inject hook state into a server-rendered fixture; no browser or production API.
    const values = [[], null, null, "", "", state === "error" ? "API chưa có chức năng (HTTP 404)" : "", state, false];
    const hooks = { ...React, useState: () => [values[index++], () => {}] };
    const exports = {};
    runInNewContext(compiled, { exports, React, require: (name) => name === "react" ? hooks : name === "./server-resource-tabs" ? { ModalShell: () => null } : {} });
    const html = renderToStaticMarkup(React.createElement(exports.ManagedTargetsView, { kind: "network", role: "connector", token: "test", notify() {}, share() {} }));
    assert.equal(html.includes("Chưa có kết nối được chia sẻ"), state === "ready");
    assert.equal(html.includes("Thử lại"), state === "error");
    assert.equal(html.includes("Đang tải danh sách"), state === "loading");
  }
});

test("primary toolbar buttons retain contrasting action backgrounds in both themes", async () => {
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(styles, /\.inline-actions button:not\(\.primary\):not\(\.danger\)/);
  assert.match(styles, /html\[data-theme="light"\] \.button\.primary\s*\{[^}]*background: var\(--action-primary-bg\) !important/s);
  assert.match(styles, /\.inline-actions \.button\s*\{[^}]*min-height: 36px/s);
  const luminance = (hex) => {
    const rgb = hex.match(/[a-f0-9]{2}/gi).map((value) => parseInt(value, 16) / 255).map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
    return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
  };
  const backgrounds = [...styles.matchAll(/--action-primary-(?:bg|hover): (#[a-f0-9]{6});/g)].map((match) => match[1]);
  assert.equal(backgrounds.length, 4);
  for (const background of backgrounds) assert.ok(1.05 / (luminance(background) + 0.05) >= 4.5, `White text on ${background}`);
});

test("navigation policy enforces connector/auditor categories even with stale permissions", async () => {
  const { default: ts } = await import("typescript");
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const nav = source.slice(source.indexOf("const navItems:"), source.indexOf("const healthLabel:"));
  const compiled = ts.transpileModule(nav + "\nexports.allowed = (user) => navItems.filter(item => navigationAllowed(item, user)).map(item => item.id);", { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  const exports = {};
  runInNewContext(compiled, { exports });
  const permissions = ["servers.view", "resources.view", "recordings.view", "audit.view", "logs.view", "users.manage", "roles.manage", "ldap.manage", "sessions.launch", "agents.manage", "updates.manage", "jobs.view", "deletions.request", "configuration.view"];
  assert.deepEqual(Array.from(exports.allowed({ role: "connector", permissions })), ["linux", "windows", "network", "web"]);
  assert.deepEqual(Array.from(exports.allowed({ role: "auditor", permissions })), ["audit"]);
  for (const role of ["admin", "operator", "viewer", "auditor", "connector", "custom"]) {
    assert.ok(!exports.allowed({ role, permissions }).includes("logs"), `${role}: no standalone server logs menu`);
  }
  assert.doesNotMatch(nav, /Log máy chủ/);
  const operator = exports.allowed({ role: "operator", permissions });
  assert.ok(!operator.includes("remote-credentials"));
  assert.ok(operator.includes("approvals"));
});

test("retired server logs hashes fall back safely while per-server logs remain", async () => {
  const { default: ts } = await import("typescript");
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const nav = source.slice(source.indexOf("const navItems:"), source.indexOf("const healthLabel:"));
  const routeStart = source.lastIndexOf("  useEffect(() => {", source.indexOf("const allowedNavigation ="));
  const routeEnd = "  }, [servers, token, currentUser]);";
  const route = source.slice(routeStart, source.indexOf(routeEnd, routeStart) + routeEnd.length);
  const compiled = ts.transpileModule(nav + route, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  const permissions = ["servers.view", "logs.view", "audit.view"];
  for (const role of ["admin", "operator", "viewer", "auditor", "connector", "custom"]) {
    for (const hash of ["#/logs", "#logs", "#/logs/"]) {
      let active, selected, replaced;
      runInNewContext(compiled, {
        token: "test", currentUser: { role, permissions }, servers: [],
        useEffect: (callback) => callback()(),
        setActive: (value) => { active = value; },
        setSelected: (value) => { selected = value; },
        sectionRoute: (section) => `#/${section}`,
        window: { location: { hash }, history: { replaceState: (_state, _title, url) => { replaced = url; } }, addEventListener() {}, removeEventListener() {} },
      });
      const expected = role === "auditor" ? "audit" : role === "connector" ? "linux" : "overview";
      assert.equal(active, expected, `${role}/${hash}`);
      assert.equal(replaced, `#/${expected}`);
      assert.equal(selected, null);
    }
  }
  assert.match(source, /\{ id: "logs", label: "Nhật ký", icon: "≡" \}/);
  assert.match(source, /<LogsResourceTab\b/);
});

test("server-renders the secure operations console shell", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  const html = await response.text();
  assert.match(html, /<title>Operation Portal<\/title>/i);
  assert.match(html, /Đang kiểm tra cấu hình hệ thống/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("dashboard includes automatic Windows and Linux fleet views", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const resources = await readFile(new URL("../app/server-resource-tabs.tsx", import.meta.url), "utf8");
  assert.match(source, /Máy chủ Linux/);
  assert.match(source, /Máy chủ Windows/);
  assert.match(source, /server\.osFamily === scope/);
  assert.match(source, /\/api\/v1\/servers/);
  assert.match(source, /Phiên truy cập/);
  assert.match(source, /Nhật ký kiểm toán/);
  assert.match(source, /serverRoute\(server\)/);
  assert.match(source, /Truyền file/);
  assert.match(resources, /service\.restart/);
  assert.match(source, /firewall\.list/);
  assert.match(resources, /Disk & Volumes/);
  assert.match(resources, /Users & Groups/);
  assert.match(resources, /patch\.install/);
  assert.match(resources, /objectArray\(value\.partitions\)\.map\(normalizeStorageNode\)/);
  assert.match(resources, /objectArray\(payload\.updates\)/);
  assert.match(resources, /process\.kill/);
  assert.match(resources, /Tối đa 500 dòng/);
  assert.match(source, /\/api\/v1\/setup\/status/);
  assert.match(source, /Kết nối kho dữ liệu/);
  assert.match(source, /Admin local đầu tiên/);
});

test("resource dialogs fit the viewport and scroll internally", async () => {
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(styles, /\.resource-modal\s*{[^}]*max-height:\s*calc\(100vh - 16px\)/s);
  assert.match(styles, /\.resource-modal\s*{[^}]*max-height:\s*calc\(100dvh - 16px\)/s);
  assert.match(styles, /\.resource-modal\s*{[^}]*max-height:\s*100%/s);
  assert.match(styles, /\.resource-modal-body\s*{[^}]*overflow:\s*auto/s);
  assert.match(styles, /\.resource-modal-footer\s*{[^}]*flex:\s*0 0 auto/s);
  assert.match(source, /id="ldap-settings-form"/);
  assert.match(source, /form="ldap-settings-form"/);
  assert.match(source, /className="ldap-settings-modal"/);
  assert.match(styles, /\.storage-tree\s*{[^}]*overflow:\s*auto/s);
  assert.match(styles, /\.resource-table-scroll\s*{[^}]*overflow:\s*auto/s);
  assert.match(styles, /\.login-card\s*{[^}]*max-height:\s*calc\(100dvh - 24px\)/s);
  assert.match(styles, /\.login-card\s*{[^}]*overflow-y:\s*auto/s);
});

test("Windows and Linux fleets can queue OS-aware common tasks", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /Tạo task chung/);
  assert.match(source, /\/api\/v1\/bulk-tasks/);
  assert.match(source, /firewall\.rule\.add\.auto/);
  assert.match(source, /Windows dùng group Administrators theo SID/);
  assert.match(source, /Oracle Linux\/Red Hat chọn default firewalld zone/);
  assert.match(source, /server_ids:\s*targetIds/);
  assert.match(source, /initialServerIds=\{selectedServerIds\}/);
});

test("firewall add form uses server capabilities and a viewport-safe scroll region", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(source, /Dữ liệu trực tiếp từ máy chủ/);
  assert.match(source, /Profile Windows Firewall/);
  assert.match(source, /Zone firewalld/);
  assert.match(source, /Filter chain trên máy chủ/);
  assert.match(source, /capabilities\.targets\.map/);
  assert.match(source, /hệ thống đang tự quét lại danh sách/);
  assert.match(source, /Thực thi trực tiếp có kiểm soát/);
  assert.match(source, /Đang chờ Agent nhận tác vụ/);
  assert.match(source, /chi tiết từ Agent ở bên dưới/);
  assert.match(source, /job-error-output/);
  assert.match(source, /Exit code/);
  assert.match(source, /autoRefreshForLatestMutation\.status !== "succeeded"/);
  assert.doesNotMatch(source, /\/api\/v1\/jobs\/\$\{jobId\}\/approve/);
  const addForm = source.slice(source.indexOf("function FirewallAddModal"), source.indexOf("function SessionsView"));
  assert.doesNotMatch(addForm, /deletion-approvals/);
  assert.doesNotMatch(source, /Table<input name="table"/);
  assert.doesNotMatch(source, /Chain<input name="chain"/);
  assert.match(styles, /\.add-firewall-modal\s*{[^}]*max-height:\s*calc\(100% - 32px\)/s);
  assert.match(styles, /\.firewall-add-scroll\s*{[^}]*overflow-y:\s*auto/s);
});

test("firewall rules are searchable and filterable", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /aria-label="Tìm firewall rule"/);
  assert.match(source, /firewallActionFilter/);
  assert.match(source, /firewallDirectionFilter/);
  assert.match(source, /firewallStateFilter/);
  assert.match(source, /firewallBackendFilter/);
  assert.match(source, /filteredFirewallRules\.map/);
});

test("recording deletion requires a distinct second administrator", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /recording-deletion-requests/);
  assert.match(source, /Người tạo yêu cầu không được tự duyệt/);
  assert.match(source, /Chờ quản trị viên khác/);
  assert.match(source, /Gửi yêu cầu xóa/);
  assert.match(source, /selectedRecordingIds/);
  assert.match(source, /Lý do \/ ticket là bắt buộc/);
  assert.match(source, /settings\/recording-retention/);
  assert.match(source, /Mặc định 180 ngày/);
});

test("storage resize stays explicit and Updates shows only patches", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const resources = await readFile(new URL("../app/server-resource-tabs.tsx", import.meta.url), "utf8");
  const updateSettings = await readFile(new URL("../app/update-source-settings.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(resources, /<span>Thao tác<\/span>/);
  assert.match(resources, /<span>Có thể Extend thêm<\/span>/);
  assert.match(resources, /unallocated \? formatBytes\(node\.sizeBytes\) : formatBytes\(extendCapacity\)/);
  assert.doesNotMatch(resources, /unallocated \? formatBytes\(node\.sizeBytes\) : formatBytes\(node\.freeBytes\)/);
  assert.match(resources, /đây không phải dung lượng còn trống bên trong filesystem/);
  assert.match(resources, /disabled=\{!canExtend\}/);
  assert.match(resources, /partition Recovery hoặc partition khác đang nằm ở giữa/);
  assert.match(resources, /logicalVolumeMapperPath\(item\) === node\.path/);
  assert.match(resources, /Unallocated không thể kéo thả/);
  assert.match(resources, /queue\("storage\.shrink"/);
  assert.match(resources, /Thứ tự vật lý các phân vùng/);
  assert.match(resources, /type === "unallocated"/);
  assert.match(resources, /Shrink không di chuyển phần đang chắn/);
  assert.match(resources, /Agent dùng DiskPart giống Disk Management/);
  assert.equal((resources.match(/\/ 512\) \* 512/g) || []).length, 2);
  assert.match(resources, /Logical Volumes/);
  assert.match(resources, /Extend LV/);
  assert.match(resources, /min=\{selectedExtendMinGiB\} step="any"/);
  assert.match(resources, /if \(selected.kind === "windows_partition"\) \{\s*parameters.disk_number = selected.diskNumber;\s*parameters.partition_number = selected.partitionNumber;/);
  assert.doesNotMatch(resources, /if \(selected.partitionNumber !== undefined\) parameters.partition_number/);
  assert.match(resources, /minimumLinuxFilesystemBytes = \(createFilesystem === "xfs" \? 300 : 16\)/);
  assert.match(resources, /Volume Linux tự động \(khuyến nghị\)/);
  assert.match(resources, /rescan disk → mở rộng partition PV liền kề → pvresize\/VG → LV/);
  assert.match(resources, /Agent tự tạo mount point, ghi UUID vào \/etc\/fstab theo kiểu atomic/);
  assert.doesNotMatch(resources, /Sau khi hệ thống tự quét lại, chọn đúng Logical Volume/);
  assert.doesNotMatch(resources, /max=\{\(bytes\(selected\.extendableBytes\) \/ 1024 \*\* 3\)\.toFixed\(3\)\}/);
  assert.match(resources, /resizeProtected: Boolean\(node\.resizeProtected\)/);
  assert.doesNotMatch(resources, /Windows Update API/);
  assert.doesNotMatch(resources, /Configuration Manager/);
  assert.match(resources, /objectArray\(payload\.updates\)/);
  assert.match(resources, /diagnostics\.currentScanComplete === true/);
  assert.doesNotMatch(resources, /Chưa thể kết luận máy có 0 bản cập nhật/);
  assert.doesNotMatch(resources, /Đang hiển thị dữ liệu hoàn tất gần nhất/);
  assert.match(resources, /Không có Internet/);
  assert.match(resources, /Mất kết nối WSUS/);
  assert.match(resources, /Không kết nối được repository/);
  assert.match(resources, /Phiên bản hệ điều hành/);
  assert.doesNotMatch(resources, /Nguồn cập nhật của máy chủ/);
  assert.doesNotMatch(resources, /patch\.source\.configure/);
  assert.match(source, /label: "Cấu hình cập nhật"/);
  assert.match(updateSettings, /Cấu hình nguồn cập nhật/);
  assert.match(updateSettings, /Microsoft Update qua Internet/);
  assert.match(updateSettings, /Ép dùng WSUS/);
  assert.match(updateSettings, /Repo Oracle Linux nội bộ/);
  assert.match(updateSettings, /Docker, PPA và repo ứng dụng khác được giữ nguyên/);
  assert.match(updateSettings, /URL Pulp Distribution cho từng nguồn Ubuntu/);
  assert.match(updateSettings, /Base, Updates và Security là bắt buộc; Backports để trống nếu chưa đồng bộ/);
  assert.match(updateSettings, /Chữ màu xám trong ô chỉ là ví dụ, không phải dữ liệu đã lưu/);
  assert.match(updateSettings, /onSubmit=\{applySources\} noValidate/);
  assert.match(updateSettings, /setMessage\(formValidationMessage\)/);
  assert.match(updateSettings, /disabled=\{Boolean\(busy\)\}/);
  assert.match(updateSettings, /repositories: ubuntuRepositorySuites/);
  assert.match(updateSettings, /\/api\/v1\/bulk-update-sources\/catalog/);
  assert.match(updateSettings, /"patch\.source\.configure"/);
  assert.match(updateSettings, /\/api\/v1\/settings\/update-sources/);
  assert.match(updateSettings, /persistSourceProfile/);
  assert.match(updateSettings, /Lưu cấu hình mẫu/);
  assert.match(updateSettings, /Áp dụng \(\$\{selectedIds\.length\} máy\)/);
  assert.match(updateSettings, /SOURCE_READ_POLL_INTERVAL_MS/);
  assert.match(updateSettings, /Đang chờ Agent đọc nguồn/);
  assert.match(updateSettings, /Kết quả và các ô URL sẽ tự xuất hiện/);
  assert.match(updateSettings, /setSourceReadWatch\(\{ profileKey: selectedProfile\.key/);
  assert.doesNotMatch(updateSettings, /Lưu và áp dụng/);
  const applySourceBody = updateSettings.match(/async function applySources[\s\S]*?\n\s{2}const savedProfile/)?.[0] ?? "";
  assert.match(applySourceBody, /createBulkTask\("patch\.source\.configure"/);
  assert.doesNotMatch(applySourceBody, /persistSourceProfile/);
  assert.doesNotMatch(updateSettings, /mode: "custom",\s*wsus_url: "",\s*repositories: ubuntuRepositorySuites/);
  assert.doesNotMatch(updateSettings, /wsusUrl\.trim\(\) : "", repositories: \[\]/);
  assert.match(styles, /input:not\(\[type="checkbox"\]\):not\(\[type="radio"\]\)/);
  assert.match(styles, /\.update-settings-layout\s*{[^}]*grid-template-columns:/s);
  assert.match(source, /"patch\.source\.read": "Đọc nguồn cập nhật"/);
  assert.match(source, /"patch\.source\.configure": "Cấu hình nguồn cập nhật"/);
  assert.match(source, /successfulUpdateScanJobs/);
  assert.match(source, /Cập nhật bản vá theo OS \+ version/);
  assert.match(source, /\/api\/v1\/bulk-update\/catalog/);
  assert.match(source, /Tiếp: Chọn patch/);
  assert.match(source, /Patch chung cho toàn bộ máy đã chọn/);
  assert.match(source, /Chi tiết thao tác/);
  assert.match(source, /Tải thêm nhật ký/);
  assert.match(source, /tự động dọn dữ liệu cũ sau \{auditRetentionDays\} ngày/);
  assert.match(source, /loadServers\(true\)/);
});

test("platform users, LDAP assignments and custom roles are editable", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(source, /Tạo tài khoản Local/);
  assert.match(source, /Cấu hình LDAP \/ Active Directory/);
  assert.match(source, /Đồng bộ AD/);
  assert.match(source, /settings\/ldap\/users\/sync/);
  assert.match(source, /user\.source === "ldap" \? "AD" : "Local"/);
  assert.match(source, /gán mọi role hiện có/);
  assert.doesNotMatch(source, /xuất hiện sau lần đăng nhập Domain đầu tiên/);
  assert.match(source, /Roles & quyền hạn/);
  assert.match(source, /permission-groups/);
  assert.match(source, /Groups của trạm vận hành/);
  assert.match(source, /allowed_group_dns/);
  assert.match(source, /Quét groups/);
  assert.match(source, /platform-groups/);
  assert.match(source, /method: "PATCH"/);
  assert.match(source, /method: "DELETE"/);
  assert.match(source, /Thông tin tài khoản/);
  assert.match(source, /\/api\/v1\/me\/profile/);
  assert.match(source, /\/api\/v1\/me\/password/);
  assert.match(source, /name="current_password"/);
  assert.match(source, /Role và tên đăng nhập không bị thay đổi/);
  assert.match(source, /Tên hiển thị và mật khẩu của tài khoản AD được quản lý tại Active Directory/);
  assert.match(source, /\/api\/v1\/users\/\$\{user\.id\}\/mfa/);
  assert.match(source, /currentUser\.role === "admin"/);
  assert.match(source, />Reset MFA<\/button>/);
  assert.match(source, /Lần đăng nhập sau sẽ hiển thị QR mới/);
  assert.match(source, /LDAPS bắt buộc/);
  assert.match(source, /use_ssl: true/);
  assert.doesNotMatch(source, /name="use_ssl"/);
  assert.match(styles, /\.account-settings-modal\s*{[^}]*width:\s*min\(720px, calc\(100vw - 16px\)\)/s);
  assert.match(styles, /\.account-identity-summary\s*{[^}]*grid-template-columns:\s*repeat\(2, minmax\(0, 1fr\)\)/s);
});

test("dashboard authentication uses a revocable HttpOnly cookie instead of web storage", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /COOKIE_SESSION_MARKER = "cookie-session"/);
  assert.match(source, /\/api\/v1\/auth\/logout/);
  assert.match(source, /"X-Tram-Auth-Mode": "cookie"/);
  assert.doesNotMatch(source, /sessionStorage/);
  assert.doesNotMatch(source, /tram_ops_token/);
});

test("process resources and server visibility controls are operable", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const resources = await readFile(new URL("../app/server-resource-tabs.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(resources, /cpuPercent/);
  assert.match(resources, /memoryBytes/);
  assert.match(resources, /Realtime 5s/);
  assert.match(resources, /refreshRef\.current/);
  assert.match(resources, /jobRef\.current/);
  assert.match(resources, /job\?\.status === "failed" && <PendingState job=\{job\}/);
  assert.match(resources, /Đã khóa \/ disable/);
  assert.match(resources, /Unlock tài khoản/);
  assert.match(source, /Share \$\{server\.name\}/);
  assert.match(source, /Xóa máy chủ/);
  assert.match(source, />Delete<\/button>/);
  assert.match(source, /<JobsView token=\{token\} servers=\{servers\}/);
  assert.match(source, /new Map\(servers\.map\(\(server\) => \[server\.id, server\]\)\)/);
  assert.match(source, /currentServer\?\.name \|\| job\.serverName \|\| job\.serverId\.slice/);
  assert.match(source, /currentServer\?\.address \|\| job\.serverAddress \|\| "chưa có IP"/);
  assert.match(source, /serverIdentity\(job\)/);
  assert.match(source, /className="job-server-hostname"/);
  assert.match(source, /className="job-server-address"/);
  assert.match(styles, /\.job-server-label\s*{[^}]*gap:\s*7px/s);
  assert.match(styles, /\.job-server-hostname\s*{[^}]*color:\s*#f4f7ff;[^}]*font-weight:\s*700/s);
  assert.match(styles, /\.job-server-address\s*{[^}]*color:\s*#66b7ff;[^}]*font-weight:\s*400/s);
  assert.match(styles, /\.server-delete-button\s*{[^}]*min-height:\s*30px/s);
  assert.match(source, /servers\.manage/);
  assert.match(source, /\/api\/v1\/audit\?limit=6/);
  assert.match(source, /overview-activity-list/);
  assert.match(source, /File tối đa 1 GiB/);
  assert.match(source, /const formElement = event\.currentTarget/);
  assert.match(source, /currentUser\.permissions\.includes\("logs\.configure"\)/);
  assert.match(source, /audit-filter-bar/);
  assert.match(source, /visibleAuditRows/);
});

test("job and audit action codes have readable labels", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /"file\.deliver": "Truyền file an toàn tới máy chủ"/);
  assert.match(source, /"process\.list": "Đọc danh sách tiến trình"/);
  assert.match(source, /jobActionLabel\(job\.action\)/);
  assert.match(source, /auditActionLabel\(event\.action, event\.detail\)/);
  assert.match(source, /auditActionLabel\(row\.action, row\.detail\)/);
  assert.match(source, /action === "job\.succeeded"/);
});

test("overview health chart uses live fleet percentages and the operator system theme", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(source, /function healthPercentages/);
  assert.match(source, /healthyCount = servers\.filter/);
  assert.match(source, /warningCount = servers\.filter/);
  assert.match(source, /criticalCount = servers\.filter/);
  assert.match(source, /--healthy-end/);
  assert.match(source, /--warning-end/);
  assert.match(source, /Trạng thái hiện tại của toàn bộ máy chủ/);
  assert.match(source, /Cập nhật \{systemClock\}/);
  assert.match(source, /setInterval\(updateSystemAppearance, 1_000\)/);
  assert.doesNotMatch(source, />24 giờ/);
  assert.doesNotMatch(source, />7 ngày</);
  assert.doesNotMatch(source, /aria-label="Thông báo"/);
  assert.doesNotMatch(source, /className="help"/);
  assert.match(source, /themeForSystemTime/);
  assert.match(source, /document\.documentElement\.dataset\.theme = nextTheme/);
  assert.match(styles, /html\[data-theme="light"\]/);
  assert.match(styles, /\.donut\s*{[^}]*--healthy-end:[^}]*--warning-end:/s);
  assert.match(styles, /\.donut\.empty\s*{[^}]*background:\s*var\(--line\)/s);
});

test("clock and phrase search work with Vietnamese or English text", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const resources = await readFile(new URL("../app/server-resource-tabs.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(source, /role="timer"/);
  assert.match(source, /function normalizeSearchText/);
  assert.match(source, /\.normalize\("NFD"\)/);
  assert.match(source, /replace\(\/\\p\{M\}\/gu, ""\)/);
  assert.match(source, /const \[jobSearch, setJobSearch\] = useState\(""\)/);
  assert.match(source, /jobActionLabel\(job\.action\)/);
  assert.match(source, /const visibleAuditRows = useMemo/);
  assert.match(source, /auditActionLabel\(row\.action, row\.detail\)/);
  assert.match(source, /hiddenAuditDetailKeys/);
  assert.match(source, /!hiddenAuditDetailKeys\.has/);
  assert.match(source, /Từ\/cụm từ tiếng Việt hoặc English/);
  assert.match(styles, /\.jobs-toolbar\s*{/);
  assert.doesNotMatch(source, /PostgreSQL|Nginx|Caddy|ClamAV|SECURE CONTROL PLANE|CONTROL PLANE ·/);
  assert.doesNotMatch(resources, /PostgreSQL/);
});

test("light theme keeps legacy and semantic text readable across the dashboard", async () => {
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\([\s\S]*?h1,[\s\S]*?textarea[\s\S]*?\)\s*{\s*color:\s*var\(--ink\)\s*!important;/s,
  );
  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\([\s\S]*?\.job-server-address,[\s\S]*?\)\s*{\s*color:\s*var\(--blue\)\s*!important;/s,
  );
  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\([\s\S]*?\.job-server-hostname,[\s\S]*?\)\s*{\s*color:\s*var\(--ink\)\s*!important;/s,
  );
  assert.match(
    styles,
    /\.operation-result \*,[\s\S]*?\.recording-screen\s*\)[\s\S]*?background:\s*#0f172a\s*!important;[\s\S]*?color:\s*#e6edf7\s*!important;/s,
  );
  assert.doesNotMatch(styles, /\.recording-screen\s+\*/);
  assert.match(styles, /html\[data-theme="light"\] \.recording-screen > p\s*{[^}]*background:\s*transparent\s*!important;[^}]*color:\s*#e47a82\s*!important;/s);
  assert.match(styles, /html\[data-theme="light"\][\s\S]*?\.jobs-row\.head/);
});

test("light theme recolors selectable cards, state badges, and compact controls", async () => {
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");

  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\([\s\S]*?\.bulk-target-list > label,[\s\S]*?\.choice-grid label,[\s\S]*?\)\s*{\s*background:\s*var\(--panel-2\)\s*!important;/s,
  );
  assert.match(styles, /html\[data-theme="light"\] \.bulk-target-list em\s*{[^}]*color:\s*#176a4e\s*!important;[^}]*background:\s*#e5f5ee\s*!important;/s);
  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\([\s\S]*?\.storage-row-actions button:not\(\.primary\):not\(\.danger\),[\s\S]*?\)\s*{\s*background:\s*var\(--panel-2\)\s*!important;/s,
  );
  assert.match(
    styles,
    /html\[data-theme="light"\]\s+:where\(\s*\.search kbd,[\s\S]*?\)\s*{\s*background:\s*#e3edf8\s*!important;[\s\S]*?color:\s*var\(--blue\)\s*!important;/s,
  );
});

test("dashboard shell fits the viewport without global zoom", async () => {
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.doesNotMatch(styles, /body\s*{[^}]*zoom:/s);
  assert.match(styles, /--font-size-increase:\s*3px/);
  assert.doesNotMatch(styles, /font-size:\s*\d+px/);
  assert.match(styles, /font-size:\s*calc\(14px \+ var\(--font-size-increase\)\)/);
  assert.match(styles, /\.shell\s*{[^}]*min-height:\s*100dvh/s);
  assert.match(styles, /\.sidebar\s*{[^}]*height:\s*100dvh/s);
  assert.match(styles, /\.sidebar nav\s*{[^}]*min-height:\s*0;[^}]*overflow-y:\s*auto/s);
  assert.match(styles, /grid-template-columns:\s*var\(--sidebar-width, 244px\)/);
  assert.match(styles, /\.sidebar nav button\s*{[^}]*min-height:\s*39px;[^}]*height:\s*auto;[^}]*white-space:\s*normal;[^}]*overflow-wrap:\s*anywhere/s);
});

test("sidebar can be resized with pointer or keyboard", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(source, /const \[sidebarWidth, setSidebarWidth\] = useState\(244\)/);
  assert.match(source, /Math\.min\(420, Math\.max\(190/);
  assert.match(source, /className="sidebar-resizer"/);
  assert.match(source, /onPointerDown=\{startSidebarResize\}/);
  assert.match(source, /onKeyDown=\{resizeSidebarWithKeyboard\}/);
  assert.match(source, /"--sidebar-width": `\$\{sidebarWidth\}px`/);
  assert.match(styles, /\.sidebar-resizer\s*{[^}]*cursor:\s*col-resize;[^}]*touch-action:\s*none/s);
});

test("MFA QR is CSP-compatible for every role", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  const caddy = await readFile(new URL("../deploy/Caddyfile", import.meta.url), "utf8");
  assert.match(source, /<img\s+className="mfa-qr"\s+src=\{mfa\.qr_svg\}/s);
  assert.doesNotMatch(source, /<object\s+className="mfa-qr"/s);
  assert.match(source, /className="login-autofill-sink"\s+name="username"\s+autoComplete="username"/s);
  assert.match(source, /name="totp_code"[\s\S]*ref=\{mfaCodeRef\}[\s\S]*autoComplete="one-time-code"[\s\S]*value=\{mfaCode\}/s);
  assert.match(source, /requestAnimationFrame\(\(\) => mfaCodeRef\.current\?\.focus\(\)\)/);
  assert.match(source, /replace\(\/\\D\/g, ""\)\.slice\(0, 6\)/);
  assert.match(styles, /\.login-autofill-sink\s*\{[^}]*left:\s*-10000px/s);
  assert.match(caddy, /img-src 'self' data: blob:/);
  assert.match(caddy, /script-src-attr 'none'/);
});

test("viewer navigation is permission-aware and stale admin hashes are replaced", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /fetch\("\/api\/v1\/me"/);
  assert.match(source, /permissions:\s*\["users\.manage", "roles\.manage", "ldap\.manage"\]/);
  assert.match(source, /allowedNavigation\.some/);
  assert.match(source, /window\.history\.replaceState\(null, "", sectionRoute\(fallbackSection\)\)/);
  assert.match(source, /Đang tải quyền tài khoản/);
});

test("Linux package carries the native offline pack for the selected OS version", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /không cần Internet hay repository khi cài/);
  assert.match(source, /LINUX_OFFLINE_PROFILE_LABELS/);
  assert.match(source, /linux_profile: osFamily === "linux" \? linuxProfile : null/);
  assert.match(source, /Phải chọn đúng OS\/version của máy đích/);
  assert.match(source, /cài không cần repository/);
});

test("Agent packages expose fleet self-update and uninstall password protection", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const controlPlaneDockerfile = await readFile(new URL("../control-plane/Dockerfile", import.meta.url), "utf8");
  assert.match(source, /\/api\/v1\/agent-upgrades\/status/);
  assert.match(source, /\/api\/v1\/agent-upgrades/);
  assert.match(source, /Cập nhật Agent trực tiếp/);
  assert.match(source, /Cần nâng thủ công 1 lần/);
  assert.match(source, /Bảo vệ gỡ cài đặt Agent/);
  assert.match(source, /\/api\/v1\/settings\/agent-uninstall-protection/);
  assert.match(source, /canManageUninstallProtection && <article className="panel agent-uninstall-panel"/);
  assert.match(source, /Mật khẩu gỡ Agent hiện tại<input name="current_password"/);
  assert.match(source, /Mật khẩu gỡ Agent mới<input name="new_password"/);
  assert.match(source, /const queued = Array\.isArray\(data\.queued\)/);
  assert.match(source, /Agent bị bỏ qua và vẫn được giữ chọn/);
  assert.match(source, /uninstallLoadFailed \? "Không tải được chính sách"/);
  assert.match(source, /uninstallLoading \? "Đang thử lại…" : "Thử lại"/);
  assert.match(source, /Cần xử lý lỗi/);
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(styles, /html\[data-theme="light"\][\s\S]*\.agent-upgrade-summary > span/);
  assert.match(styles, /html\[data-theme="light"\] \.agent-upgrade-confirm-list > div/);
  assert.match(controlPlaneDockerfile, /chown -R root:root \/opt\/tram-agent-assets/);
  assert.match(controlPlaneDockerfile, /find \/opt\/tram-agent-assets -type f -exec chmod 0444/);
});

test("dashboard exposes build freshness and deployment verification", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  const packageJson = await readFile(new URL("../package.json", import.meta.url), "utf8");
  const dockerfile = await readFile(new URL("../Dockerfile", import.meta.url), "utf8");
  const deployScript = await readFile(new URL("../deploy/deploy-dashboard.sh", import.meta.url), "utf8");
  assert.match(source, /CURRENT_DASHBOARD_BUILD/);
  assert.match(source, /\/build-info\.json\?check=/);
  assert.match(source, /Có giao diện mới/);
  assert.match(source, /Tải lại giao diện/);
  assert.match(styles, /\.build-update-banner\s*\{/);
  assert.match(packageJson, /scripts\/build-dashboard\.mjs/);
  assert.match(dockerfile, /ARG SOURCE_REVISION=/);
  assert.match(dockerfile, /SOURCE_REVISION="\$SOURCE_REVISION" pnpm run build/);
  assert.match(deployScript, /--no-cache --build-arg SOURCE_REVISION="\$revision" dashboard/);
  assert.match(deployScript, /Dashboard build mismatch/);
  assert.match(deployScript, /Lưu cấu hình mẫu/);
  assert.match(deployScript, /build --pull --no-cache guacamole/);
  assert.match(deployScript, /force-recreate api dashboard guacamole/);
  assert.match(deployScript, /tram-clipboard-sync\.jar/);
  assert.match(deployScript, /tram-clipboard-sync-v3\.js/);
});

test("remote credentials are admin-managed and clipboard is paste-only", async () => {
  const consoleSource = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const credentialSource = await readFile(new URL("../app/remote-credentials.tsx", import.meta.url), "utf8");
  const apiSource = await readFile(new URL("../control-plane/app/main.py", import.meta.url), "utf8");
  assert.match(consoleSource, /label: "Tài khoản xác thực"[\s\S]*adminOnly: true/);
  assert.match(consoleSource, /body: JSON\.stringify\(\{ server_id: server\.id, protocol, credential_id: credentialId, width, height \}\)/);
  assert.match(credentialSource, /Chỉ Administrator quản lý/);
  assert.match(credentialSource, /Mật khẩu được mã hóa ở máy chủ Operation Portal, không trả về trình duyệt và không ghi vào nhật ký/);
  assert.match(apiSource, /"disable-copy": "true", "disable-paste": "false"/);
  assert.match(apiSource, /"enable-sftp": "false"[\s\S]*"sftp-disable-upload": "true"[\s\S]*"sftp-disable-download": "true"/);
  assert.match(apiSource, /"enable-drive": "false"[\s\S]*"disable-upload": "true"[\s\S]*"disable-download": "true"/);
  assert.match(apiSource, /password_encrypted=job_fernet\(\)\.encrypt/);
});

test("Guacamole waits for the latest browser clipboard before forwarding input", async () => {
  const compose = await readFile(new URL("../compose.yaml", import.meta.url), "utf8");
  const dockerfile = await readFile(new URL("../deploy/guacamole/Dockerfile", import.meta.url), "utf8");
  const manifest = JSON.parse(await readFile(new URL("../deploy/guacamole/clipboard-sync/guac-manifest.json", import.meta.url), "utf8"));
  const extension = await readFile(new URL("../deploy/guacamole/clipboard-sync/tram-clipboard-sync-v3.js", import.meta.url), "utf8");

  assert.equal(manifest.guacamoleVersion, "1.6.0");
  assert.equal(manifest.namespace, "tram-clipboard-sync-v3");
  assert.deepEqual(manifest.js, ["tram-clipboard-sync-v3.js"]);
  assert.match(compose, /image: tram-guacamole:1\.6\.0-clipboard-sync\.3[\s\S]*context: \.\/deploy\/guacamole/);
  assert.match(dockerfile, /FROM guacamole\/guacamole:1\.6\.0/);
  assert.match(dockerfile, /jar --create --file \/etc\/guacamole\/extensions\/tram-clipboard-sync\.jar/);
  assert.match(extension, /browserClipboard\.readText\(\)[\s\S]*service\.setClipboard\(new ClipboardData/);
  assert.match(extension, /addEventListener\('focus', resyncIfNeeded, true\)/);
  assert.match(extension, /isPasteShortcut[\s\S]*resyncClipboard\(true\)/);
  assert.match(extension, /isMousePasteButton[\s\S]*resyncClipboard\(true\)/);
  assert.match(extension, /ManagedClient[\s\S]*getInstance[\s\S]*installClientInputGate/);
  assert.doesNotMatch(extension, /Guacamole\.Client\.prototype/);
  assert.match(extension, /pendingClipboardSync[\s\S]*sendKeyEventAfterClipboardSync/);
  assert.match(extension, /pendingClipboardSync[\s\S]*sendMouseStateAfterClipboardSync/);

  let configureClipboard;
  let configureManagedClient;
  let startClipboard;
  const windowListeners = new Map();
  const documentListeners = new Map();
  const forwardedKeys = [];
  const forwardedMouse = [];
  const remoteWrites = [];
  let browserClipboard = "A";
  let remoteClipboard = "";
  let holdNextRead = false;
  let rejectNextRead = false;
  let resolveRead = () => {};

  const clipboardService = {
    resyncClipboard() {},
    setClipboard(data) {
      remoteWrites.push(data.data);
      remoteClipboard = data.data;
      return Promise.resolve();
    },
  };
  const clipboardModule = {
    config(definition) {
      configureClipboard = definition.at(-1);
    },
    run(definition) {
      startClipboard = definition.at(-1);
    },
  };
  const clientModule = {
    config(definition) {
      configureManagedClient = definition.at(-1);
    },
  };
  const fakeWindow = {
    navigator: {
      clipboard: {
        readText() {
          if (rejectNextRead) {
            rejectNextRead = false;
            return Promise.reject(new Error("clipboard permission denied"));
          }
          if (!holdNextRead) return Promise.resolve(browserClipboard);
          return new Promise((resolve) => {
            resolveRead = resolve;
          });
        },
      },
    },
    addEventListener(type, listener) {
      windowListeners.set(type, listener);
    },
  };
  const fakeDocument = {
    visibilityState: "visible",
    addEventListener(type, listener) {
      documentListeners.set(type, listener);
    },
  };
  function FakeClient() {
    // Apache Guacamole defines these as own methods on every Client instance.
    this.sendKeyEvent = function sendKeyEvent(pressed, keysym) {
      forwardedKeys.push({ pressed, keysym, clipboard: remoteClipboard });
    };
    this.sendMouseState = function sendMouseState(state, force) {
      forwardedMouse.push({ state, force, clipboard: remoteClipboard });
    };
  }
  assert.equal(FakeClient.prototype.sendKeyEvent, undefined);
  assert.equal(FakeClient.prototype.sendMouseState, undefined);
  const ManagedClient = {
    getInstance(id) {
      return { id, client: new FakeClient() };
    },
  };
  class FakeMouseState {
    constructor(x, y, left, middle, right, up, down) {
      Object.assign(this, { x, y, left, middle, right, up, down });
    }
  }
  class FakeClipboardData {
    constructor(data) {
      Object.assign(this, data);
    }
  }

  runInNewContext(extension, {
    angular: {
      module(name) {
        if (name === "clipboard") return clipboardModule;
        if (name === "client") return clientModule;
        throw new Error(`Unexpected Angular module: ${name}`);
      },
    },
    Guacamole: { Client: FakeClient, Mouse: { State: FakeMouseState } },
    Promise,
  });
  assert.equal(typeof configureClipboard, "function");
  assert.equal(typeof configureManagedClient, "function");
  assert.equal(typeof startClipboard, "function");
  configureClipboard({
    decorator(name, definition) {
      assert.equal(name, "clipboardService");
      definition.at(-1)(clipboardService, fakeWindow, FakeClipboardData);
    },
  });
  configureManagedClient({
    decorator(name, definition) {
      assert.equal(name, "ManagedClient");
      definition.at(-1)(ManagedClient);
    },
  });
  startClipboard([fakeDocument], fakeWindow, clipboardService);
  await waitForImmediate();

  windowListeners.get("blur")();
  browserClipboard = "B";
  holdNextRead = true;
  windowListeners.get("focus")();
  const client = ManagedClient.getInstance("test").client;
  client.sendKeyEvent(1, 0x56);
  assert.deepEqual(forwardedKeys, [], "input must wait while clipboard B is being read");

  resolveRead(browserClipboard);
  await waitForImmediate();
  assert.equal(remoteClipboard, "B");
  assert.equal(forwardedKeys.length, 1);
  assert.equal(forwardedKeys[0].pressed, 1);
  assert.equal(forwardedKeys[0].keysym, 0x56);
  assert.equal(forwardedKeys[0].clipboard, "B");
  assert.deepEqual(remoteWrites, ["A", "B"]);

  windowListeners.get("blur")();
  holdNextRead = false;
  rejectNextRead = true;
  windowListeners.get("focus")();
  client.sendKeyEvent(1, 0x43);
  await waitForImmediate();
  assert.deepEqual(remoteWrites, ["A", "B"], "a denied read must not write stale data");
  assert.equal(forwardedKeys.length, 2);

  // Chrome may return the previous clipboard value during the focus event.
  // Ctrl+V must force a second read and hold the V key until that read has
  // synchronized the newer value.
  windowListeners.get("blur")();
  browserClipboard = "B";
  windowListeners.get("focus")();
  await waitForImmediate();
  browserClipboard = "C";
  holdNextRead = true;
  documentListeners.get("keydown")({ ctrlKey: true, key: "v", code: "KeyV", keyCode: 86 });
  client.sendKeyEvent(1, 0x76);
  assert.equal(forwardedKeys.length, 2, "first Ctrl+V must wait for a forced fresh read");

  resolveRead(browserClipboard);
  await waitForImmediate();
  assert.equal(remoteClipboard, "C");
  assert.equal(forwardedKeys.length, 3);
  assert.equal(forwardedKeys[2].clipboard, "C");
  assert.deepEqual(remoteWrites, ["A", "B", "B", "C"]);

  // A right-click paste does not emit a browser paste event. Chrome may also
  // have returned C during focus while the system clipboard has already moved
  // on to D. The captured right mousedown must therefore force another read
  // and hold the remote mouse event until D has been synchronized.
  holdNextRead = false;
  windowListeners.get("blur")();
  browserClipboard = "C";
  windowListeners.get("focus")();
  await waitForImmediate();
  browserClipboard = "D";
  holdNextRead = true;
  documentListeners.get("mousedown")({ button: 2, buttons: 2 });
  const rightClickState = new FakeMouseState(10, 20, false, false, true, false, false);
  client.sendMouseState(rightClickState, true);
  rightClickState.right = false;
  assert.deepEqual(forwardedMouse, [], "right-click must wait for a forced fresh read");

  resolveRead(browserClipboard);
  await waitForImmediate();
  assert.equal(remoteClipboard, "D");
  assert.equal(forwardedMouse.length, 1);
  assert.equal(forwardedMouse[0].clipboard, "D");
  assert.equal(forwardedMouse[0].state.right, true);
  assert.equal(forwardedMouse[0].force, true);
  assert.deepEqual(remoteWrites, ["A", "B", "B", "C", "C", "D"]);
});
