import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(new Request("http://localhost/", { headers: { accept: "text/html" } }), { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } }, { waitUntil() {}, passThroughOnException() {} });
}

test("server-renders the secure operations console shell", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  const html = await response.text();
  assert.match(html, /<title>Trạm Vận Hành<\/title>/i);
  assert.match(html, /Đang kiểm tra cấu hình hệ thống/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("dashboard includes automatic Windows and Linux fleet views", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  assert.match(source, /Máy chủ Linux/);
  assert.match(source, /Máy chủ Windows/);
  assert.match(source, /server\.osFamily === scope/);
  assert.match(source, /\/api\/v1\/servers/);
  assert.match(source, /Phiên truy cập/);
  assert.match(source, /Nhật ký kiểm toán/);
  assert.match(source, /serverRoute\(server\)/);
  assert.match(source, /Truyền file/);
  assert.match(source, /service\.restart/);
  assert.match(source, /firewall\.list/);
  assert.match(source, /parseServiceOutput/);
  assert.match(source, /\/api\/v1\/setup\/status/);
  assert.match(source, /Kết nối PostgreSQL/);
  assert.match(source, /Admin local đầu tiên/);
});

test("firewall add form uses server capabilities and a viewport-safe scroll region", async () => {
  const source = await readFile(new URL("../app/ops-console.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(source, /Dữ liệu trực tiếp từ máy chủ/);
  assert.match(source, /Profile Windows Firewall/);
  assert.match(source, /Zone firewalld/);
  assert.match(source, /Filter chain trên máy chủ/);
  assert.match(source, /capabilities\.targets\.map/);
  assert.doesNotMatch(source, /Table<input name="table"/);
  assert.doesNotMatch(source, /Chain<input name="chain"/);
  assert.match(styles, /\.add-firewall-modal\s*{[^}]*max-height:\s*calc\(100% - 32px\)/s);
  assert.match(styles, /\.firewall-add-scroll\s*{[^}]*overflow-y:\s*auto/s);
});
