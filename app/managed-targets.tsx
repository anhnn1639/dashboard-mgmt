"use client";

import { FormEvent, RefObject, useCallback, useEffect, useImperativeHandle, useRef, useState } from "react";
import { ModalShell } from "./server-resource-tabs";
import { readManagedTargetResponse } from "./managed-target-api";
import { ManagedSessionModal } from "./managed-session-modal";

type TargetConfig = { name: string; kind: "network" | "web"; address?: string; port?: number; url: string; web_allowed_origins?: string[]; credential?: { username: string; password: string } };
type Target = { id: string; name: string; kind: "network" | "web"; address: string; config: TargetConfig | null; connectionReady: boolean };
type RedirectDiscovery = { navigation: string[]; resources: string[]; blocked: string[]; error: string };
type DiscoveryState = { url: string; busy: boolean; result: RedirectDiscovery | null; error: string };
type WebConsoleFormGuard = { beforeSave: (url: string) => boolean };
type RedirectSuggestion = { origin: string; count: number; lastSeen: string };

const discoveryNotes: Record<string, string> = {
  timeout: "Website tải chậm nên có thể còn địa chỉ chưa xuất hiện.",
  "http-error": "Website trả lỗi HTTP; danh sách chỉ gồm địa chỉ đã kịp ghi nhận.",
  tls: "Không thương lượng được HTTPS với website.",
  certificate: "Website từ chối chứng thư HTTPS.",
  connection: "Không kết nối được website từ máy chủ Operation Portal.",
  "blocked-origin": "Website chuyển tới địa chỉ không dùng được (DNS lỗi hoặc trỏ về loopback/link-local).",
};

function originLines(value: string) {
  return value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
}

/** Compare what the Administrator typed with the API's scheme://host:port form. */
function originKey(value: string) {
  try {
    const parsed = new URL(value);
    return `${parsed.protocol}//${parsed.hostname}:${parsed.port || (parsed.protocol === "https:" ? "443" : "80")}`;
  } catch {
    return value.trim();
  }
}

function originList(value: unknown) {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function WebConsoleFields({ token, role, target, formGuard }: { token: string; role: string; target: Target | null; formGuard?: RefObject<WebConsoleFormGuard | null> }) {
  const admin = role === "admin";
  const saved = target?.config ?? null;
  const [edited, setEdited] = useState<string | null>(null);
  const [discovery, setDiscovery] = useState<DiscoveryState | null>(null);
  const [suggestions, setSuggestions] = useState<RedirectSuggestion[] | null>(null);
  const origins = edited ?? (saved?.web_allowed_origins ?? []).join("\n");
  const known = new Set(originLines(origins).map(originKey));
  const currentOrigins = useRef(origins);
  const currentUrl = useRef(saved?.url ?? "");
  const latestDiscovery = useRef<DiscoveryState | null>(null);
  const activeRequest = useRef<AbortController | null>(null);
  // Only auto-added origins belong to a probe; preserve manually entered origins.
  const autoOrigins = useRef(new Set<string>());

  useEffect(() => () => { activeRequest.current?.abort(); activeRequest.current = null; }, []);

  function publishDiscovery(value: DiscoveryState | null) {
    latestDiscovery.current = value;
    setDiscovery(value);
  }

  function editOrigins(value: string) {
    currentOrigins.current = value;
    setEdited(value);
  }

  function changeUrl(url: string) {
    if (url === currentUrl.current) return;
    currentUrl.current = url;
    activeRequest.current?.abort();
    activeRequest.current = null;
    publishDiscovery(null);
    const obsolete = autoOrigins.current;
    autoOrigins.current = new Set();
    if (obsolete.size) editOrigins(originLines(currentOrigins.current).filter((value) => !obsolete.has(originKey(value))).join("\n"));
  }



  useEffect(() => {
    if (!admin || !target) return;
    const abort = new AbortController();
    // Origins blocked in recent recorded sessions, offered as one-click adds.
    const initial = window.setTimeout(() => {
      void fetch(`/api/v1/managed-targets/${target.id}/redirect-suggestions`, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store", signal: abort.signal })
        .then((response) => response.ok ? response.json() : null)
        .then((data) => { if (Array.isArray(data?.items)) setSuggestions(data.items as RedirectSuggestion[]); })
        .catch(() => { /* Suggestions are optional; the form stays usable. */ });
    }, 0);
    return () => { window.clearTimeout(initial); abort.abort(); };
  }, [admin, target, token]);

  function addOrigins(values: string[], automatic = false) {
    const existing = originLines(currentOrigins.current);
    const seen = new Set(existing.map(originKey));
    const additions = values.filter((value) => {
      const key = originKey(value);
      if (seen.has(key)) return false;
      seen.add(key);
      if (automatic) autoOrigins.current.add(key);
      return true;
    });
    editOrigins([...existing, ...additions].join("\n"));
  }

  async function discover(url: string) {
    changeUrl(url);
    if (activeRequest.current && latestDiscovery.current?.url === url) return;
    activeRequest.current?.abort();
    const abort = new AbortController();
    activeRequest.current = abort;
    const isCurrent = () => !abort.signal.aborted && activeRequest.current === abort && currentUrl.current === url;
    publishDiscovery({ url, busy: true, result: null, error: "" });
    // A canceled client request may leave its anonymous server probe finishing.
    // Retry the worker's busy response, within one deadline, for the current URL.
    const deadline = window.setTimeout(() => {
      if (!isCurrent()) return;
      publishDiscovery({ url, busy: false, result: null, error: "Dò địa chỉ chuyển hướng quá thời gian chờ. Kiểm tra kết nối rồi thử dò lại, hoặc kiểm tra danh sách trước khi lưu." });
      abort.abort(); activeRequest.current = null;
    }, 90_000);
    async function retryWhenAvailable() {
      return new Promise<void>((resolve, reject) => {
        const timer = window.setTimeout(() => { abort.signal.removeEventListener("abort", cancel); resolve(); }, 1500);
        function cancel() { window.clearTimeout(timer); reject(new Error("Đã hủy dò địa chỉ.")); }
        abort.signal.addEventListener("abort", cancel, { once: true });
      });
    }
    try {
      let response: Response;
      do {
        response = await fetch("/api/v1/managed-targets/redirect-discovery", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ url }), signal: abort.signal });
        if (response.status === 409 && isCurrent()) await retryWhenAvailable();
        else break;
      } while (isCurrent());
      if (!isCurrent()) return;
      const data = await readManagedTargetResponse(response, "discover");
      if (!isCurrent()) return;
      const result: RedirectDiscovery = { navigation: originList(data.navigation), resources: originList(data.resources), blocked: originList(data.blocked), error: typeof data.error === "string" ? data.error : "" };
      addOrigins(result.navigation, true);
      publishDiscovery({ url, busy: false, result, error: "" });
    } catch (reason) {
      if (isCurrent()) publishDiscovery({ url, busy: false, result: null, error: reason instanceof Error ? reason.message : "Không dò được địa chỉ chuyển hướng." });
    } finally {
      window.clearTimeout(deadline);
      if (activeRequest.current === abort) activeRequest.current = null;
    }
  }

  useImperativeHandle(formGuard, () => ({ beforeSave(url: string) {
    changeUrl(url);
    const latest = latestDiscovery.current;
    if (!admin || (!latest && url === (saved?.url ?? ""))) return true;
    if (latest?.url === url && !latest.busy) return true;
    if (!latest?.busy) void discover(url);
    return false;
  } }));

  function chip(value: string, label: string) {
    const added = known.has(originKey(value));
    return <button key={value} type="button" className="origin-chip" disabled={added} onClick={() => addOrigins([value])}>{added ? "✓" : "＋"} {label}</button>;
  }

  return <>
    <label>URL website (HTTP hoặc HTTPS)<input name="url" type="url" placeholder="https://vcenter.example.local/ui/" defaultValue={saved?.url} required
      onChange={(event) => changeUrl(event.currentTarget.value.trim())}
      onBlur={admin ? (event) => { const value = event.currentTarget.value.trim(); if (value && value !== (latestDiscovery.current?.url ?? saved?.url)) void discover(value); } : undefined} /></label>
    <label>Địa chỉ chuyển hướng / SSO được phép<textarea name="web_allowed_origins" value={origins} onChange={(event) => { autoOrigins.current.clear(); editOrigins(event.target.value); }} placeholder={"https://sso.example.local\nhttps://console.example.local:8443"} readOnly={!admin} rows={3} /></label>
    {admin && <div className="redirect-discovery">
      <div className="redirect-discovery-actions">
        <button type="button" className="button ghost" disabled={Boolean(discovery?.busy)} onClick={(event) => {
          const field = event.currentTarget.form?.elements.namedItem("url");
          if (field instanceof HTMLInputElement && field.value.trim()) void discover(field.value.trim());
        }}>{discovery?.busy ? "Đang dò…" : "⟳ Tự dò địa chỉ chuyển hướng"}</button>
        {discovery?.busy && <span role="status">Đang mở website trong trình duyệt riêng của Operation Portal, thường mất khoảng 30 giây, tối đa 90 giây nếu dịch vụ đang bận…</span>}
      </div>
      {discovery?.error && <p className="resource-help warning" role="alert">{discovery.error}</p>}
      {discovery?.result && <>
        <p className="resource-help" role="status">{discovery.result.navigation.length
          ? `Đã tự thêm ${discovery.result.navigation.length} địa chỉ mà website chuyển tới. Kiểm tra danh sách rồi bấm Lưu kết nối.`
          : discovery.result.error ? "Chưa ghi nhận địa chỉ chuyển hướng; lần dò chưa hoàn tất." : "Website không chuyển sang địa chỉ khác trước bước đăng nhập. Nếu phiên bị chặn sau khi đăng nhập, địa chỉ đó sẽ tự hiện ở đây."}{discovery.result.error ? ` ${discoveryNotes[discovery.result.error] ?? ""}` : ""}</p>
        {discovery.result.resources.length > 0 && <div className="origin-chip-list"><span>Trang còn tải tài nguyên từ:</span>{discovery.result.resources.map((value) => chip(value, value))}</div>}
        {discovery.result.blocked.length > 0 && <p className="resource-help warning">Không dùng được (DNS lỗi hoặc địa chỉ nội bộ bị cấm): {discovery.result.blocked.join(", ")}</p>}
      </>}
      {suggestions && suggestions.length > 0 && <div className="origin-chip-list"><span>Phiên gần đây bị chặn khi chuyển tới:</span>{suggestions.map((item) => chip(item.origin, `${item.origin} · ${item.count} lần`))}</div>}
    </div>}
    <p className="resource-help">{admin
      ? "Operation Portal tự mở URL trong trình duyệt riêng để dò địa chỉ website chuyển tới và thêm sẵn vào danh sách; bạn chỉ kiểm tra rồi lưu. Mỗi dòng một địa chỉ gồm HTTP/HTTPS, tên miền hoặc IP và cổng, không có đường dẫn hay tham số đăng nhập. Chỉ địa chỉ trong danh sách mới truy cập được trong phiên."
      : "Danh sách địa chỉ chuyển hướng do Administrator quản lý. Mọi đường dẫn trên URL gốc và các địa chỉ này đều truy cập được, kể cả sau chuyển hướng."}</p>
    <p className="resource-help">Operation Portal tự xử lý chứng thư nội bộ, tự ký hoặc không hợp lệ trong phiên Web console. Phiên vẫn được ghi hình.</p>
  </>;
}

export function ManagedTargetsView({ kind, token, role, notify, share }: { kind: "network" | "web"; token: string; role: string; notify: (message: string) => void; share: (target: { id: string; name: string }) => void }) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [editing, setEditing] = useState<Target | "new" | null>(null);
  const [deleting, setDeleting] = useState<Target | null>(null);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [loadError, setLoadError] = useState("");
  const [loadState, setLoadState] = useState<"loading" | "ready" | "error">("loading");
  const [busy, setBusy] = useState(false);
  const [connecting, setConnecting] = useState<Target | null>(null);
  const webFormGuard = useRef<WebConsoleFormGuard | null>(null);
  const canManage = role === "admin" || role === "operator";
  const load = useCallback(async () => {
    setLoadState("loading"); setLoadError("");
    try {
      const response = await fetch("/api/v1/managed-targets", { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
      const data = await readManagedTargetResponse(response, "list");
      setTargets(data.items); setLoadState("ready");
    } catch (reason) {
      setLoadError(reason instanceof TypeError ? "Không kết nối được tới API. Kiểm tra kết nối mạng rồi bấm Thử lại." : reason instanceof Error ? reason.message : "Không tải được kết nối.");
      setLoadState("error");
    }
  }, [token]);
  useEffect(() => { const initial = window.setTimeout(() => void load(), 0); return () => window.clearTimeout(initial); }, [load]);
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (kind === "web" && role === "admin" && !webFormGuard.current?.beforeSave(String(form.get("url") ?? "").trim())) {
      setError("Hãy chờ dò địa chỉ chuyển hướng hoàn tất, kiểm tra danh sách rồi bấm Lưu kết nối lần nữa.");
      return;
    }
    setBusy(true); setError("");
    const body: TargetConfig = { kind, name: String(form.get("name")), url: kind === "web" ? String(form.get("url")) : "", ...(kind === "network" ? { address: String(form.get("address")), port: Number(form.get("port")) } : {}) };
    if (kind === "web") body.web_allowed_origins = role === "admin"
      ? String(form.get("web_allowed_origins") ?? "").split(/\r?\n/).map((value) => value.trim()).filter(Boolean)
      : (editing && editing !== "new" ? editing.config?.web_allowed_origins ?? [] : []);
    if (editing === "new") body.credential = { username: String(form.get("username")), password: String(form.get("password")) };
    try {
      const response = await fetch(`/api/v1/managed-targets${editing && editing !== "new" ? "/" + editing.id : ""}`, { method: editing === "new" ? "POST" : "PUT", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
      await readManagedTargetResponse(response, editing === "new" ? "create" : "edit");
      setEditing(null); await load(); notify(editing === "new" ? "Đã lưu kết nối và tài khoản vào Tài khoản xác thực." : "Đã lưu cấu hình kết nối; tài khoản xác thực được giữ nguyên.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Không lưu được kết nối"); }
    finally { setBusy(false); }
  }
  async function remove(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!deleting) return;
    const form = new FormData(event.currentTarget);
    setBusy(true); setError("");
    try {
      const response = await fetch(`/api/v1/servers/${deleting.id}`, { method: "DELETE", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ confirmation: form.get("confirmation"), reason: form.get("reason") }) });
      const data = await readManagedTargetResponse(response, "delete");
      setDeleting(null); await load(); notify(data.status === "pending_approval" ? "Đã gửi yêu cầu xóa; chờ một Administrator duyệt." : "Đã xóa kết nối; lịch sử vẫn được giữ.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Không xóa được kết nối"); }
    finally { setBusy(false); }
  }
  const rows = targets.filter((item) => item.kind === kind && `${item.name} ${item.address} ${item.config?.url ?? ""}`.toLowerCase().includes(search.toLowerCase()));
  const selected = editing && editing !== "new" ? editing.config : null;
  return <section className="panel view-panel"><div className="panel-head"><div><h2>{kind === "network" ? "Thiết bị mạng" : "Web console"}</h2><p>Kết nối khai báo thủ công, không cài Agent.</p></div><div className="inline-actions"><button className="button ghost" disabled={loadState === "loading"} onClick={() => void load()}>Làm mới</button>{canManage && <button className="button primary" onClick={() => { setError(""); setEditing("new"); }}>＋ Thêm kết nối</button>}</div></div><input className="resource-search" aria-label="Tìm kết nối" placeholder={kind === "web" ? "Tìm tên hoặc URL…" : "Tìm tên hoặc IP…"} value={search} onChange={(event) => setSearch(event.target.value)} />{loadState === "loading" && <p role="status">Đang tải danh sách kết nối…</p>}{loadError && <div className="danger-panel" role="alert"><p>{loadError}</p><button className="button primary" onClick={() => void load()}>Thử lại</button></div>}<div className="resource-table-scroll"><table className="resource-table"><thead><tr><th>Tên kết nối</th><th>Địa chỉ</th><th>Trạng thái</th><th>Thao tác</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><b>{item.name}</b></td><td>{item.config?.url || item.address}<small>{item.kind === "network" && item.config ? `IP ${item.address} · cổng ${item.config.port}` : ""}</small></td><td>{item.connectionReady ? "Sẵn sàng kết nối" : "Cần kiểm tra dịch vụ phiên"}</td><td><div className="inline-actions">{["admin", "operator", "connector"].includes(role) && <button className="button primary" onClick={() => setConnecting(item)}>↗ Kết nối</button>}{canManage && <><button onClick={() => { setError(""); setEditing(item); }}>Sửa</button><button onClick={() => { setError(""); setDeleting(item); }}>{role === "operator" ? "Yêu cầu xóa" : "Xóa"}</button></>}{role === "admin" && <button onClick={() => share(item)}>Chia sẻ</button>}</div></td></tr>)}</tbody></table></div>{loadState === "ready" && !rows.length && <div className="empty-state">{search ? "Không có kết nối khớp bộ lọc." : role === "connector" ? "Chưa có kết nối được chia sẻ cho bạn." : "Chưa có kết nối trong danh mục này."}</div>}{rows.length > 0 && <p className="resource-help">{kind === "network" ? "SSH mở qua Operation Portal và có ghi hình. Người dùng chỉ chọn tài khoản được chia sẻ. Khóa máy chủ được ghi nhận ở lần đầu và kiểm tra ở các lần sau." : "Web console mở qua Operation Portal và được ghi hình. Máy người dùng chỉ cần truy cập Operation Portal; kết nối tới website do máy chủ Operation Portal thực hiện."}</p>}{connecting && <ManagedSessionModal target={connecting} token={token} close={() => setConnecting(null)} notify={notify} />}
    {editing && <ModalShell title={editing === "new" ? "Thêm kết nối" : "Sửa kết nối"} subtitle={kind === "web" ? "Web console HTTP / HTTPS" : "Switch / router qua SSH"} close={() => setEditing(null)}>
      <form className="resource-form" onSubmit={save}>
        {error && <div className="danger-panel" role="alert">{error}</div>}
        <label>{kind === "web" ? "Tên web console" : "Tên kết nối"}<input name="name" defaultValue={selected?.name} minLength={2} maxLength={100} required /></label>
        {kind === "network" ? <div className="form-grid"><label>Địa chỉ IPv4 của thiết bị<input name="address" placeholder="10.64.70.20" defaultValue={selected?.address} required /></label><label>Cổng SSH<input name="port" type="number" min={1} max={65535} defaultValue={selected?.port ?? 22} required /></label></div> : <WebConsoleFields key={editing === "new" ? "new" : editing.id} token={token} role={role} target={editing !== "new" ? editing : null} formGuard={webFormGuard} />}
        {kind === "network" && <p className="resource-help">SSH tự thương lượng, ưu tiên thuật toán mới và tự thử Group14/RSA-SHA1 khi thiết bị cũ cần. Không cần bật thêm tùy chọn. Khóa máy chủ vẫn được kiểm tra và phiên vẫn được ghi hình.</p>}
        {editing === "new" ? <fieldset><legend>Tài khoản xác thực ban đầu</legend><div className="form-grid"><label>Username<input name="username" required maxLength={128} autoComplete="off" /></label><label>Password<input name="password" type="password" required maxLength={1024} autoComplete="new-password" /></label></div><p className="resource-help">Lưu mã hóa vào Tài khoản xác thực. Sau khi lưu, chỉ Administrator được quản lý tài khoản; người kết nối chỉ chọn username được phép sử dụng.</p></fieldset> : <p className="resource-help">Tài khoản đã lưu không thay đổi tại đây. Administrator quản lý username/password trong mục Tài khoản xác thực.</p>}
        <div className="modal-actions"><button type="button" className="button ghost" onClick={() => setEditing(null)}>Hủy</button><button disabled={busy} className="button primary">{busy ? "Đang lưu…" : "Lưu kết nối"}</button></div>
      </form>
    </ModalShell>}
    {deleting && <ModalShell title={`Xóa ${deleting.name}`} subtitle={role === "operator" ? "Chỉ thực hiện sau khi một Administrator duyệt" : "Giữ nguyên lịch sử để kiểm toán"} close={() => setDeleting(null)}><form className="resource-form" onSubmit={remove}>{error && <div className="danger-panel">{error}</div>}<label>Lý do<textarea name="reason" required minLength={3} maxLength={500} /></label><label>Nhập DELETE để xác nhận<input name="confirmation" pattern="DELETE" required autoComplete="off" /></label><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setDeleting(null)}>Hủy</button><button className="button danger" disabled={busy}>{role === "operator" ? "Gửi yêu cầu xóa" : "Xóa kết nối"}</button></div></form></ModalShell>}
  </section>;
}
