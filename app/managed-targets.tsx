"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { ModalShell } from "./server-resource-tabs";
import { readManagedTargetResponse } from "./managed-target-api";
import { ManagedSessionModal } from "./managed-session-modal";

type TargetConfig = { name: string; kind: "network" | "web"; address?: string; port?: number; url: string; credential?: { username: string; password: string } };
type Target = { id: string; name: string; kind: "network" | "web"; address: string; config: TargetConfig | null; connectionReady: boolean };

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
    event.preventDefault(); setBusy(true); setError("");
    const form = new FormData(event.currentTarget);
    const body: TargetConfig = { kind, name: String(form.get("name")), url: kind === "web" ? String(form.get("url")) : "", ...(kind === "network" ? { address: String(form.get("address")), port: Number(form.get("port")) } : {}) };
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
  return <section className="panel view-panel"><div className="panel-head"><div><h2>{kind === "network" ? "Thiết bị mạng" : "Web console"}</h2><p>Kết nối khai báo thủ công, không cài Agent.</p></div><div className="inline-actions"><button className="button ghost" disabled={loadState === "loading"} onClick={() => void load()}>Làm mới</button>{canManage && <button className="button primary" onClick={() => { setError(""); setEditing("new"); }}>＋ Thêm kết nối</button>}</div></div><input className="resource-search" aria-label="Tìm kết nối" placeholder={kind === "web" ? "Tìm tên hoặc URL…" : "Tìm tên hoặc IP…"} value={search} onChange={(event) => setSearch(event.target.value)} />{loadState === "loading" && <p role="status">Đang tải danh sách kết nối…</p>}{loadError && <div className="danger-panel" role="alert"><p>{loadError}</p><button className="button primary" onClick={() => void load()}>Thử lại</button></div>}<div className="resource-table-scroll"><table className="resource-table"><thead><tr><th>Tên kết nối</th><th>Địa chỉ</th><th>Trạng thái</th><th>Thao tác</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><b>{item.name}</b></td><td>{item.config?.url || item.address}<small>{item.kind === "network" && item.config ? `IP ${item.address} · cổng ${item.config.port}` : ""}</small></td><td>Đã lưu cấu hình</td><td><div className="inline-actions">{["admin", "operator", "connector"].includes(role) && item.connectionReady && <button className="button primary" onClick={() => setConnecting(item)}>↗ Kết nối</button>}{canManage && <><button onClick={() => { setError(""); setEditing(item); }}>Sửa</button><button onClick={() => { setError(""); setDeleting(item); }}>{role === "operator" ? "Yêu cầu xóa" : "Xóa"}</button></>}{role === "admin" && <button onClick={() => share(item)}>Chia sẻ</button>}</div></td></tr>)}</tbody></table></div>{loadState === "ready" && !rows.length && <div className="empty-state">{search ? "Không có kết nối khớp bộ lọc." : role === "connector" ? "Chưa có kết nối được chia sẻ cho bạn." : "Chưa có kết nối trong danh mục này."}</div>}{rows.length > 0 && <p className="resource-help">{kind === "network" ? "SSH mở qua Trạm vận hành và có ghi hình. Người dùng chỉ chọn tài khoản được chia sẻ. Khóa máy chủ được ghi nhận ở lần đầu và kiểm tra ở các lần sau." : "Cấu hình và tài khoản đã được lưu. Dịch vụ mở phiên web có ghi hình chưa được triển khai; không có liên kết trực tiếp bỏ qua ghi hình."}</p>}{connecting && <ManagedSessionModal target={connecting} token={token} close={() => setConnecting(null)} notify={notify} />}
    {editing && <ModalShell title={editing === "new" ? "Thêm kết nối" : "Sửa kết nối"} subtitle={kind === "web" ? "Web console HTTPS" : "Switch / router qua SSH"} close={() => setEditing(null)}>
      <form className="resource-form" onSubmit={save}>
        {error && <div className="danger-panel" role="alert">{error}</div>}
        <label>{kind === "web" ? "Tên web console" : "Tên kết nối"}<input name="name" defaultValue={selected?.name} minLength={2} maxLength={100} required /></label>
        {kind === "network" ? <div className="form-grid"><label>Địa chỉ IPv4 của thiết bị<input name="address" placeholder="10.64.70.20" defaultValue={selected?.address} required /></label><label>Cổng SSH<input name="port" type="number" min={1} max={65535} defaultValue={selected?.port ?? 22} required /></label></div> : <label>URL HTTPS<input name="url" type="url" placeholder="https://vcenter.example.local/ui/" defaultValue={selected?.url} required /></label>}
        {kind === "network" && <p className="resource-help">SSH tự thương lượng, ưu tiên thuật toán mới và tự thử Group14/RSA-SHA1 khi thiết bị cũ cần. Không cần bật thêm tùy chọn. Khóa máy chủ vẫn được kiểm tra và phiên vẫn được ghi hình.</p>}
        {editing === "new" ? <fieldset><legend>Tài khoản xác thực ban đầu</legend><div className="form-grid"><label>Username<input name="username" required maxLength={128} autoComplete="off" /></label><label>Password<input name="password" type="password" required maxLength={1024} autoComplete="new-password" /></label></div><p className="resource-help">Lưu mã hóa vào Tài khoản xác thực. Sau khi lưu, chỉ Administrator được quản lý tài khoản; người kết nối chỉ chọn username được phép sử dụng.</p></fieldset> : <p className="resource-help">Tài khoản đã lưu không thay đổi tại đây. Administrator quản lý username/password trong mục Tài khoản xác thực.</p>}
        <div className="modal-actions"><button type="button" className="button ghost" onClick={() => setEditing(null)}>Hủy</button><button disabled={busy} className="button primary">{busy ? "Đang lưu…" : "Lưu kết nối"}</button></div>
      </form>
    </ModalShell>}
    {deleting && <ModalShell title={`Xóa ${deleting.name}`} subtitle={role === "operator" ? "Chỉ thực hiện sau khi một Administrator duyệt" : "Giữ nguyên lịch sử để kiểm toán"} close={() => setDeleting(null)}><form className="resource-form" onSubmit={remove}>{error && <div className="danger-panel">{error}</div>}<label>Lý do<textarea name="reason" required minLength={3} maxLength={500} /></label><label>Nhập DELETE để xác nhận<input name="confirmation" pattern="DELETE" required autoComplete="off" /></label><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setDeleting(null)}>Hủy</button><button className="button danger" disabled={busy}>{role === "operator" ? "Gửi yêu cầu xóa" : "Xóa kết nối"}</button></div></form></ModalShell>}
  </section>;
}
