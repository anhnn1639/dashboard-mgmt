"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { ModalShell } from "./server-resource-tabs";

type TargetConfig = { name: string; kind: "network" | "web"; address: string; port: number; url: string; ssh_host_key: string };
type Target = { id: string; name: string; kind: "network" | "web"; address: string; config: TargetConfig | null; connectionReady: boolean };

export function ManagedTargetsView({ kind, token, role, notify, share }: { kind: "network" | "web"; token: string; role: string; notify: (message: string) => void; share: (target: { id: string; name: string }) => void }) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [editing, setEditing] = useState<Target | "new" | null>(null);
  const [deleting, setDeleting] = useState<Target | null>(null);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const canManage = role === "admin" || role === "operator";
  const load = useCallback(async () => {
    const response = await fetch("/api/v1/managed-targets", { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail ?? "Không tải được kết nối");
    setTargets(data.items ?? []);
  }, [token]);
  useEffect(() => { const initial = window.setTimeout(() => void load().catch((reason) => setError(reason.message)), 0); return () => window.clearTimeout(initial); }, [load]);
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    const form = new FormData(event.currentTarget);
    const body: TargetConfig = { kind, name: String(form.get("name")), address: String(form.get("address")), port: Number(form.get("port")), url: kind === "web" ? String(form.get("url")) : "", ssh_host_key: kind === "network" ? String(form.get("ssh_host_key") ?? "") : "" };
    try {
      const response = await fetch(`/api/v1/managed-targets${editing && editing !== "new" ? "/" + editing.id : ""}`, { method: editing === "new" ? "POST" : "PUT", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Thông tin kết nối chưa hợp lệ; kiểm tra IP, URL và cổng.");
      setEditing(null); await load(); notify("Đã lưu cấu hình kết nối.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Không lưu được kết nối"); }
    finally { setBusy(false); }
  }
  async function remove(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!deleting) return;
    const form = new FormData(event.currentTarget);
    setBusy(true); setError("");
    try {
      const response = await fetch(`/api/v1/servers/${deleting.id}`, { method: "DELETE", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ confirmation: form.get("confirmation"), reason: form.get("reason") }) });
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Không xóa được kết nối");
      setDeleting(null); await load(); notify(data.status === "pending_approval" ? "Đã gửi yêu cầu xóa; chờ một Administrator duyệt." : "Đã xóa kết nối; lịch sử vẫn được giữ.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Không xóa được kết nối"); }
    finally { setBusy(false); }
  }
  const rows = targets.filter((item) => item.kind === kind && `${item.name} ${item.address}`.toLowerCase().includes(search.toLowerCase()));
  const selected = editing && editing !== "new" ? editing.config : null;
  return <section className="panel view-panel"><div className="panel-head"><div><h2>{kind === "network" ? "Thiết bị mạng" : "Web console"}</h2><p>Kết nối khai báo thủ công, không cài Agent.</p></div><div className="inline-actions"><button className="button ghost" onClick={() => void load().catch((reason) => setError(reason.message))}>Làm mới</button>{canManage && <button className="button primary" onClick={() => { setError(""); setEditing("new"); }}>＋ Thêm kết nối</button>}</div></div><input className="resource-search" aria-label="Tìm kết nối" placeholder="Tìm tên hoặc IP…" value={search} onChange={(event) => setSearch(event.target.value)} />{error && <div className="danger-panel" role="alert">{error}</div>}<div className="resource-table-scroll"><table className="resource-table"><thead><tr><th>Tên kết nối</th><th>Địa chỉ</th><th>Trạng thái</th><th>Thao tác</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td><b>{item.name}</b></td><td>{item.config?.url || item.address}<small>{item.config ? `IP ${item.address} · cổng ${item.config.port}` : ""}</small></td><td>Đã lưu cấu hình</td><td><div className="inline-actions">{canManage && <><button onClick={() => { setError(""); setEditing(item); }}>Sửa</button><button onClick={() => { setError(""); setDeleting(item); }}>{role === "operator" ? "Yêu cầu xóa" : "Xóa"}</button></>}{role === "admin" && <button onClick={() => share(item)}>Chia sẻ</button>}</div></td></tr>)}</tbody></table></div>{!rows.length && <div className="empty-state">{role === "connector" ? "Chưa có kết nối được chia sẻ cho bạn." : "Chưa có kết nối trong danh mục này."}</div>}{rows.length > 0 && <p className="resource-help">Cấu hình đã lưu; mở phiên và ghi hình thiết bị/web console chưa được kích hoạt. Không có liên kết mở trực tiếp bỏ qua ghi hình.</p>}
    {editing && <ModalShell title={editing === "new" ? "Thêm kết nối" : "Sửa kết nối"} subtitle={kind === "web" ? "vCenter, web console HTTPS và thiết bị có giao diện web" : "Switch / router qua SSH"} close={() => setEditing(null)}><form className="resource-form" onSubmit={save}>{error && <div className="danger-panel">{error}</div>}<label>Tên kết nối<input name="name" defaultValue={selected?.name} minLength={2} maxLength={100} required /></label><label>Địa chỉ IPv4 của thiết bị<input name="address" placeholder="10.64.70.20" defaultValue={selected?.address} required /></label><label>Cổng<input name="port" type="number" min={1} max={65535} defaultValue={selected?.port ?? (kind === "web" ? 443 : 22)} required /></label>{kind === "web" ? <label>URL HTTPS<input name="url" type="url" placeholder="https://vcenter.example.local/ui/" defaultValue={selected?.url} required /></label> : <label>SSH public host key (có thể bổ sung sau)<textarea name="ssh_host_key" placeholder="ssh-ed25519 AAAA…" defaultValue={selected?.ssh_host_key} /><small>Khóa công khai của thiết bị, không nhập private key.</small></label>}<p className="resource-help">Không nhập mật khẩu vào URL. Tài khoản xác thực do Administrator quản lý riêng.</p><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setEditing(null)}>Hủy</button><button disabled={busy} className="button primary">Lưu kết nối</button></div></form></ModalShell>}
    {deleting && <ModalShell title={`Xóa ${deleting.name}`} subtitle={role === "operator" ? "Chỉ thực hiện sau khi một Administrator duyệt" : "Giữ nguyên lịch sử để kiểm toán"} close={() => setDeleting(null)}><form className="resource-form" onSubmit={remove}>{error && <div className="danger-panel">{error}</div>}<label>Lý do<textarea name="reason" required minLength={3} maxLength={500} /></label><label>Nhập DELETE để xác nhận<input name="confirmation" pattern="DELETE" required autoComplete="off" /></label><div className="modal-actions"><button type="button" className="button ghost" onClick={() => setDeleting(null)}>Hủy</button><button className="button danger" disabled={busy}>{role === "operator" ? "Gửi yêu cầu xóa" : "Xóa kết nối"}</button></div></form></ModalShell>}
  </section>;
}
