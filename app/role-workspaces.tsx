"use client";

import { useCallback, useEffect, useState } from "react";

type Approval = { id: string; serverName: string; action: string; parameters: Record<string, unknown>; reason: string; requestedBy: string; status: string; jobId?: string };
const statusLabels: Record<string, string> = { pending: "Chờ một Administrator duyệt", approved: "Đã duyệt", rejected: "Đã từ chối" };

export function DeletionApprovalsView({ token, isAdmin }: { token: string; isAdmin: boolean }) {
  const [items, setItems] = useState<Approval[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const load = useCallback(async () => {
    const response = await fetch("/api/v1/deletion-approvals", { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail ?? "Không tải được yêu cầu xóa");
    setItems(data.items ?? []);
  }, [token]);
  useEffect(() => {
    const run = () => void load().catch((reason) => setError(String(reason.message)));
    const initial = window.setTimeout(run, 0);
    const timer = window.setInterval(run, 10000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, [load]);
  async function review(item: Approval, decision: "approve" | "reject") {
    if (!window.confirm(`${decision === "approve" ? "Duyệt thực hiện xóa" : "Từ chối"}: ${item.action} trên ${item.serverName}?`)) return;
    setBusy(item.id); setError("");
    try {
      const response = await fetch(`/api/v1/deletion-approvals/${item.id}/review`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ decision }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Không xử lý được yêu cầu");
      await load();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Không xử lý được yêu cầu"); }
    finally { setBusy(""); }
  }
  return <section className="panel view-panel"><h2>Phê duyệt xóa</h2><p>Operator gửi yêu cầu; một Administrator duyệt mới thực hiện. Yêu cầu có hiệu lực 24 giờ.</p>{error && <div role="alert" className="danger-panel">{error}</div>}<div className="resource-table-scroll"><table className="resource-table"><thead><tr><th>Thiết bị</th><th>Thao tác / lý do</th><th>Người yêu cầu</th><th>Trạng thái</th><th /></tr></thead><tbody>{items.map((item) => <tr key={item.id}><td>{item.serverName}</td><td>{item.action}<pre style={{ whiteSpace: "pre-wrap", maxWidth: 400 }}>{JSON.stringify(item.parameters, null, 2)}</pre><small>{item.reason}</small></td><td>{item.requestedBy}</td><td>{statusLabels[item.status] ?? item.status}{item.jobId && <small>Tác vụ: {item.jobId}</small>}</td><td>{isAdmin && item.status === "pending" && <div className="inline-actions"><button disabled={!!busy} onClick={() => void review(item, "approve")}>Duyệt xóa</button><button disabled={!!busy} onClick={() => void review(item, "reject")}>Từ chối</button></div>}</td></tr>)}</tbody></table></div>{!items.length && <div className="empty-state">Chưa có yêu cầu xóa.</div>}</section>;
}

export function ReadOnlyWorkspace({ token, kind }: { token: string; kind: "logs" | "configuration" }) {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    const response = await fetch(`/api/v1/${kind === "logs" ? "logs" : "configuration-snapshot"}`, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail ?? "Không đọc được dữ liệu");
    setData(payload); setError("");
  }, [kind, token]);
  useEffect(() => { const timer = window.setTimeout(() => void load().catch((reason) => setError(reason.message)), 0); return () => window.clearTimeout(timer); }, [load]);
  return <section className="panel view-panel"><div className="panel-head"><div><h2>{kind === "logs" ? "Log máy chủ" : "Cấu hình — chỉ xem"}</h2><p>{kind === "logs" ? "Dữ liệu log đã được Agent gửi về; không tạo tác vụ mới." : "Thông tin bí mật không được trả về. Vai trò này không có quyền thay đổi."}</p></div><button className="button ghost" onClick={() => void load().catch((reason) => setError(reason.message))}>Làm mới</button></div>{error && <div role="alert" className="danger-panel">{error}</div>}{data && Object.entries(data).map(([title, value]) => <details key={title} open><summary>{title}</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 600, overflow: "auto" }}>{JSON.stringify(value, null, 2)}</pre></details>)}</section>;
}
