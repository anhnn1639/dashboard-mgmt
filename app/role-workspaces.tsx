"use client";

import { useCallback, useEffect, useRef, useState } from "react";


export type ApprovalUser = { id: string; role: string; permissions: string[] };
export type Approval = {
  id: string; kind: "operation" | "recording"; target: string; action: string;
  parameters?: Record<string, unknown>; reason: string; requestedBy: string;
  requestedById: string; status: string; createdAt: string; expiresAt?: string;
  jobId?: string; jobStatus?: string; error?: string;
};
type OperationRequest = { id: string; serverName: string; action: string; parameters: Record<string, unknown>; reason: string; requestedBy: string; requestedById: string; status: string; createdAt: string; expiresAt?: string; jobId?: string; jobStatus?: string };
type RecordingRequest = { id: string; sessions: Array<{ label: string }>; reason: string; requestedBy: string; requestedByUsername: string; status: string; createdAt: string; error?: string };
const actionLabels: Record<string, string> = { "server.delete": "Xóa thiết bị khỏi hệ thống", "storage.delete": "Xóa vùng lưu trữ", "firewall.rule.remove": "Xóa quy tắc tường lửa", "user.delete": "Xóa tài khoản", "group.delete": "Xóa nhóm", "group.remove_user": "Xóa tài khoản khỏi nhóm" };
const statusLabels: Record<string, string> = { pending: "Chờ duyệt", approved: "Đã duyệt", rejected: "Đã từ chối", deleting: "Đang xóa", deleted: "Đã xóa", failed: "Xóa chưa hoàn tất", expired: "Hết hạn", cancelled: "Đã hủy" };
const jobLabels: Record<string, string> = { queued: "Đang chờ thực hiện", running: "Đang thực hiện", succeeded: "Hoàn tất", failed: "Thực hiện thất bại", cancelled: "Đã hủy" };

export function approvalStatus(item: Approval, time = Date.now()) {
  return item.status === "pending" && item.expiresAt && Date.parse(item.expiresAt) <= time ? "expired" : item.status;
}
export function canReviewApproval(item: Approval, user: ApprovalUser) {
  return user.role === "admin" && user.id !== item.requestedById && approvalStatus(item) === "pending"
    && user.permissions.includes(item.kind === "recording" ? "recordings.delete" : "deletions.approve");
}
export function approvalReviewRequest(item: Approval, decision: "approve" | "reject") {
  return item.kind === "recording"
    ? { url: `/api/v1/recording-deletion-requests/${encodeURIComponent(item.id)}/${decision}`, body: undefined }
    : { url: `/api/v1/deletion-approvals/${encodeURIComponent(item.id)}/review`, body: JSON.stringify({ decision }) };
}
export async function loadApprovals(token: string, permissions: string[]): Promise<Approval[]> {
  async function get(path: string) {
    const response = await fetch(path, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail ?? "Không tải được yêu cầu phê duyệt");
    return data.items ?? [];
  }
  const [operations, recordings]: [OperationRequest[], RecordingRequest[]] = await Promise.all([
    permissions.some((p) => ["deletions.request", "deletions.approve"].includes(p)) ? get("/api/v1/deletion-approvals") : [],
    permissions.some((p) => ["deletions.request", "recordings.delete"].includes(p)) ? get("/api/v1/recording-deletion-requests") : [],
  ]);
  return [
    ...operations.map((item): Approval => ({ ...item, kind: "operation", target: item.serverName })),
    ...recordings.map((item): Approval => ({ ...item, kind: "recording", target: item.sessions.map((session) => session.label).join("\n"), action: "Xóa video", requestedBy: item.requestedByUsername, requestedById: item.requestedBy })),
  ].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
}

export function ApprovalsView({ token, currentUser }: { token: string; currentUser: ApprovalUser }) {
  const [items, setItems] = useState<Approval[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [history, setHistory] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const loadGeneration = useRef(0);
  const load = useCallback(async () => {
    const generation = ++loadGeneration.current;
    try {
      const updated = await loadApprovals(token, currentUser.permissions);
      if (generation !== loadGeneration.current) return;
      setItems(updated);
      setError(""); setLoaded(true);
    } catch (reason) {
      if (generation === loadGeneration.current) throw reason;
    }
  }, [token, currentUser.permissions]);
  useEffect(() => {
    const generationRef = loadGeneration;
    const run = () => void load().catch((reason) => setError(reason instanceof Error ? reason.message : "Không tải được yêu cầu"));
    const initial = window.setTimeout(run, 0);
    const timer = window.setInterval(run, 10000);
    window.addEventListener("focus", run);
    return () => { ++generationRef.current; window.clearTimeout(initial); window.clearInterval(timer); window.removeEventListener("focus", run); };
  }, [load]);
  async function review(item: Approval, decision: "approve" | "reject") {
    if (!canReviewApproval(item, currentUser)) return;
    if (!window.confirm(`${decision === "approve" ? "Duyệt thực hiện" : "Từ chối"}: ${actionLabels[item.action] ?? item.action} trên ${item.target}?`)) return;
    setBusy(item.kind + item.id); setError("");
    try {
      const request = approvalReviewRequest(item, decision);
      const response = await fetch(request.url, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: request.body });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Không xử lý được yêu cầu");
      await load();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "Không xử lý được yêu cầu";
      try { await load(); } catch { /* Keep the last list if refresh also fails. */ }
      setError(message);
    } finally { setBusy(""); }
  }
  const visible = items.filter((item) => history || ["pending", "deleting"].includes(approvalStatus(item)));
  return <section className="panel view-panel">
    <div className="panel-head"><div><h2>Phê duyệt</h2><p>Tập trung yêu cầu thao tác và xóa video. Người gửi yêu cầu không được tự duyệt.</p></div>
      <button className="button ghost" disabled={!!busy} onClick={() => void load().catch((reason) => setError(reason.message))}>Làm mới</button></div>
    <label><input type="checkbox" checked={history} onChange={(event) => setHistory(event.target.checked)} /> Hiện cả yêu cầu đã xử lý và hết hạn</label>
    {error && <div role="alert" className="danger-panel">{error}</div>}
    <div className="resource-table-scroll"><table className="resource-table"><thead><tr><th>Loại / đối tượng</th><th>Thao tác / lý do</th><th>Người yêu cầu</th><th>Trạng thái</th><th>Phê duyệt</th></tr></thead>
      <tbody>{visible.map((item) => <tr key={item.kind + item.id}>
        <td><b>{item.kind === "recording" ? "Video ghi hình" : "Thao tác vận hành"}</b><pre style={{ whiteSpace: "pre-wrap", maxWidth: 360 }}>{item.target}</pre></td>
        <td>{actionLabels[item.action] ?? item.action}{item.parameters && Object.keys(item.parameters).length > 0 && <pre style={{ whiteSpace: "pre-wrap", maxWidth: 360 }}>{JSON.stringify(item.parameters, null, 2)}</pre>}<small>{item.reason}</small></td>
        <td>{item.requestedBy}<small>{new Date(item.createdAt).toLocaleString("vi-VN")}</small></td>
        <td>{statusLabels[approvalStatus(item)] ?? item.status}{item.jobStatus && <small>{jobLabels[item.jobStatus] ?? item.jobStatus}</small>}{item.error && <small>{item.error}</small>}</td>
        <td>{canReviewApproval(item, currentUser) ? <div className="inline-actions">
          <button className="button primary" disabled={!!busy} onClick={() => void review(item, "approve")}>Duyệt</button>
          <button className="button ghost" disabled={!!busy} onClick={() => void review(item, "reject")}>Từ chối</button>
        </div> : approvalStatus(item) === "pending" && item.requestedById === currentUser.id ? "Chờ quản trị viên khác" : "—"}</td>
      </tr>)}</tbody></table></div>
    {!visible.length && <div className="empty-state">{loaded ? "Không có yêu cầu phù hợp." : "Đang tải yêu cầu phê duyệt..."}</div>}
  </section>;
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
