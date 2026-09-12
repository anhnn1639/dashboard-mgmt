"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Approval, actionLabels, approvalReviewMessage, approvalReviewRequest, approvalStatus, canReviewApproval, loadApprovals } from "./role-workspaces";

function noticeKey(item: Approval) { return `${item.kind}:${item.id}`; }
function noticeTitle(item: Approval) {
  return item.kind === "recording" ? "Yêu cầu xóa video ghi hình" : `Yêu cầu: ${actionLabels[item.action] ?? item.action}`;
}
function shortTime(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "" : parsed.toLocaleString("vi-VN", { dateStyle: "short", timeStyle: "short" });
}

const bellIcon = (
  <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 8.6a6 6 0 1 0-12 0c0 4.9-2 6.4-2 6.4h16s-2-1.5-2-6.4z" /><path d="M10.4 18.8a2 2 0 0 0 3.2 0" /></svg>
);

/** A shortcut to the central approval queue, with the same status and permissions. */
export function NotificationCenter({ token, role, userId, permissions, openApprovals, notify }: {
  token: string;
  role: string;
  userId: string;
  permissions: string[];
  openApprovals: () => void;
  notify: (message: string) => void;
}) {
  const [notices, setNotices] = useState<Approval[]>([]);
  const [popped, setPopped] = useState<Approval[]>([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const seen = useRef<Set<string> | null>(null);
  const loadGeneration = useRef(0);
  const loadController = useRef<AbortController | null>(null);
  const reviewInFlight = useRef(false);
  const active = useRef(true);
  const currentUser = { id: userId, role, permissions };

  const load = useCallback(async () => {
    const generation = ++loadGeneration.current;
    loadController.current?.abort();
    const controller = new AbortController();
    loadController.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 10_000);
    try {
      const items = await loadApprovals(token, permissions, controller.signal);
      if (generation !== loadGeneration.current) return;
      if (controller.signal.aborted) throw new Error("Notification load timed out");
      const collected = items.filter((item) => approvalStatus(item) === "pending");
      setNotices(collected);
      setLoaded(true);
      setError("");
      const known = seen.current;
      const fresh = known ? collected.filter((item) => !known.has(noticeKey(item))) : [];
      if (!known) seen.current = new Set(collected.map(noticeKey));
      else for (const item of collected) known.add(noticeKey(item));
      // Also remove/update toasts whose request was handled in another view.
      setPopped((live) => {
        const next = new Map(collected.map((item) => [noticeKey(item), item]));
        const remaining = live.flatMap((item) => next.has(noticeKey(item)) ? [next.get(noticeKey(item))!] : []);
        return [...fresh, ...remaining.filter((item) => !fresh.some((added) => noticeKey(added) === noticeKey(item)))].slice(0, 3);
      });
    } catch {
      if (generation === loadGeneration.current) setError("Không cập nhật được thông báo. Dữ liệu hiển thị có thể chưa mới nhất; hãy thử lại.");
    } finally {
      window.clearTimeout(timeout);
      if (loadController.current === controller) loadController.current = null;
    }
  }, [token, permissions]);

  useEffect(() => {
    active.current = true;
    const generationRef = loadGeneration;
    const controllerRef = loadController;
    const initial = window.setTimeout(() => void load(), 0);
    const timer = window.setInterval(() => void load(), 20_000);
    const refresh = () => void load();
    window.addEventListener("focus", refresh);
    return () => {
      active.current = false;
      ++generationRef.current;
      controllerRef.current?.abort();
      window.clearTimeout(initial);
      window.clearInterval(timer);
      window.removeEventListener("focus", refresh);
    };
  }, [load]);

  useEffect(() => {
    if (!popped.length) return;
    const timer = window.setTimeout(() => setPopped((current) => current.slice(0, -1)), 8_000);
    return () => window.clearTimeout(timer);
  }, [popped]);

  useEffect(() => {
    if (!open) return;
    function close(event: MouseEvent) {
      if (!(event.target instanceof Element) || !event.target.closest(".notif-wrap")) setOpen(false);
    }
    function escape(event: KeyboardEvent) { if (event.key === "Escape") setOpen(false); }
    window.addEventListener("click", close);
    window.addEventListener("keydown", escape);
    return () => { window.removeEventListener("click", close); window.removeEventListener("keydown", escape); };
  }, [open]);

  async function review(item: Approval, decision: "approve" | "reject") {
    if (reviewInFlight.current || error || !canReviewApproval(item, currentUser)) return;
    if (!window.confirm(approvalReviewMessage(item, decision))) return;
    if (!canReviewApproval(item, currentUser)) return;
    reviewInFlight.current = true;
    setBusy(noticeKey(item));
    // Any list fetched before this mutation must not restore the handled row.
    ++loadGeneration.current;
    loadController.current?.abort();
    try {
      const request = approvalReviewRequest(item, decision);
      const response = await fetch(request.url, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: request.body,
      });
      const data = await response.json().catch(() => null);
      if (!active.current) return;
      if (!response.ok) throw new Error(typeof data?.detail === "string" ? data.detail : "Không xử lý được yêu cầu.");
      ++loadGeneration.current;
      loadController.current?.abort();
      setNotices((current) => current.filter((notice) => noticeKey(notice) !== noticeKey(item)));
      setPopped((current) => current.filter((notice) => noticeKey(notice) !== noticeKey(item)));
      notify(decision === "approve" ? "Đã duyệt yêu cầu; thao tác được ghi vào nhật ký kiểm toán." : "Đã từ chối yêu cầu; thao tác được ghi vào nhật ký kiểm toán.");
    } catch (reason) {
      if (active.current) notify(reason instanceof Error ? reason.message : "Không xử lý được yêu cầu.");
    } finally {
      if (active.current) await load();
      reviewInFlight.current = false;
      if (active.current) setBusy("");
    }
  }

  function actions(item: Approval) {
    return <div className="notif-actions">
      {canReviewApproval(item, currentUser) ? <>
        <button type="button" className="button primary compact" disabled={!!busy || !!error} onClick={() => void review(item, "approve")}>Duyệt</button>
        <button type="button" className="button compact" disabled={!!busy || !!error} onClick={() => void review(item, "reject")}>Từ chối</button>
      </> : <p className="notif-wait">{item.requestedById === userId ? "Bạn đã gửi yêu cầu này · chờ một Administrator khác duyệt" : "Đang chờ Administrator duyệt"}</p>}
      <button type="button" className="button compact" onClick={() => { setOpen(false); openApprovals(); }}>Mở chi tiết</button>
    </div>;
  }

  function content(item: Approval) {
    return <div className="notif-main">
      <b>{noticeTitle(item)}</b>
      <p>{item.requestedBy} gửi lúc {shortTime(item.createdAt)}</p>
      <pre className="notif-target">{item.target}</pre>
      {item.parameters && Object.keys(item.parameters).length > 0 && <pre className="notif-target">{JSON.stringify(item.parameters, null, 2)}</pre>}
      {item.reason && <small>{item.reason}</small>}
      {actions(item)}
    </div>;
  }

  const pendingNotices = notices.filter((item) => approvalStatus(item) === "pending");
  const livePopped = popped.filter((item) => pendingNotices.some((notice) => noticeKey(notice) === noticeKey(item)));
  const pending = pendingNotices.length;
  const summary = error ? "Chưa cập nhật được" : !loaded ? "Đang tải thông báo" : pending ? `${pending} việc đang chờ` : "Không có việc chờ";

  return (
    <div className="notif-wrap">
      <button type="button" className="icon-button bell" aria-expanded={open} aria-label={`Thông báo · ${summary}`}
        onClick={(event) => { event.stopPropagation(); setOpen((current) => !current); }}>
        {bellIcon}
        {pending > 0 && <span className="notif-dot">{pending}</span>}
      </button>
      {open && (
        <div className="notif-panel" role="dialog" aria-label="Thông báo và phê duyệt">
          <div className="notif-head"><h3>Thông báo</h3><span className="notif-count">{summary}</span></div>
          {error && <p className="notif-error" role="alert">{error}</p>}
          <div className="notif-list">
            {!loaded && !error && <p className="notif-empty">Đang tải thông báo…</p>}
            {loaded && !error && pending === 0 && <p className="notif-empty">Không có yêu cầu nào đang chờ xử lý.</p>}
            {pendingNotices.map((item) => <article key={noticeKey(item)} className="notif-item">{content(item)}</article>)}
          </div>
          <div className="notif-foot">
            <button type="button" className="notif-link" disabled={!!busy} onClick={() => void load()}>Thử tải lại</button>
            <button type="button" className="notif-link" onClick={() => { setOpen(false); openApprovals(); }}>Mở mục Phê duyệt</button>
          </div>
        </div>
      )}
      {livePopped.length > 0 && (
        <div className="notif-toasts" role="status" aria-live="polite">
          {livePopped.map((item) => (
            <article key={noticeKey(item)} className="notif-toast">
              {content(item)}
              <button type="button" className="notif-link" aria-label="Đóng thông báo" onClick={() => setPopped((current) => current.filter((notice) => noticeKey(notice) !== noticeKey(item)))}>✕</button>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
