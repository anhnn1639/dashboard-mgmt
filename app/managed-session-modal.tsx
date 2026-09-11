"use client";

import { FormEvent, useEffect, useState } from "react";
import { ModalShell } from "./server-resource-tabs";

type Choice = { id: string; username: string; label: string };

export function ManagedSessionModal({ target, token, close, notify }: {
  target: { id: string; name: string; kind: "network" | "web" };
  token: string;
  close: () => void;
  notify: (message: string) => void;
}) {
  const protocol = target.kind === "web" ? "web" : "ssh";
  const [choices, setChoices] = useState<Choice[]>([]);
  const [selected, setSelected] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const abort = new AbortController();
    fetch(`/api/v1/servers/${target.id}/remote-credentials?protocol=${protocol}`, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store", signal: abort.signal })
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Không tải được tài khoản xác thực.");
        if (!abort.signal.aborted) { setChoices(data.items); setSelected(data.items[0]?.id ?? ""); }
      })
      .catch((reason) => { if (!abort.signal.aborted) setError(reason instanceof Error ? reason.message : "Không tải được tài khoản xác thực."); })
      .finally(() => { if (!abort.signal.aborted) setLoading(false); });
    return () => abort.abort();
  }, [target.id, protocol, token]);

  async function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected || busy) return;
    const popup = window.open("about:blank", "_blank");
    if (!popup) { setError("Trình duyệt đã chặn cửa sổ phiên. Cho phép popup cho Operation Portal rồi thử lại."); return; }
    popup.opener = null;
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/v1/sessions/launch", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ server_id: target.id, protocol, credential_id: selected }) });
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Không tạo được phiên kết nối.");
      const destination = new URL(data.url, window.location.origin);
      if (destination.origin !== window.location.origin || !destination.pathname.startsWith("/guacamole/")) throw new Error("Địa chỉ phiên truy cập không hợp lệ.");
      try { window.localStorage.removeItem("GUAC_AUTH_TOKEN"); } catch { /* Browser storage may be disabled. */ }
      popup.location.href = destination.href;
      notify(protocol === "web" ? "Đã tạo phiên Web console qua Operation Portal. Website sẽ mở sau khi ghi hình sẵn sàng." : "Đã tạo phiên SSH có ghi hình. Có thể paste văn bản vào phiên.");
      close();
    } catch (reason) {
      popup.close();
      setError(reason instanceof Error ? reason.message : "Không tạo được phiên kết nối.");
    } finally { setBusy(false); }
  }

  return <ModalShell title="Chọn tài khoản kết nối" subtitle={`${target.name} · phiên được ghi hình`} close={() => { if (!busy) close(); }}>
    <form className="resource-form" onSubmit={connect}>
      {error && <div className="danger-panel" role="alert">{error}</div>}
      <label>Username<select value={selected} required disabled={loading || busy || !choices.length} onChange={(event) => setSelected(event.target.value)}><option value="">{loading ? "Đang tải tài khoản…" : "Chọn tài khoản…"}</option>{choices.map((item) => <option key={item.id} value={item.id}>{item.username}{item.label !== item.username ? ` · ${item.label}` : ""}</option>)}</select></label>
      {!loading && !choices.length && !error && <div className="warning-box">Chưa có tài khoản được phép sử dụng. Administrator cần tạo hoặc chia sẻ tài khoản trong mục Tài khoản xác thực.</div>}
      <p className="resource-help">Chỉ sử dụng tài khoản được cấp quyền. Mật khẩu đã lưu không trả về máy người dùng; phiên được ghi lại để kiểm toán.</p>
      {protocol === "web" && <p className="resource-help">Operation Portal tự điền tài khoản đã chọn và đăng nhập sau khi ghi hình sẵn sàng. Nếu website yêu cầu OTP/CAPTCHA hoặc biểu mẫu riêng, hãy hoàn tất bước đó ngay trong phiên.</p>}
      <div className="modal-actions"><button type="button" className="button ghost" disabled={busy} onClick={close}>Hủy</button><button className="button primary" disabled={loading || busy || !selected}>{busy ? "Đang chuẩn bị kết nối…" : "Kết nối"}</button></div>
    </form>
  </ModalShell>;
}
