/** Read the API response without leaking HTML proxy errors into the form. */
export async function readManagedTargetResponse(response: Response, operation: "list" | "create" | "edit" | "delete") {
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(operation === "list" || operation === "create"
        ? "API chưa có chức năng Thiết bị mạng / Web console (HTTP 404). Cần cập nhật đồng bộ API và giao diện; nếu đã cập nhật, kiểm tra proxy /api/ đang trỏ đúng dịch vụ API."
        : "Kết nối không còn tồn tại hoặc API chưa được cập nhật. Hãy tải lại danh sách trước khi thử lại.");
    }
    if (response.status === 401) throw new Error("Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.");
    if (response.status === 403) throw new Error("Bạn không có quyền thực hiện thao tác này.");
    if (response.status === 502 || response.status === 503 || response.status === 504) throw new Error("Dịch vụ API chưa sẵn sàng. Đợi dịch vụ khởi động xong rồi bấm Thử lại.");
    throw new Error(typeof data?.detail === "string" ? data.detail : `Không xử lý được kết nối (HTTP ${response.status}). Kiểm tra các trường đã nhập rồi thử lại.`);
  }
  if (!data || typeof data !== "object" || (operation === "list" && !Array.isArray(data.items))) {
    throw new Error("Phản hồi không đúng định dạng API. Kiểm tra proxy /api/ và cập nhật đồng bộ API với giao diện.");
  }
  return data;
}
