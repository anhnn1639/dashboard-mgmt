# Patch relay cho mạng máy chủ cách ly

## Mô hình ứng dụng hỗ trợ

Dashboard tìm và cài bản cập nhật qua update engine gốc của hệ điều hành:

- Windows Server dùng Windows Update Agent (WUA). WUA đánh giá tính tương thích ngay trên máy đích, vì vậy Server 2019 chỉ trả các update áp dụng được cho máy 2019 và Server 2022 được đánh giá độc lập.
- Ubuntu dùng các nguồn APT đang cấu hình cho đúng release đã cài.
- Oracle Linux và Red Hat Enterprise Linux dùng các repository YUM/DNF đang bật cho đúng release và kiến trúc đã cài.

Control plane không coi tên update là bằng chứng tương thích. Task cập nhật hàng loạt được nhóm theo đúng tên OS, version và kiến trúc; catalog cho chọn là giao của các lần quét hoàn tất trên mọi máy đích. API kiểm tra lại ID/version bằng lần quét hoàn tất mới nhất của từng máy và ghim revision Windows riêng của máy đó trước khi tạo job.

## Topology relay khuyến nghị

Không dùng máy chủ ngoài Internet như một file proxy tải tùy ý `.msu`, `.deb` hoặc `.rpm` rồi yêu cầu control plane thực thi. Phải dùng protocol repository gốc có chữ ký:

1. Windows: triển khai WSUS upstream ở vùng có kết nối và WSUS internal/downstream (hoặc dùng quy trình export/import WSUS cho mạng cách ly). Cấu hình máy đích bằng Group Policy với `UseWUServer=1` và URL HTTPS của WSUS internal.
2. Ubuntu: xuất bản mirror/snapshot APT đã ký cho từng release hỗ trợ (`jammy` 22.04 và `noble` 24.04) qua repository HTTPS nội bộ.
3. Oracle Linux / Red Hat: xuất bản repository YUM/DNF đã ký cho từng major release và kiến trúc. Pulp/Satellite hoặc repository manager tương đương có thể đồng bộ và tạo snapshot nội dung.
4. Chỉ cho máy được quản trị kết nối tới endpoint WSUS/repository nội bộ. Control plane tiếp tục giao tiếp với Agent chỉ qua kênh mTLS 9443 hiện có.

Cách này cho relay ngoài tải một lần, còn client gốc vẫn xác minh chữ ký Microsoft/package, dependency và tính tương thích. Nó cũng tránh đẩy payload patch nhiều GiB qua kênh điều khiển Agent.

## Thông tin cần có trước khi bật relay production

- URL WSUS internal/upstream, TLS CA, port và thông tin mạng internal có cách ly hoàn toàn hay không.
- URL repository APT và signing key cho Ubuntu 22.04/24.04.
- URL repository YUM/DNF, GPG key và mô hình subscription/content entitlement cho Oracle Linux 7/8 và RHEL 7/8.
- Product, classification, language, architecture được duyệt; thời gian lưu và dung lượng kho.
- Đồng bộ tự động qua proxy hay export/import offline có ký/xác minh.

Không lưu secret hoặc private key ký repository trong database dashboard hay gói Agent. Sau khi có các endpoint trên, automation triển khai có thể cấu hình nguồn native; cơ chế kiểm tra kết nối nhanh hiện tại sẽ báo `Mất kết nối WSUS` hoặc `Không kết nối được repository` mà không khởi chạy lần quét online dài.
