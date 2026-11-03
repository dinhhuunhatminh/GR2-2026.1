# V-SecOps Engine – hệ thống lựa chọn và truy vết kết quả các công cụ bảo mật trong DevOps pipeline (MCP)

> BẢN NHÁP ĐỂ CHỈNH SỬA. Đồ án GR2, Đại học Bách khoa Hà Nội, học kỳ 2026.1.
> Sinh viên: Đinh Hữu Nhật Minh (MSSV 20235778). GVHD: TS. Vũ Thị Hương Giang.

## Giới thiệu

Pipeline DevOps có nhiều pha, mỗi pha có công cụ bảo mật riêng. Mỗi công cụ tốn thời gian chạy, bắt loại lỗi khác nhau và sinh cảnh báo sai. Dự án gồm hai máy chủ MCP để trợ lý AI (ví dụ Claude Desktop) gọi được:

| Nhánh | Việc làm | Thư mục |
|---|---|---|
| Nhánh 1 | Từ mô tả dự án và ngân sách thời gian, chọn tập công cụ bảo mật trong danh mục 18 công cụ, đưa ra 3 phương án (ít nhiễu / cân bằng / bao phủ tối đa) kèm lý do chọn và loại | `nhanh1_chon_cong_cu/` |
| Nhánh 2 | Từ kết quả quét của các công cụ, dựng đồ thị tài sản, nối các cảnh báo ở nhiều pha thành vết, gom nhóm, xếp mức ưu tiên, kèm bằng chứng tệp và dòng mã | `nhanh2_truy_vet/` |

Phần tính toán nằm trong máy chủ MCP. AI chỉ điều phối và trình bày. Hai máy chủ không gọi nhau, AI là bên chuyển kết quả của Nhánh 1 sang Nhánh 2.

## Cấu trúc thư mục

```
nhanh1_chon_cong_cu/   máy chủ MCP chọn công cụ (server.py, lib/, data/)
nhanh2_truy_vet/       máy chủ MCP truy vết (server.py, lib/, tests/)
huan_luyen_hcl/        mã dựng đặc trưng, huấn luyện và xuất bảng xác suất (HCL)
danh_gia/              mã đánh giá và kiểm thử cho Nhánh 2
```

## Yêu cầu

- Python 3.10 trở lên.
- Docker, nếu muốn chạy các công cụ quét (Nhánh 2).
- Cài thư viện: `pip install -r requirements.txt`
- Mã trong `huan_luyen_hcl/` cần thêm: `pip install -r requirements-huanluyen.txt`

## Cách chạy

Kiểm tra nhanh máy chủ có khởi động được không:

```
python nhanh1_chon_cong_cu/server.py
python nhanh2_truy_vet/server.py
```

Cài vào Claude Desktop: mở `claude_desktop_config.json` và thêm vào mục `mcpServers` (đổi đường dẫn cho đúng máy của bạn):

```json
{
  "mcpServers": {
    "chon-cong-cu-bao-mat": {
      "command": "python",
      "args": ["<đường dẫn>/nhanh1_chon_cong_cu/server.py"]
    },
    "truy-vet-nhanh2": {
      "command": "python",
      "args": ["<đường dẫn>/nhanh2_truy_vet/server.py"],
      "env": { "VSECOPS_ALLOWED_ROOTS": "<thư mục chứa repo cần quét>" }
    }
  }
}
```

Thoát hẳn Claude Desktop rồi mở lại. Biến môi trường `VSECOPS_ALLOWED_ROOTS` giới hạn thư mục mà Nhánh 2 được đọc; yêu cầu ngoài vùng này bị từ chối. Quét ứng dụng đang chạy chỉ nhắm vào các địa chỉ trong `VSECOPS_ALLOWED_TARGETS`.

## Công cụ MCP

Nhánh 1: `chon_cong_cu`, `danh_muc_cong_cu`, `huong_dan_mo_ta_du_an`.

Nhánh 2: `phien_ban`, `kiem_tra_moi_truong`, `chay_quet_tinh`, `chay_ung_dung`, `chay_quet_dong`, `tao_route_map`, `trang_thai_job`, `truy_vet`, `truy_vet_v3`, `xem_vet`, `bao_cao_vet`, `bao_cao_so_sanh`, `xep_hang_loi`, `bao_cao_v3`, `xep_hang_loi_v3`. Các công cụ chạy quét mặc định chỉ lập kế hoạch, phải xác nhận mới chạy thật.

## Phương pháp (tóm tắt)

- Nhánh 1: lớp suy luận đầu vào từ mô tả dự án, lớp xác suất bắt lỗi của từng công cụ (mặc định là mô hình học theo cấp bậc HCL, bảng `data/bang_hcl_b33b.json`; có thể chọn `hcl_v8` hoặc `bayes` để đối chiếu), rồi tìm tập công cụ tối ưu trong ngân sách thời gian.
- Nhánh 2: đồ thị tài sản nối endpoint, hàm xử lý, lời gọi hàm, tệp cấu hình, gói thư viện, image và container; vết nối các cảnh báo; nhãn cùng lỗi / cùng tài sản / chưa rõ họ.

## Kết quả hiện có và giới hạn

- Số liệu đánh giá kèm khoảng tin cậy 95% nằm trong báo cáo giữa kỳ, không lặp lại ở đây.
- Số liệu Nhánh 2 đo trên chính dữ liệu dùng để chỉnh hệ thống, người đối chiếu là Claude, nên có thể cao hơn thực tế.
- Hai giả thuyết trong số năm giả thuyết của Nhánh 1 chưa đạt; số cặp lỗi dùng để học còn ít.
- Nhánh 1 có thể chọn công cụ mà Nhánh 2 chưa xử lý được (ví dụ njsscan, eslint, codeql).
- Quét ứng dụng đang chạy rất lâu (ước lượng khoảng 1170 giây).
- AI đôi khi không gọi hệ thống mà trả lời theo trí nhớ.

## Dữ liệu và mã huấn luyện

Bộ dữ liệu lỗi và kết quả thử nghiệm không kèm trong repo vì kích thước lớn. Các tập lệnh trong `huan_luyen_hcl/` và `danh_gia/` còn ghi cứng đường dẫn tới thư mục dữ liệu của tác giả; muốn chạy lại cần chỉnh đường dẫn (biến môi trường `B33_DATA` cho một số tập lệnh).

## Giấy phép

Chưa chọn giấy phép.
