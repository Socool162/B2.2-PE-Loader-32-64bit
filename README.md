Mô phỏng quá trình load một file PE như Windows PE Loader:
+ Đọc file PE từ đĩa.
+ Cấp phát vùng bộ nhớ theo ImageBase/SizeOfImage.
+ Ánh xạ các section đúng địa chỉ RVA.
+ Xử lý Entry Point: mô phỏng chuyển quyền điều khiển.

Xử lý lỗi:
+ kiểm tra hợp lệ định dạng PE, cấu trúc header, section size, tránh crash khi dữ liệu sai...

Lưu ý:
+ file check_.exe chỉ để so sánh output của import directory với cff explorer (được liệt kê trong file report).  
+ Đã load được file 64bit với GUI (calc.exe ở win11)
