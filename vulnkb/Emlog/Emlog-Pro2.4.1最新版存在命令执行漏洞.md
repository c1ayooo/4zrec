# Emlog-Pro2.4.1最新版存在命令执行漏洞

- **系统**：Emlog　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="EMLOG"`

**请求体 / payload**
```
在外观-模板-安装模板中 上传一个带有恶意文件的zip。
注意 模板文件需要与其格式一致，文末附下载链接.
传成功，访问对应的恶意文件路径。
url路径:http://emlog/content/templates/shell/header.php?pass=phpinfo();
```
- **预期**：200　|　—