# 叮叮演示版某涉案系统ajax存在信息泄露漏洞

叮叮演示版某涉案系统 ｜ 信息泄露 ｜ —
- **指纹**：`header="Access-Control-Allow-Headers: x-requested-with,content-type,x-csrf token,appkey,token"`

**Payload**
```
通过报错ThinkPHP 访问 /index.php/api/ajax 能得到tp的数据库账号密码
```
- **响应特征**：200