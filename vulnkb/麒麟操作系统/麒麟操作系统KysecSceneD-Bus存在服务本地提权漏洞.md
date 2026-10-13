# 麒麟操作系统KysecSceneD-Bus存在服务本地提权漏洞

- **系统**：麒麟操作系统　|　**类型**：权限提升　|　**CVE**：—

**请求体 / payload**
```
**一、漏洞概述**
该漏洞存在于麒麟系统中的 com.kylin.KysecScene D-Bus 系统服务。该服务以 root 权限运行，但其 D-Bus 策略配置过于宽松，允许任意本地用户直接调用敏感方法。同时，服务暴露的 LoadJson 与 SaveJson 方法对传入文件路径缺乏访问控制与路径校验，导致低权限用户可借助该服务实现：
读取高敏感文件（如 /etc/shadow）。
以 root 身份向任意路径写入数据（如 /etc/passwd）。
最终可形成完整的本地提权链，攻击者能够获得 root 权限并完全控制系统。
**二、漏洞定位过程**
1. 枚举系统 D-Bus 服务
通过以下命令可定位到目标服务：
busctl --system list  grep -i kylin
输出中可见：
com.kylin.KysecScene ... root ...
这表明 KysecScene 由 root 身份运行。
2. 检查 D-Bus 策略文件
策略文件路径如下：
cat /usr/share/dbus-1/system.d/com.kylin.KysecScene.conf
关键配置（原意）为允许默认上下文用户访问该服务：
<policy context="default">
<allow own="com.kylin.KysecScene"/>
<allow …（脚本共 2298 字，完整版见原文）
```
- **预期**：200　|　—