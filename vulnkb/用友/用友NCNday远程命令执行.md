# 用友NCNday远程命令执行

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="产品登录界面"`

**请求体 / payload**
```
nday的路径
/service/~baseapp/UploadServlet
/service/ECFileManageServlet
/servlet/~ic/nc.bs.framework.mx.monitor.MonitorServlet
/servlet/~ic/nc.bs.framework.mx.MxServlet
/servlet/~uapxbrl/uap.xbrl.persistenceImpl.XbrlPersistenceServlet
/servlet/~uapss/com.yonyou.ante.servlet.FileReceiveServlet
/servlet/~ic/nc.document.pub.fileSystem.servlet.DownloadServlet
/servlet/~ic/nc.document.pub.fileSystem.servlet.UploadServlet
/servlet/~ic/nc.document.pub.fileSystem.servlet.DeleteServlet
/servlet/~ic/com.ufida.zior.console.ActionHandlerServlet
/ServiceDispatcherServlet
/servlet/~baseapp/nc.message.bs.NCMess…（脚本共 804 字，完整版见原文）
```
- **预期**：200　|　—