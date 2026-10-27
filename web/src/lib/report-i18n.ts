// 报告页 i18n shim:antifox 移植页面的文案表(内嵌 zh-CN),提供
// useTranslation 的最小兼容(t(key, {name}) 支持 {{name}} 插值)。
// 全站固定中文,不引入 react-i18next 运行时。
import * as React from "react";

const TABLE: Record<string, string> = {
  "reports.title": "报告管理",
  "reports.subtitle": "报告出具方 / Logo / 测试人员等组织级设置 + 已生成报告清单",
  "reports.settingsTitle": "报告设置",
  "reports.settingsHint": "这些设置作用于所有报告的封面与页眉（每份报告生成时读取）",
  "reports.company": "报告出具方",
  "reports.companyPlaceholder": "如 XX 安全服务团队（封面与页眉都用它）",
  "reports.companyEn": "出具方（英文，可选）",
  "reports.logo": "报告 Logo",
  "reports.uploadLogo": "上传 Logo",
  "reports.clearLogo": "清除 Logo",
  "reports.logoUploaded": "Logo 已上传",
  "reports.personnel": "测试人员",
  "reports.personName": "姓名",
  "reports.personRole": "角色",
  "reports.personContact": "联系方式",
  "reports.addPerson": "添加人员",
  "reports.cvssVersion": "CVSS 版本",
  "reports.saved": "报告设置已保存",
  "reports.listTitle": "已生成报告",
  "reports.listHint": "每次生成 Word 报告后自动记录，可随时下载",
  "reports.colTask": "任务",
  "reports.colFile": "文件名",
  "reports.colCompany": "出具方",
  "reports.colSize": "大小",
  "reports.colTime": "生成时间",
  "reports.download": "下载",
  "reports.empty": "暂无报告，去任务详情的「报告」页生成",
  "reports.newReport": "新建报告",
  "reports.newReportHint": "选择一个任务，用其漏洞与资产生成 Word 报告（异步，完成后出现在下方列表）",
  "reports.selectTask": "选择任务",
  "reports.selectTaskPlaceholder": "选择要出报告的任务",
  "reports.reportTitle": "报告标题（可选）",
  "reports.reportTitlePlaceholder": "留空自动用任务名",
  "reports.clientName": "客户名称（可选）",
  "reports.clientPlaceholder": "客户名（封面用）",
  "reports.generate": "生成",
  "reports.generating": "生成中…",
  "reports.genStarted": "已开始生成，请稍候…",
  "reports.genDone": "报告已生成",
  "reports.genFailed": "生成失败：{{msg}}",
  "reports.language": "报告语言",
  "reports.langZhCN": "简体中文",
  "reports.langZhTW": "繁体中文",
  "reports.langEnUS": "英文",
  "reports.selectFindings": "选择漏洞",
  "reports.findingsAll": "全选",
  "reports.findingsNone": "全不选",
  "reports.findingsSelected": "已选 {{n}}/{{total}}",
  "reports.findingsEmpty": "该任务暂无漏洞",
  "reports.findingsLoading": "加载漏洞中…",
  "reports.templatesTitle": "报告模版",
  "reports.templatesHint": "保存多份「出具方 / Logo / 测试人员 / 默认语言」预设，新建报告时选用",
  "reports.newTemplate": "新建模版",
  "reports.editTemplate": "编辑模版",
  "reports.templateName": "模版名称",
  "reports.templateNamePlaceholder": "如 中文标准交付 / English Delivery",
  "reports.useTemplate": "使用模版",
  "reports.templateNone": "不使用（用报告设置默认）",
  "reports.templateSaved": "模版已保存",
  "reports.templateDeleted": "模版已删除",
  "reports.deleteTemplateConfirm": "确定删除该模版？",
  "reports.templatesEmpty": "暂无模版，点「新建模版」创建",
  "reports.templateColName": "名称",
  "reports.templateColLang": "默认语言",
  "reports.delete": "删除",
  "reports.deleted": "报告已删除",
  "reports.deleteConfirm": "确认删除报告「{{name}}」？此操作不可撤销。",
  "taskDetail.report.genStarted": "已开始生成报告，请稍候…",
  "common.saving": "保存中…",
  "taskDetail.report.generate": "生成 Word 报告",
  "taskDetail.report.regenerate": "重新生成",
  "common.save": "保存",
  "taskDetail.report.generating": "生成中…",
  "taskDetail.report.download": "下载 Word 报告",
  "taskDetail.report.genFailed": "报告生成失败：{{msg}}",
  "common.loading": "加载中…",
  "taskDetail.report.docxHint":
    "「生成 Word 报告」调用 AI 将发现改写为专业中文叙述，并用 python-docx 排版成交付级 .docx；下方为 Markdown 快速预览。",
  "taskDetail.report.empty": "暂无报告",
  "common.cancel": "取消",
  "taskDetail.report.copyToast": "已复制 Markdown",
  "taskDetail.report.title": "渗透测试报告（Markdown）",
  "taskDetail.copy": "复制",
};

export function t(key: string, opts?: Record<string, unknown>): string {
  let s = TABLE[key] ?? key;
  if (opts) {
    for (const [k, v] of Object.entries(opts)) {
      s = s.replace(new RegExp(`{{${k}}}`, "g"), String(v));
    }
  }
  return s;
}

export function useTranslation(): { t: typeof t } {
  return { t };
}

export type TFunction = typeof t;
