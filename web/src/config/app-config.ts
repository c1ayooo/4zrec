import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "4zrec",
  // 登录用户名：与后端 server/auth.go 的 loginUsername 保持一致
  loginUsername: "4zrec",
  version: packageJson.version,
  copyright: `© ${currentYear}, 4zrec.`,
  meta: {
    title: "4zrec",
    description: "LLM 驱动的自主渗透测试系统控制台",
  },
};
