"use client";

import Link from "next/link";

import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="flex h-dvh flex-col items-center justify-center space-y-2 text-center">
      <h1 className="font-semibold text-2xl">页面不存在</h1>
      <Link prefetch={false} replace href="/function/tasks">
        <Button variant="outline">返回任务列表</Button>
      </Link>
    </div>
  );
}
