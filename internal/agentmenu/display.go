package agentmenu

import "fmt"

func stateLabel(v any) string {
	s := str(v)
	labels := map[string]string{"queued": "等待处理", "running": "正在执行", "verifying": "正在检查", "succeeded": "已完成", "failed": "执行失败", "failed_manual": "需要人工处理", "unknown": "结果未确认", "pending_cleanup": "等待服务器清理", "superseded": "已被新任务取代", "retry_wait": "等待重试", "verified": "已验证", "pending": "等待应用", "enabled": "启用", "disabled": "停用", "deleted": "已请求删除"}
	if label, ok := labels[s]; ok {
		return label
	}
	return s
}
func showImpact(v object) {
	fmt.Printf("实例 %s，版本 %v，状态：%s\n", str(v["id"]), v["version"], stateLabel(v["actual_state"]))
	if nodes, ok := v["nodes"].([]any); ok {
		for _, item := range nodes {
			if n, ok := item.(map[string]any); ok {
				fmt.Printf("• %s | 端口 %v | %s / %s | %s\n", str(n["name"]), n["port"], stateLabel(n["desired_state"]), stateLabel(n["actual_state"]), str(n["id"]))
			}
		}
	}
	fmt.Println("以上是面板记录，整个实例发布会应用所有专线组的当前授权。")
}
func showTask(v object) {
	fmt.Printf("任务：%s\n状态：%s\n原因：%s\n更新时间：%s\n", str(v["id"]), stateLabel(v["state"]), str(v["last_error"]), str(v["updated_at"]))
	switch str(v["state"]) {
	case "queued", "running", "verifying", "retry_wait":
		fmt.Println("下一步：稍后再查询，不要重复提交。")
	case "unknown":
		fmt.Println("下一步：选择“检查服务器实际状态”。未知不等于成功，也不等于未执行。")
	case "failed", "failed_manual", "superseded":
		fmt.Println("下一步：查看面板部署状态与本机日志，按当前配置处理。")
	}
	if children, ok := v["children"].([]any); ok {
		for _, child := range children {
			if c, ok := child.(map[string]any); ok {
				fmt.Printf("子任务 %s：%s %s\n", str(c["id"]), stateLabel(c["state"]), str(c["last_error"]))
			}
		}
	}
}
