package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"procir/internal/gui"
	"procir/internal/scoring"
	"procir/internal/yara"
)

func main() {
	yaraPath := flag.String("yara", "", "YARA 规则文件或目录路径")
	flag.Parse()

	// Auto-detect yara rules in same directory as executable
	if *yaraPath == "" {
		exePath, _ := os.Executable()
		if exePath != "" {
			exeDir := filepath.Dir(exePath)
			candidates := []string{
				filepath.Join(exeDir, "rules"),
				filepath.Join(exeDir, "yara"),
				filepath.Join(exeDir, "rules.yar"),
			}
			for _, c := range candidates {
				if _, err := os.Stat(c); err == nil {
					*yaraPath = c
					break
				}
			}
		}
	}

	if *yaraPath != "" {
		engine := yara.NewEngine(*yaraPath)
		if engine != nil && engine.Enabled() {
			scoring.YaraEngine = engine
			fmt.Printf("YARA 已加载: %d 条规则 (%s)\n", engine.RuleCount(), *yaraPath)
			if errs := engine.Errors(); len(errs) > 0 {
				for _, e := range errs {
					fmt.Printf("  警告: %s\n", e)
				}
			}
		} else {
			fmt.Printf("YARA 规则加载失败: %s\n", *yaraPath)
		}
	}

	gui.Run()
}
