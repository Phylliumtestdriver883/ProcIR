## ProcIR v1.5.1 - Windows 应急响应进程排查工具

面向安全工程师的一键式应急响应工具，快速定位木马、后门、持久化、白加黑、内存注入等威胁。

### v1.5.1 — Bug 修复 & 代码优化

本次更新修复了多个进程分析误报问题，优化了 IOC 提取、YARA 加载流程和代码质量。

#### 进程分析误报修复

- **修复 OriginalFilename `.mui` 后缀误报**：Windows 系统文件（如 svchost.exe）的 `GetFileVersionInfo` 返回 `svchost.exe.mui`，导致"原始文件名不匹配"误判 +10 分。现在在签名提取阶段自动剥离 `.mui` 后缀
- **修复 masquerade 检测硬编码 `C:\` 问题**：改用 `HasSuffix` 匹配 `\windows\system32\...`，不再依赖盘符，支持非 C: 盘 Windows 安装
- **补充 SysWOW64 路径**：dllhost.exe 等进程在 SysWOW64 下不再被误判为伪装
- **扩展 expectedParents**：smss.exe 补充 `[system process]`；dllhost.exe 补充 `services.exe`；减少父进程链误报
- **OriginalName 比较加 `filepath.Base` 提取**：防止带路径前缀时误判

#### IOC 提取修复

- **修复网络 IP 未纳入 IOC**：进程网络连接采集到的公网 IP 现在直接进入 IOC 列表（之前只从命令行正则提取，遗漏了实际网络连接）
- **移除域名提取**：域名正则误报率极高（文件名、路径、版本号被匹配），已移除。域名信息已包含在 URL 提取中
- **修复 IP 校验缺失 octet 范围检查**：版本号如 `4.18.26020.6` 不再被误判为 IP 地址
- **补充过滤**：广播地址 (255.x.x.x)、组播地址 (224-239.x.x.x) 现在被正确过滤

#### YARA 界面增强

- **新增"加载规则文件夹"按钮**：支持浏览器选择文件夹，自动过滤 .yar/.yara/.rule 文件
- **递归加载规则目录**：`filepath.WalkDir` 替代 `os.ReadDir`，子目录中的规则文件也会被加载
- **修复多文件上传 N+1 性能问题**：上传 N 个文件不再触发 N 次全目录重解析，改为 upload(save-only) + 单次 reload
- **GUI 模式不再从命令行加载 YARA**：统一在界面操作，CLI 模式不受影响

#### 代码质量优化

- **YARA 面板全面 i18n 化**：所有按钮、提示、错误消息改用 `t()` 函数，英文模式完整翻译
- **替换手写 `itoa` / `baseName`**：改用标准库 `strconv.Itoa` / `filepath.Base`
- **删除未使用代码**：移除 `rePath` 正则、`isInterestingDomain` 等死代码 (~80 行)
- **修复 `io.Copy` / `dst.Close()` 错误丢弃**：YARA 文件上传时磁盘写入错误不再被静默忽略

---

### 使用

```
procir.exe                    # GUI 模式（默认）
procir.exe -yara rules.yar   # GUI 模式（YARA 在界面加载）
procir.exe -cli -o scan.json # CLI 模式，导出 JSON
```
