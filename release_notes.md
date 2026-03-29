## ProcIR v1.4.0 - Windows 应急响应进程排查工具

面向安全工程师的一键式应急响应工具，快速定位木马、后门、持久化、白加黑、内存注入等威胁。

### v1.4.0 — 规则体系全面增强

本次更新对检测规则体系进行系统性优化，新增 40+ 条规则，覆盖高价值攻击链盲区，同时强化误报控制。

#### LOLBin 扩充与分级

- **新增 12 个 LOLBin**：bash.exe / wsl.exe / finger.exe / ftp.exe / curl.exe / tar.exe / control.exe / pktmon.exe / replace.exe / ie4uinit.exe / msxsl.exe / diantz.exe
- **三级风险分级**：低风险(+8) / 中风险(+12) / 高风险(+18)，替代原有统一 +12 评分
- 总计 52 个 LOLBin 覆盖

#### AMSI / Defender 绕过检测（新增）

- 命令行检测：`amsiinitfailed` / `amsiutils` → +30
- Defender 排除项篡改：`Set-MpPreference -ExclusionPath` / `-DisableRealtimeMonitoring` → +25
- PowerShell 4104 脚本块同步检测
- **强规则**：AMSI 绕过 + 下载/IEX → 最低 80 (Critical)
- **新行为链**：AMSI/Defender 绕过链 (+25~35)

#### LSASS / 凭证访问检测（新增）

- 命令行关键词：sekurlsa / minidump / comsvcs.dll / procdump+lsass / nanodump / dumpert / pypykatz / handlekatz → +35
- **强规则**：LSASS 转储 → 最低 80 (Critical)
- Sysmon Event ID 10 (ProcessAccess)：访问 LSASS → +30
- Sysmon Event ID 8 (CreateRemoteThread)：远程线程 → +25，注入 LSASS → +45
- **新行为链**：凭证获取链 (+35~40)

#### .NET 无文件攻击检测（新增）

- Assembly.Load / Add-Type / AppDomain / CodeDom.Compiler → +25
- csc.exe / vbc.exe 可疑编译 → +20
- PowerShell 4104 脚本块中 .NET 反射 → +25

#### 横向移动检测（新增）

- WMIC 远程进程创建 (`process call create`) → +25
- 远程计划任务 (`schtasks /create /s`) → +25
- 远程服务创建 (`sc \\host create`) → +25
- PsExec / WinRS / Enter-PSSession → +30
- **新行为链**：横向移动链 (+30)

#### Sysmon 事件覆盖扩展

- **新增 Event ID 8**：CreateRemoteThread → +25，目标 LSASS → +20
- **新增 Event ID 10**：ProcessAccess → LSASS +30
- **新增 Event ID 17/18**：命名管道 → 可疑管道名 (postex/meterpreter/cobalt/beacon/psexec) → +25
- **新增 Event ID 4703**：高危令牌权限调整 (SeDebugPrivilege 等) → +20

#### 浏览器/Electron 误报控制

- 新增 15 个已知 Electron 应用白名单 (VS Code / Teams / Slack / Discord 等)
- Electron 应用不再触发「浏览器→系统工具」规则
- 已签名 Electron 应用 + 可信路径：-10 降权

#### 评分体系优化

- **上下文权重封顶**：命令行乘数上限 +25，父子链乘数上限 +15（防止分数膨胀）
- **融合引擎增强**：
  - 用户目录 + 事件 + 触发器：+20
  - DLL 劫持 + YARA + 外联：最低 80 (Critical)
  - **反证机制**：可信签名 + 可信路径 + 无任何异常证据 → 分数封顶 20 (Suspicious)

#### 新增行为链（3 条，总计 9 条）

| 攻击链 | 分值 | 模式 |
|--------|------|------|
| 凭证获取链 | +35~40 | LSASS/Dump 工具 + 特权 + 外联 |
| AMSI/Defender 绕过链 | +25~35 | AMSI bypass + 下载/IEX |
| 横向移动链 | +30 | WMIC/PsExec/WinRS/远程任务/远程服务 |

---

### 使用

```
procir.exe                    # 直接运行
procir.exe -yara rules.yar   # 带 YARA 规则
```
