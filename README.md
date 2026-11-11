# WindowsProcArchDetector

[![checks](https://github.com/AiProgram/WindowsProcArchDetector/actions/workflows/ci.yml/badge.svg)](https://github.com/AiProgram/WindowsProcArchDetector/actions/workflows/ci.yml)

一个 Windows 进程运行架构判定 Demo：判断当前主机架构、指定 PID 的进程架构，并给出
`arm64`、`arm64ec`、`arm64x`、`x64`、`x86`、`arm32` 以及 WOW64/模拟信息。

实现参考了 C++ 兼容性上报模块，保留了 `host_arch`、`process_arch`、`is_wow64`、
`running_on_arm`、`is_arm_native`、`is_emulated`、`confidence`、`reason` 等字段语义。
项目不依赖任何第三方 NuGet 包。

## Highlights

- 主机架构：`IsWow64Process2` + `GetNativeSystemInfo` 回退，启动时探测一次并缓存
- 进程架构：`IsWow64Process2` / `IsWow64Process` 回退
- 主模块路径：`QueryFullProcessImageNameW` + PSAPI `GetModuleFileNameExW` 回退
- PE 解析：读取 `IMAGE_FILE_HEADER.Machine`，支持 ARM64EC/ARM64X 特征节识别
- CLI：当前进程、指定 PID、`--all`、`--name` 过滤、表格/详细/JSON 输出
- 可解释性：每个报告都包含 `confidence` 和 `reason`
- 自动化检查：17 项无 NuGet 检查、CLI JSON 冒烟、GitHub Actions CI

## Repository layout

```text
.
├─ src/ProcessArchDemo/
│  ├─ ProcessArchDemo.csproj
│  ├─ Program.cs
│  ├─ Cli/
│  │  ├─ CliApplication.cs      # 参数解析、进程枚举、输出调度
│  │  ├─ CliJson.cs             # JSON 序列化
│  │  └─ TextReportWriter.cs    # 表格和详细文本
│  └─ Compat/
│     ├─ ArchitectureClassifier.cs # 纯架构映射/ARM 标志规则
│     ├─ ArchitectureDetector.cs   # Win32 探测和综合决策
│     ├─ CompatibilityReport.cs    # 数据模型和字符串格式化
│     ├─ NativeMethods.cs          # P/Invoke
│     └─ PeImageInspector.cs       # PE 头和节表解析
├─ tests/ProcessArchDemo.Tests/
│  ├─ ProcessArchDemo.Tests.csproj
│  ├─ Program.cs
│  ├─ TestRunner.cs
│  ├─ PeFixtureBuilder.cs
│  ├─ ClassifierTests.cs
│  ├─ PeImageInspectorTests.cs
│  ├─ DetectorTests.cs
│  └─ CliJsonTests.cs
├─ check.ps1
├─ check.cmd
├─ .github/workflows/ci.yml
└─ LICENSE
```

## Requirements

- Windows 10 1709 或更高版本（推荐 Windows 11）
- .NET SDK 11，用于当前 `net11.0-windows` 目标
- 若使用 .NET 8/9，把下面两个 csproj 的 `TargetFramework` 改成 `net8.0-windows` 或
  `net9.0-windows` 即可：
  - `src/ProcessArchDemo/ProcessArchDemo.csproj`
  - `tests/ProcessArchDemo.Tests/ProcessArchDemo.Tests.csproj`

## Build and run

```powershell
# 构建
dotnet build .\src\ProcessArchDemo\ProcessArchDemo.csproj -c Release

# 当前进程
dotnet run --project .\src\ProcessArchDemo\ProcessArchDemo.csproj -c Release

# 指定 PID（支持逗号分隔）
dotnet run --project .\src\ProcessArchDemo\ProcessArchDemo.csproj -c Release -- 1234 5678

# 扫描全部可见进程
dotnet run --project .\src\ProcessArchDemo\ProcessArchDemo.csproj -c Release -- --all

# 扫描并过滤进程名，输出 JSON
dotnet run --project .\src\ProcessArchDemo\ProcessArchDemo.csproj -c Release -- --all --name msedge --json
```

构建后也可以直接运行 apphost：

```text
src\ProcessArchDemo\bin\Release\net11.0-windows\ProcessArchDemo.exe --all
```

如果在受限宿主环境中直接启动 apphost 时只能看到少量进程，可以改用 DLL 启动；这是宿主进程
隔离造成的，不是进程枚举逻辑本身的限制：

```powershell
dotnet .\src\ProcessArchDemo\bin\Release\net11.0-windows\ProcessArchDemo.dll --all
```

## Automated checks

运行一条命令完成构建、17 项检查、CLI JSON 冒烟和 CLI 错误码检查：

```powershell
pwsh .\check.ps1
# 或
.\check.cmd
```

如果 PowerShell 执行策略禁止运行本地脚本，可使用：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\check.ps1
```

检查内容包括：

- PE 机器类型到 `x86/x64/arm32/arm64/arm64ec/arm64x` 的映射
- `.a64xrm` / `.hexpthk` hybrid 特征节对 ARM64EC/ARM64X 的细化
- 合成 PE 文件解析，包括 `SizeOfOptionalHeader`、大小写节名、损坏的 MZ/e_lfanew
- ARM 主机上的 `is_arm_native` / `is_emulated` 组合
- 主机架构与 `RuntimeInformation.OSArchitecture` 的一致性
- 当前进程架构与 `RuntimeInformation.ProcessArchitecture` 的一致性
- 实际启动 `SysWOW64\cmd.exe`，验证 x86/WOW64 进程能被识别
- 不存在的 PID 不会抛异常，返回 `unknown` + `low`
- JSON 字段结构、空进程列表和 reason 字段
- CLI 的 JSON 退出码、未知参数的退出码

CI 配置见 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)，在 `windows-latest` 上执行同一份
`check.ps1`。

## Output

单进程示例（Windows 11 ARM64 实测）：

```text
Host architecture : arm64
Host detection    : IsWow64Process2 (native machine 0xAA64)

PID 16744 (powershell)
  host_arch         : arm64
  process_arch      : arm64x
  is_wow64          : false
  running_on_arm    : true
  is_arm_native     : true
  is_emulated       : false
  confidence        : high
  runtime_machine   : unknown
  pe_machine        : ARM64
  hybrid_pe         : true (.hexpthk, .a64xrm)
  image_path        : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  reason            : host=arm64 (native machine 0xAA64); runtime=unknown; wow64=false
                      [IsWow64Process2]; PE=ARM64; hybrid-sections=.hexpthk,.a64xrm
```

JSON 输出使用固定根结构：

```json
{
  "schema_version": 1,
  "host": {
    "arch": "arm64",
    "native_machine": "0xAA64",
    "detection": "IsWow64Process2",
    "diagnostic": null
  },
  "processes": [
    {
      "pid": 1234,
      "process_name": "cmd",
      "image_path": "C:\\Windows\\SysWOW64\\cmd.exe",
      "process_arch": "x86",
      "host_arch": "arm64",
      "is_wow64": true,
      "running_on_arm": true,
      "is_arm_native": false,
      "is_emulated": true,
      "confidence": "high",
      "runtime_machine": "I386",
      "pe_machine": "I386",
      "hybrid_pe_metadata": false,
      "hybrid_pe_sections": [],
      "reason": "host=arm64 (native machine 0xAA64); runtime=I386; wow64=true [IsWow64Process2]; PE=I386"
    }
  ]
}
```

## Field semantics

| Field | Meaning |
| --- | --- |
| `host_arch` | 操作系统原生架构，不是当前进程架构 |
| `process_arch` | 进程主模块架构，可能是 `arm64ec` / `arm64x` |
| `is_wow64` | `IsWow64Process2` 的 `ProcessMachine != UNKNOWN` 原始结果 |
| `running_on_arm` | 主机是 ARM32/ARM64 |
| `is_arm_native` | ARM 主机上的原生 ARM 进程：`arm64`、`arm64ec`、`arm64x` |
| `is_emulated` | ARM 主机上运行了需要 CPU 模拟的架构：`x86`、`x64`、`arm32` |
| `confidence` | `high` / `medium` / `low` |
| `reason` | 判定依据和失败原因，适合服务端上报和排障 |

> `is_wow64` 是原始 API 语义，不要把它当作“是否在模拟”的唯一指标。实测在 ARM64 Windows 上，
> x64 模拟进程的 `IsWow64Process2` 可能返回 `ProcessMachine=UNKNOWN`，`is_wow64=false`；
> 此时应结合 `process_arch` 和 `is_emulated` 判断。x86 进程在 ARM64 上通常返回 `I386`，
> `is_wow64=true`。在 x64 主机上，x86 进程也会返回 `WOW64=true`。

## Detection flow

1. **主机架构**：对当前进程调用一次 `IsWow64Process2`，读取 `NativeMachine`。失败时回退
   到 `GetNativeSystemInfo`，并缓存结果。
2. **运行时证据**：对目标 PID 调用 `IsWow64Process2` 获取 `ProcessMachine` 和
   `NativeMachine`；旧系统回退到 `IsWow64Process`。
3. **主模块路径**：优先 `QueryFullProcessImageNameW(PROCESS_QUERY_LIMITED_INFORMATION)`；
   失败时使用 `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`，再回退到
   `GetModuleFileNameExW`。
4. **PE 证据**：读取 DOS/NT 头和节表，取 `IMAGE_FILE_HEADER.Machine`，并检查
   `.a64xrm`、`.hexpthk` 特征节。
5. **综合判定**：
   - PE 可读时以 PE 为准，`confidence=high`；
   - PE 与运行时 `ProcessMachine` 冲突时降为 `medium`；
   - PE 不可读但运行时信息可用时使用运行时结果；
   - 只能从主机架构安全推断时使用运行结果/主机信息，`low`；
   - 无法取得有效证据时返回 `unknown` + `low`，不会猜测。

PE 机器类型映射：

| Machine | Result |
| --- | --- |
| `0x014C` | x86 |
| `0x8664` | x64 |
| `0x01C0` / `0x01C2` / `0x01C4` | arm32 |
| `0xAA64` | arm64；带 hybrid 节时进一步判定 |
| `0xA641` | arm64ec |
| `0xA64E` | arm64x |

Hybrid 规则：

- `Machine=AMD64` 且存在 `.a64xrm` / `.hexpthk`：按 `arm64ec` 处理；
- `Machine=ARM64` 且存在上述特征节：按 `arm64x` 处理；
- 特征节是辅助启发式，PE 的 `Machine` 字段仍是主要依据。

## Verified on Windows 11 ARM64

| Process | Result |
| --- | --- |
| `ProcessArchDemo.exe` | `arm64`，high |
| `powershell.exe` | `arm64x`，high，含 `.hexpthk`、`.a64xrm` |
| `DeepSeek Harness.exe` | `x64`，`is_emulated=true`，high |
| `SysWOW64\cmd.exe` | `x86`，`is_wow64=true`，`is_emulated=true`，high |
| 全量扫描 | 约 230 个进程，覆盖 arm64/arm64x/x64/x86 |

`unknown` 大多来自 `wininit`、`WmiPrvSE`、`TrustedInstaller` 等受保护/系统进程：当前用户令牌
无法 `OpenProcess` 或读取镜像路径。以管理员身份运行、并具备 `SeDebugPrivilege` 时可以显著减少。

## Limitations

- **权限**：Session 0 服务读取用户进程、读取受保护进程时可能失败。可以提升权限、启用
  `SeDebugPrivilege` 后重试，或把报告降级为 `low` 并保留 `reason`。
- **主模块路径不等于内存中模块的实时状态**：如果进程启动后磁盘上的 EXE 被替换，PE 信息
  可能与实际加载镜像不一致，此时会给出 `medium` 和冲突说明。
- **解释型/托管应用**：`dotnet MyApp.dll`、Java、Node 等进程报告的是宿主可执行文件
  （如 `dotnet.exe`）的架构，而不是 IL/字节码/JIT 后的架构。
- **文件系统重定向**：如果本工具本身编译为 x86，在 32 位视图中打开 `System32` 路径可能被
  重定向到 `SysWOW64`。Demo 以原生 ARM64 运行，未处理这个场景。
- **Hybrid 识别**：`.a64xrm` / `.hexpthk` 是工具链特征节，属于辅助判断；不保证覆盖所有厂商
  生成的 ARM64EC/ARM64X 镜像。
- **ARM64 上的 `ProcessMachine=UNKNOWN`**：实测 x64 模拟进程也可能返回 `UNKNOWN`，因此运行时
  API 本身无法区分“原生 ARM64/ARM64X”和“x64 模拟”。如果 PE 也读不到，Demo 会返回
  `process_arch=unknown`（`low`），而不是猜测成 arm64。

## Differences from the reference C++ module

- 使用 `IntPtr` + `finally CloseHandle` 管理进程句柄，避免泄漏；
- PE 解析按文件偏移读取，不依赖固定的 4 KB 头部缓冲区；
- 增加 JSON 输出、批量 PID、`--all`、名称过滤和汇总；
- 将纯映射规则抽到 `ArchitectureClassifier`，可离线检查；
- 对 `IsWow64Process2`、路径查询和 PSAPI 都做了回退与错误文本收集；
- 增加无 NuGet 的自动化检查与 CI。

## License

[MIT](LICENSE)
