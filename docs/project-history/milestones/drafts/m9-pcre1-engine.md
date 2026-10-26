# M9 PCRE1 原型（Source foundation，未商用闭环）

当前主干使用 Node RegExp 的有界 Worker 子集，无法执行 atomic/possessive、命名引用、条件、递归等 PCRE1 语法。该原型以固定 PCRE 8.45 原生独立进程替代；不回退 JS，不创造 Kong1.5 不存在的调试端点，不更改 Admin API 白名单、权限或真实代理探测的固定 origin/SSRF 保护。

官方来源为 PCRE Project 的 SourceForge 8.45 release。tar.gz SHA256 `4e6ce03e0336e8b4a3d6c2b70b1c5e18590a5673a98186da90d4f33c23defc09`，2,096,552 bytes；独立 tar.bz2 同 release SHA `4dae6fdcd2bb0bb6c37b5f97c33c2be954da743985369cddac3546e3218bffb8`。BSD-3-Clause 原完整许可证随原型和生成物分发。

源码按 Kong1.5.1 `kong/router.lua`（SHA `316d010942e82d069f719e505b96c2c9cca41c4ea6d7a3aaff773b30d8000c43`）执行：先以原 pattern 的 PCRE_ANCHORED 匹配索引，再以原 pattern 追加 `(?<uri_postfix>.*)` 执行最终 URI 规则。不能用 `^(?:pattern)` 包装；否则 inline flags、递归、引用与保留捕获名语义会改变。采用 8-bit、默认区分大小写、PCRE 默认 LF/BSR、无隐式 UTF/UCP flags；库支持 UTF/UCP 内部设施。禁用 JIT、启用 heap recursion，能力和预算显式返回。8.45 与目标 Kong 实际所链 PCRE 版本的差异必须由真实录制矩阵确认，不能只靠同属 PCRE1 就宣称逐位等价。

安全边界：

- 固定 helper 路径、零模式 argv、无 Shell；输入是有版本、长度的二进制帧，只经过 stdin，输出最多80字节。子进程环境仅 C locale，不继承平台密钥或凭证。
- 在读取输入或编译模式之前，独立进程设置 `no_new_privs`、禁 core dump、fd上限3、CPU1秒、地址空间64MiB、stack512KiB、原生 wall alarm200ms。seccomp仅允许fd0读、fd1写、退出、必要非可执行内存和时钟/随机数；文件、socket、exec、ptrace及其余调用默认杀进程。
- 每个原生匹配100,000步/递归256，最多64个模式、单模式2048 UTF8字节、subject8192字节；父进程250ms期限、4并发、输出精确帧/枚举验证。任何不可用、超限、非法响应均显式partial，禁止给出确定阴性或静默JS结果。
- 原型PCRE1为上游已停止维护的兼容组件；不装入API进程、无文件/网络能力。该隔离协议和生产镜像构建、CVE/SBOM评估仍须独审，不能以npm audit为其安全证据。

在 Linux x64/arm64 准备新输出目录（当前仅x64真实验证）：

```bash
node deploy/scripts/prepare-pcre1-engine.mjs
```

构建需要 `/usr/bin/cc` 与 libc/Linux headers。只下载固定官方 release、限制HTTPS跳转主机/大小/时间、验SHA，在内存读取tar仅挑固定源码，不执行tar/shell。输入可以用 `--archive-file=/absolute/verified/archive.tar.gz` 复用同SHA离线包；输出已有目录时拒绝覆盖。生成 `apps/console-api/native-bin/{kongpilot-pcre1,pcre1-build.json,PCRE-8.45-LICENCE.txt}`，API校验binary SHA后启动。生成物不得提交为未经校验的host binary。

**尚未做完的集成与真实验收：**

1. 为production Docker多阶段与CI显式增加编译器/固定源码准备、runtime helper/许可证COPY；当前原型未修改Dockerfile/CI，因此不能直接部署为完整功能。
2. 准备脚本的幂等验证/原子发布与并发安装负例、缺失/漂移binary的能力状态、生产read-only/distroless实际运行。
3. 对文件/socket/exec/ptrace等的真实seccomp负例，以及OOM/编译预算/独立wall/输出异常、并发与ARM64验收。
4. Root唯一实际Kong写者使用新隔离case建立真实1.5 regex routes，录制CRUD响应与代理命中、与BFF模拟逐项比较；包含 atomic、possessive、named backref、lookaround、condition、recursion、保留uri_postfix、负样本、regex priority/多path与raw percent URI。原型的native单测不是“真实Kong录制”。
5. 生产权限/旧模拟记录/实际proxy probe仍按原安全边界；完整M0–M11联合回归与更新正式用户手册。

已保留初次Source fixture/依赖设置失败和一次正样本返回unsupported：后者原始耗时527ms、原结果原因未在首次Vitest JSON留存；同模式直接真helper6.53ms匹配，添加诊断输出后的74/74通过。没有放宽运行期限或把首次失败改绿，商用前仍需观察负载下的诊断可用性。

Inherited descriptors and anonymous memory are fenced independently. Before input, the worker calls `close_range(3, UINT_MAX, 0)`, covering descriptors above a caller-lowered current NOFILE limit. Older kernels or an outer EPERM policy use a fixed read-only `/proc/self/fd` traversal (at most 64 batches / 4096 entries, actual EOF required) without allocating other descriptors during the traversal; unavailable procfs, malformed records or an excessive count exits closed. Its own directory descriptor is then closed. The 200 ms native wall timer starts before descriptor closure.

The mmap seccomp rule requires MAP_ANONYMOUS and forbids PROT_EXEC. The independent mprotect rule still forbids PROT_EXEC. Thus inherited fd0 or an unexpectedly inherited high fd cannot be used for file-backed mmap; memory allocation remains available to PCRE's bounded non-recursive heap allocator. Parent timeout, concurrency, memory, PCRE steps/recursion and all other syscall restrictions are retained.

Run the actual native sandbox regression with the fixed archive already in the build cache:

```sh
python3 tests/security/m9-pcre1-sandbox.test.py --archive /absolute/cache/pcre-8.45.tar.gz
```

It compiles the unmodified production C into bounded native probe processes and exercises real inherited fd4096 (also above a lowered hard NOFILE=64), the bounded fallback, excessive-descriptor refusal, file-backed mmap SIGSYS, anonymous allocation, executable mmap/mprotect and open/socket/execve/ptrace SIGSYS, plus actual PCRE matching and catastrophic match-limit behavior. The optional historical baseline argument is accepted only at the known pre-hardening source SHA and demonstrates that the original worker actually permitted file-backed stdin mmap; the baseline is not built or shipped as the production helper.


Production packaging and source CI now require the fixed native worker. The API Docker build installs gcc/libc development headers only in its build stage, runs the fixed builder, and copies only the helper/build manifest/BSD license to the existing Node22 distroless runtime. Local native-bin is excluded from git and Docker context. Production must retain the existing read-only root filesystem; the runtime image/ABI/seccomp/architecture check is an actual release gate, not implied by a host compile.

The source-quality runner adds a mandatory PCRE1 prerequisite before Vitest. Its wrapper obtains and SHA-verifies the official archive once, shares it with the production builder and standalone native security suite, and accepts only an actual 15/15, zero-skip native result. Native child groups have a 60s limit and 2 MiB per-output-stream bound; raw artifacts remain private. Missing/failed PCRE verification blocks the complete Vitest test stage. The six new preparation boundary cases and quality-runner negative cases do not replace real native, Docker or Kong-recorded comparisons. The host offline wrapper has been exercised with the actual pinned archive and actual native compiler; the genuine Node22 GitHub whole pipeline remains a separate pending gate.

The embedded PCRE1 component must appear explicitly as version 8.45 in the final image SBOM/license inventory; npm audit alone does not discover or clear it. PCRE1 is upstream end-of-life. Commercial review must assess this management-platform diagnostic component with its actual syscall/process budgets and final image scan, and retain the truthful engine/version/profile in the simulator. PCRE1 compatibility and a recorded Kong1.5 corpus are separate from asserting every Kong/OpenResty build has an identical linked PCRE patch version.
