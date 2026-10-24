# A4 actual02：真实 curl 首次正常启动，trace 保存容量停止

固定 System32 curl 在零能力 LPAC 中执行 `--disable --version`，正常输出固定版本内容并自然退出 0；普通前后版本正控均通过。原源提交为 `ebc2c6dac85975bf692abd08e76bd83d1d37947a`。私有导入内存序列、Config payload 只读读回、两份 `[2,0,0,2]` LPAC 身份证明与一次 Resume 均通过。

完整试次仍是 `inconclusive/trace`。固定 trace 为 557312 字节，保存时复用的旧 helper 上限为 524288 字节，在打开输出文件前报 `durable_bound`；所以本次没有 trace 原始文件，也没有执行 decoder。不能追补 trace 内容或据此授予完整启动机制资格；trace 后的第二次映像租约核验也未执行。

14 项限定清理谓词和 outer 清理均通过，`recovery_required=false`。前后四对象快照逐字节相同，均 8364 字节、SHA256 `8668bdf4b3802e415b53f95b88e322b804ef0f035463fdd5c5cad7e8f08ea4c3`。与前一试次之间的 DNS/路由变化另记为未归因，不改写旧基线。没有获得 HTTP、DNS、代理、恶意同 SID 边界、root 崩溃连续性或 Linux 等效验收。

本机与 [CI](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/40062122898) 均 1418 项通过；本机 2 项既有符号链接环境 skip，CI 0 skip，20 项固定 PE 方法两端均执行，CI 运行时步骤全部跳过。后续修复同时处理 trace 的精确尺寸写入，以及可达最大 trace 报告超过旧写入上限的问题；新试次另行记录。

[安全摘要](../../verification/windows-2026-10-22/lpac-curl-a4-loader-actual-02/summary.json) · [原始公报](../../verification/windows-2026-10-22/lpac-curl-a4-loader-local-02-public.json) · [原始预检](../../verification/windows-2026-10-22/lpac-curl-a4-loader-local-02-preflight.json) · [actual01 与独立恢复](2026-10-24-lpac-curl-a4-loader-01.md)。
