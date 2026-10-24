# Ordinary curl HTTP 字节校准 01（2026-10-24）

本次唯一一次实际调用完成两次普通身份的 System32 curl 正控，两次均自然退出 `0`。它确认固定 curl 能在受监督的进程与接收端中发送既定 HTTP 请求并读取响应正文。`selected_LPAC_tested`、`DNS_tested`、`proxy_tested`、`Linux_equivalence` 和产品验收均为 `false`；没有执行 selected LPAC HTTP，也没有获得应用完整隔离资格。

公开记录见 [summary.json](../../verification/windows-2026-10-22/curl-http-ordinary-calibration-01/summary.json)。两次均使用自有 `127.0.0.1` 临时 TCP 端口、HTTP/1.1、IPv4、显式禁用代理，无 DNS 名称；两次是独立普通正控，不是 selected 测试前后的成对资格证明。

| 文件核对项目 | case 0 | case 1 |
| --- | ---: | ---: |
| 实际接收请求：头 + 正文 | 128 + 8065 = 8193 字节 | 128 + 8065 = 8193 字节 |
| 接收端完成 `sendall`：头 + 正文 | 113 + 12176 = 12289 字节 | 113 + 12176 = 12289 字节 |
| curl stdout 正文逐字节一致 | 12176 字节 | 12176 字节 |
| curl stderr / stdin 文件 | 0 / 0 字节 | 0 / 0 字节 |
| 自然退出 / 超时 | 0 / false | 0 / false |
| 请求 EOF 后多余字节 | 0 | 0 |

POST 正文通过 `--data-binary @文件` 输入，stdin 为空。归档时直接读取私有 `received-request.bin`、`request-body.bin` 和 stdout，核对记录中的请求头、正文生成式、完整请求哈希以及响应正文生成式。请求原始字节已保存；完整响应线缆帧未另存，响应证据由接收端 `sendall` 完成路径、记录的响应头和 curl 实际 stdout 正文组成。各原始文件的长度与 SHA256 留在摘要中，原件保留私有。

原有 45 秒 QPC 总预算覆盖外层 worker Job 和两个内层 curl Job；每个接收端 work 截止为最多 8 秒，curl `--max-time` 为 6 秒。实际根调用总耗时约 4.391 秒。两次 work 都在原截止前完成；peer、listener 的独立关闭回执及接收线程 join 都在原总预算的清理预留内完成，没有续 work。listener 在 `thread.start()` 成功交接后由接收线程独占关闭。新目录只设置当前用户与 SYSTEM 的私有 ACL。

外层与两个内层启动记录均确认 Resume 前身份校验；两个 curl 还确认 Resume 前属于原外层 Job。三份记录中的 `process_exit_confirmed`、`job_empty`、`job_closed`、`handles_closed` 均为 true，清理错误为空，两个 socket 的 close/readback 均成功。原始三份记录的通用 `nested_resource_cleanup_incomplete` 仍为 **true**，摘要如实保留；这里报告上述已知资源的具体回执，不将该标记改写为 false，也不宣称普遍资源清理资格。

本轮 before/after 全局快照均为 8364 字节，SHA256 均为 `8668bdf4b3802e415b53f95b88e322b804ef0f035463fdd5c5cad7e8f08ea4c3`，字节相同。比较只涵盖 firewall profiles、DNS、routes、user proxy 四项，不含 NRPT。与更早基线比较时 DNS/routes 仍不同，不能将本轮相等解释为恢复历史全局配置。

实际校准入口按原字节归档为 [curl_http_calibration_root_01.py](../../verification/windows-2026-10-22/curl-http-ordinary-calibration-01/curl_http_calibration_root_01.py)：18778 字节，SHA256 `30a6393f5bccb66118490b7befe51959f3a3227e7b6fca1ba01675057919b4ed`。归档位置不是它原有的运行目录布局。含本机固定用户名的根 launcher 未归档。

[source-manifest.json](../../verification/windows-2026-10-22/curl-http-ordinary-calibration-01/source-manifest.json) 是 Ready03 的安全字段投影，绑定源提交 `0d024290b4f86a3aae042b8b2c5499687fc93928`、90 项 `source_hashes` 与 `source_sha256=c10559be677975f49baf7f2ddd21e9c370fc17eade2f7b05976f4356b6e7da7f`。原 freeze 为 30260 字节，SHA256 `c90fbbdbf75f3495c1c492d8a386a1bb4766d73da370cf1aa9cd0de13e9e96cf`；投影不是原 freeze 的 exact 副本。90 项仓库源文件均逐一核对哈希，未重复复制源码，也未从 Ready03 的状态字段推导本轮资格。

本轮归档只做文件读取、字节比较、哈希和脱敏检查，没有重新运行校准、项目代码、测试或原生 API。公开四文件不包含运行 nonce、端口、PID、用户 SID、用户目录绝对路径、私有原始报文或全局配置内容。
