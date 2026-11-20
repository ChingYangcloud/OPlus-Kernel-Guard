# 欧加 (OPPO / OnePlus) Android 15 GKI 6.6 内核监控、审计与网络深度包检测 (DPI) 驱动逆向与空壳化防御研究报告

> **声明：由于作者比较懒所以文案由美国大豆包整理。**


* **研究样本基线**：`vendor_modules.tar.gz` 中的 23 个监控、审计与网络 DPI 内核模块（`.modinfo` `vermagic`: `6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64`）及配套的 `oplus_kernel_guard_v3.0.0.zip` / `v3.0.1.zip` 空壳模块清单（`manifest.json`）。
* **核验原则**：本报告中的所有函数名、全局变量名、`/proc` 与 `/dev` 路径、Generic Netlink 家族名、`register_net_sysctl_sz` 目录名及 `ProtobufCFieldDescriptor` 字段名，均严格取自这 23 个 `.ko` 二进制文件的 `.symtab`、`.strtab`、`.rodata` 与 `.data` 节实测数据，剔除跨平台/跨版本开源代码的推断符号。

## 一、 23 个监控驱动危害分级总览（T0 极高危 ～ T3 低危）

基于对 23 个 `.ko` 二进制文件的 ELF 符号表（`.symtab`）、重定位表（`.rela.text` / `.rela.rodata`）、内核挂载点（Kprobe / Tracepoint / Netfilter）、`register_net_sysctl_sz` 表项以及 `protobuf-c` 上报描述符（`ProtobufCFieldDescriptor`）的交叉核实，首先明确**内核态与用户态的边界**：

* **内核模块真实上报给用户态或执行控制的范围**：涵盖**明文访问域名（`domain`）**、**DNS 劫持伪造应答并丢弃原包（`oplus_dns_hook_output_hook`）**、**DNS 服务器 IP（`dnsServer`）与响应时延/状态码（`latency, code`）**、**游戏主服务器与对战服务器 IPv4/IPv6 地址（`battleIp, gameUid, ipv6High, ipv6Low`）**、**发起请求的应用 `UID`**、**前台界面 `Activity` 名称（`activityName`）**、**32 款国内外特定 App 的 TLS SNI / QUIC SNI / HTTP 业务行为状态信号（`uid, levelType, dpiId, state`）**、**扫码与移动支付状态位（`qr order detect` / `qr pay detect`）**、**进程执行二进制完整路径（`execve_report`）**、**VFS 层文件读取完整路径（`d_path`）**、**提权前后凭据对比与 `SIGKILL` 强杀**，以及**强制销毁/关闭 Socket（`asyn_destroy_sk` / `destroy_sk_asyn` / `msc_close_sk_handler`）与向基带下发 MIPC 防火墙规则（`send_mipc_set_packet_fw_to_md`）**。
* **静态分析的边界说明**：上述 23 个内核 `.ko` 模块通过 Generic Netlink（`netlink_unicast`）、`/proc`、`/dev` 字符设备或内核日志将采集到的活动信号与元数据输出至本地特权守护进程。至于用户态守护进程拿到这些数据后是仅用于本地策略还是上传至远端服务器，仅凭内核 `.ko` 的静态分析无法判定，因此**凡向用户态输出应用活动信号、身份标识（UID/PID）、通信元数据或具备主动阻断能力的模块，均纳入 23 模块全量空壳化驻留范围**。

| 危害等级 | 模块数量 | 评级核心依据（严格对应二进制 `.symtab` 与调用图） | 涉及模块清单 | 空壳化防御策略（`v3.0.1` `hollow_23` 架构） |
| :--- | :--- | :--- | :--- | :--- |
| **🔴 T0 极高危**<br>*(明文域名上报 / DNS 伪造注入 / 32 款 App DPI / 主动强杀 / 动态探针)* | **6 个** | 直接向用户态上报**明文域名 (`domain`)**、在出站 UDP 53 钩子中**构造伪造 DNS 应答包注入本地协议栈并丢弃原包 (`oplus_dns_hook_output_hook`)**、上报**游戏对战服务器 IPv4/IPv6 (`battleIp, gameUid, ipv6High, ipv6Low`)**、针对 32 款特定 App 进行 **TLS SNI / QUIC SNI 深度包检测并上报活动信号 (`notify_dpi_result`)**、暴露 `/proc/kprobe_ctl` **任意内核函数动态 Hook 接口**、调用 `get_user_pages_remote` **跨进程读取用户态虚拟内存 (`access_process_vm_ubt`)**，或挂载 **21 个探针（13 `kretprobe` + 8 `kprobe`）主动发送 `SIGKILL` 强杀进程 (`oplus_root_killed`)** | `oplus_patch.ko`<br>`oplus_secure_guard_new.ko`<br>`oplus_network_dns_hook.ko`<br>`oplus_network_dns_cache.ko`<br>`oplus_network_data_module.ko`<br>`oplus_bsp_dfr_ubt.ko` | **全量空壳驻留（0 `rmmod`）**：保留 `/proc/kprobe_*`、Genl Family、导出符号与 **38 个** `/proc/sys/net/*` 目录，置空底层 Kprobe/Netfilter 钩子与上报出口 |
| **🟠 T1 高危**<br>*(细粒度行为画像 / 文件路径 / 扫码支付追踪 / 模块与系统调用表校验)* | **6 个** | 记录进程在 VFS 层读取的**每一个文件的完整路径 (`d_path`)**、嗅探微信/支付宝等**扫码订单与支付 (`qr order detect` / `qr pay detect`) 状态位**、关联前台 **`activityName`** 与 Socket 状态、挂载 `oplus_dns_data_output/input_hook` 上报 **DNS 服务器 IP (`dnsServer`)、解析时延 (`latency`) 与响应码 (`code`)**，或挂载 `load_module` 校验 `.ko` SHA-256 白名单并每小时巡检 `sys_call_table` 哈希 (`inte.ko` v0.16) | `oplus_bsp_file_read_record.ko`<br>`oplus_network_qr_scan.ko`<br>`oplus_network_sk_predict.ko`<br>`oplus_network_snapshot.ko`<br>`oplus_network_tcpdump_enhance.ko`<br>`inte.ko` | **全量空壳驻留（0 `rmmod`）**：保留 `/proc/oplus_mem/oplus_frr`、`/proc/inte_*`、Genl Family 与 **3 个** `/proc/sys/net/*` 目录，底层钩子返回无害绿灯信号 |
| **🟡 T2 中危**<br>*(应用活跃度画像 / Socket 强关与基带防火墙控制 / IPC 统计)* | **5 个** | 按应用 `UID`、`TGID/PID` 或 Binder 事务维度采集**长连接推送心跳周期、TCP 重传率、VIP 收包线程 ID**；其中 `linkpower_module` 还具备**拦截 DNS (`sk_pid_hook_dsc_block_dns`)、强制销毁/关闭 Socket (`asyn_destroy_sk` / `destroy_sk_asyn` / `msc_close_sk_handler`) 及通过 `send_mipc_set_packet_fw_to_md` 向 MTK 基带下发 MIPC 包过滤防火墙规则的主动控制能力** | `oplus_network_app_monitor.ko`<br>`oplus_network_vip_task.ko`<br>`oplus_network_linkpower_module.ko`<br>`oplus_bsp_midas.ko`<br>`oplus_sys_stability_helper.ko` | **全量空壳驻留（0 `rmmod`）**：保留 `/dev/midas_dev`、`/dev/binder_stats`、Genl `oplus_frk_nl` 及 **7 个** `/proc/sys/net/*` 目录，置空采集钩子与自定义 `proc_handler` |
| **🟢 T3 低危**<br>*(按 UID 流量与 RTT 统计 / 系统故障黑匣子 / 平台遥测)* | **6 个** | 按 `UID` 统计网卡流量（`add_iface_uid_stats`）与 RTT 评分（`oplus_score_calc_and_report`）、采集黑屏/亮屏故障事件（`SendTheiaKevent`）、在 `/proc/oplus_mem/sigkill_reason` 记录 `SIGKILL` 发送溯源，或通过联发科 MBrain 采集进程 `fork`/`exit`、Binder 事务与硬件功耗计数器 | `oplus_bsp_dfr_theia.ko`<br>`oplus_bsp_sigkill_diagnosis.ko`<br>`oplus_network_score.ko`<br>`oplus_network_stats_calc.ko`<br>`mtk_mbraink.ko`<br>`mtk_mbraink_v6991.ko` | **全量空壳驻留（0 `rmmod`）**：保留 `/dev/mbraink`、`/proc/oplus_mem/sigkill_reason`、Theia `/proc` 节点、Genl Family 及 **2 个** `/proc/sys/net/*` 目录 |

## 二、 23 个监控驱动逐项二进制核实详表（严格对齐 `.symtab` 与 `.rodata`）

下表所有模块大小、SHA-256、通信通道与函数符号均与 23 个 `.ko` 二进制文件逐一核对一致（`/proc/sys/net/*` 合计 `38 + 3 + 7 + 2 = 50` 个目录）：

| 危害分级 | 序号 | 模块文件名 (`.ko`) | 大小 (B) | 原厂 SHA-256 (前16位) | 暴露给用户态的真实壳层接口 (`genl` / `/proc/sys/net/` / `/proc` / `/dev`) | 经 `.symtab` 与 `.rodata` 核实的内核行为与关键函数符号 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **🔴 T0 极高危** | 01 | `oplus_patch.ko` | 31,912 | `75da2dc99f6d4c22` | `/proc/kprobe_ctl`<br>`/proc/kprobe_log` | **任意内核函数动态 Hook 接口**：通过 `ctl_write` 接收 `kprobe <sym>`、`kretprobe <sym>`、`enable_kprobe:<sym>`、`enable_all` 等指令调用 `hook_register` / `hook_enable`，并在 `handler_pre_first` / `handler_pre_second` 中调用 `log_add` 记录触发进程 `comm` 与 `pid` |
| **🔴 T0 极高危** | 02 | `oplus_secure_guard_new.ko` | 78,008 | `ac3a7e312ed6b949` | Genl: `secure_guard`<br>(`oplus_security_family` / `kevent_send_to_user`) | **21 个探针（13 `kretprobe` + 8 `kprobe`）提权强杀与执行上报**：<br>1. `oplus_exe_block_ret_handler` / `oplus_report_execveat_new`：监控 `/data/local/tmp` 与 `/data` 下程序执行，上报 `%d,path@@%s` 并对异常提权进程发送 `SIGKILL`<br>2. `uid_ret_handler` / `oplus_root_check_post_handler`：检测系统调用返回时凭据突变或 `get_fs()` 越界，调用 `oplus_root_check_succ` ➔ `oplus_root_killed` 发送 `SIGKILL`<br>3. `oplus_sepolicy_reload` / `oplus_heapspray_check`：监控非 `init` 重载 SELinux 策略与 `ip_setsockopt` / `cpuinfo_open` 堆喷射 |
| **🔴 T0 极高危** | 03 | `oplus_network_dns_hook.ko` | 33,208 | `a4659e0d70d2bfb6` | Genl: `oplus_dns_hook`<br>Sysctl: `/proc/sys/net/oplus_dns_hook` | **出站 DNS 拦截、伪造应答包注入与首次命中域名上报**：仅注册出站钩子 `oplus_dns_hook_output_hook` 与 Netlink 接收函数 `oplus_dns_hook_netlink_rcv_msg`（支持 `add url` / `update url` / `del url` / `clear url`）。命中规则时调用 `skb_copy_expand` ➔ `skb_store_bits` ➔ `ip_send_check` ➔ `csum_tcpudp_nofold` ➔ `ip_route_me_harder` / `ip6_route_me_harder` ➔ `ip_local_out` / `ip6_local_out` **直接构造伪造 DNS 响应包注入本地协议栈，并调用 `kfree_skb_reason` 丢弃原始出站查询包**；同时在 `s_first_notify` 开启时向 `s_user_pid` 单播上报域名（`send_first_dns_event %s`） |
| **🔴 T0 极高危** | 04 | `oplus_network_dns_cache.ko` | 26,952 | `3cbf3ee2d318f7d2` | 共享 Genl: `comm_netlink`<br>Sysctl: `/proc/sys/net/oplus_dns_cache` | **DNS 响应拆包与明文域名 Protobuf 上报**：挂载 Netfilter 钩子 `hfunc` 并在 `parse_lib` 中解析 DNS 报文，通过 `report_nas` 与定时器 `dns_report_timeout_fun` 调用 `notify_netlink_event` 上报 `notify_dns_meta_data`（含 **`uid`、`domain` 明文域名、`ttl`**） |
| **🔴 T0 极高危** | 05 | `oplus_network_data_module.ko` | 1,341,544 | `b2cd7c8bbbbd1120` | Genl: `comm_netlink`<br>Sysctl: **`/proc/sys/net/` 下共 36 个目录**（16 个顶级目录 + 20 个 `net/oplus_dpi/*` 子目录） | **32 款特定 App 内核态 DPI 引擎与 25 类 Protobuf 消息中枢**：挂载 `dpi_output_hook_v4/v6`、`dpi_input_hook_v4/v6`、`oplus_game_data_input_hook`、`game_main_stream_nf_output_hook_func`、`wifi_accelerate_output/postrouting_hook`，通过 `tls_sni_match`、`gquic_sni_match`、`http_request_match` 识别 32 款 App 流量，调用 `notify_dpi_result` 上报 `(uid, levelType, dpiId, state)`，并在 `notify_game_main_stream_ip_message` 中上报 **`(battleIp, gameUid, ipv6High, ipv6Low)`** |
| **🔴 T0 极高危** | 06 | `oplus_bsp_dfr_ubt.ko` | 23,472 | `6a674fa486051367` | Platform Driver: `userspace_backtrace`<br>（无 `/proc` 或 `/dev` 节点，输出走 `_printk_deferred`） | **跨进程用户态虚拟内存回溯读取**：注册 platform driver `userspace_backtrace_driver` 并挂载 `__tracepoint_android_vh_sysrq_crash`（回调 `userspace_backtrace_systrigger`），在 `dump_userspace_backtrace` 中调用 `access_process_vm_ubt`（内部使用 `get_user_pages_remote`）跨进程读取用户态进程栈与内存映射信息 |
| **🟠 T1 高危** | 07 | `oplus_bsp_file_read_record.ko` | 29,176 | `4422c07f9cd3adad` | `/proc/oplus_mem/oplus_frr`<br>(`oplus_frr_read` / `oplus_frr_write`) | **VFS 层文件读取全路径监控**：挂载 `trace_android_vh_filemap_read_hook`、`trace_android_vh_filemap_map_pages_hook`、`trace_android_vh_do_read_fault_hook` 3 个 tracepoint，在 `io_monitor_record` 中调用 `d_path()` 记录目标进程读取的每一个文件完整路径、Inode 与页偏移 |
| **🟠 T1 高危** | 08 | `oplus_network_qr_scan.ko` | 29,336 | `87c6a579d24b6640` | Genl: `qr_scan`<br>(`qr_monitor_genl_family`) | **扫码订单与扫码支付状态位嗅探**：挂载 `oplus_filter_qr_v4_send_skb`、`oplus_filter_qr_v6_send_skb`、`oplus_filter_qr_v4_receive_skb`、`oplus_filter_qr_v6_receive_skb`，匹配目标应用 `s_package_uid` 的 TCP SYN（`v4 syn match` / `v6 syn match`）及 `"200 OK"` / `"pay"` 特征，通过 `oplus_qr_hooks_send_to_user` 上报 **`qr order detect`、`qr order post success`、`qr pay detect`、`qr pay post success`** 事件 |
| **🟠 T1 高危** | 09 | `oplus_network_sk_predict.ko` | 25,296 | `83c0feed1d6d5433` | 共享 Genl: `comm_netlink`<br>Sysctl: `/proc/sys/net/oplus_sk_predict` | **前台 Activity 与 Socket 行为关联**：通过 `set_sk_predict_activity_info` 接收用户态下发的 `(isSet, uid, dpiId, activityName)`，挂载 `handler_sys_socket`、`handler_sys_socket_exit`、`handler_inet_release` 探针，调用 `notify_sk_predict_result` 上报 `(uid, dpiId, state)` |
| **🟠 T1 高危** | 10 | `oplus_network_snapshot.ko` | 55,800 | `981dd6a7367e739d` | 共享 Genl: `comm_netlink`<br>Sysctl: `/proc/sys/net/oplus_snapshot`<br>`/proc/sys/net/oplus_dnsdata_hook` | **DNS 服务器 IP/时延/RCODE 与按 UID 流量快照上报**：<br>1. `oplus_dnsdata_hook_init` 注册 `oplus_dns_data_output_hook` 与 `oplus_dns_data_input_hook`，通过 `report_dns_data` / `dns_query_timeout` 上报 `dns_normal_data`（**`uid, isRecursion, dnsServer, latency, index, code`**，共 6 个整数字段，不含域名）<br>2. `network_stat_output_hook` / `network_stat_input_hook` ➔ `hook_fun` 采集流量并在 `snapshot_report_timer_function` 中按网卡与 `uid` 上报 12 项吞吐率与 RTT 快照 |
| **🟠 T1 高危** | 11 | `oplus_network_tcpdump_enhance.ko` | 29,888 | `e187f2d1c4cd7c24` | Genl: `tcpdump_netlink`<br>& `comm_netlink` (`comm_netlink_inform_msg`) | **出站异常套接字哈希记录与抓包触发器**：符号表仅注册出站钩子 `tcpdump_output_hook_v4` 与 `tcpdump_output_hook_v6`，在 `tcpdump_handle_record` 中计算套接字 `crc32_be` 存入 `s_record_socket_map`，并通过内部 `notify_netlink_event` 单播给用户态抓包守护进程 |
| **🟠 T1 高危** | 12 | `inte.ko` | 51,320 | `485f4520648576d8` | `/proc/inte_ko`<br>`/proc/inte_systbl`<br>`/proc/inte_status` | **内核模块 SHA-256 白名单与系统调用表每小时哈希巡检（v0.16）**：挂载 `load_module` `kretprobe`（`hash_probe_entry`）与 `getname_kp`，计算加载 `.ko` 的 SHA-256 并通过 `check_ko_exist_in_hash_tbl` 比对由 `oplus_kohashpro` 写入（`proc_write_ko`）的 `inte_hash_table`，异常时调用 `add_ko_event` 写入 `/proc/inte_ko`（`ko_proc_show`）；同时启动周期为 1 小时（`interval 1H`）的延迟工作队列 `check_task` 调用 `do_hash` 校验 `sys_call_table` 哈希，异常时调用 `add_systbl_event` 写入 `/proc/inte_systbl`（`systbl_proc_show`） |
| **🟡 T2 中危** | 13 | `oplus_network_app_monitor.ko` | 61,112 | `4dc295ffde5cea26` | Genl: `app_monitor`<br>Sysctl: `/proc/sys/net/oplus_apps_monitor`<br>`/proc/sys/net/oplus_app_power_monitor` | **单应用长连接心跳、重传与功耗告警监控**：挂载 `oplus_apps_monitor_postrouting_hook4/6` 与 `oplus_apps_monitor_input_hook4/6`，通过 `apps_monitor_report_apps_rtt_to_user`、`oplus_app_monitor_send_app_info_report`、`oplus_app_monitor_send_beat_alarm`、`oplus_app_monitor_send_push_alarm`、`oplus_app_monitor_send_traffic_alarm` 上报 Top 心跳/推送/流量/重传应用，并在 `/proc/sys/net/oplus_app_power_monitor` 上绑定 4 个自定义 `proc_handler` |
| **🟡 T2 中危** | 14 | `oplus_network_vip_task.ko` | 42,568 | `cde9d9672e38678b` | 共享 Genl: `comm_netlink`<br>Sysctl: `/proc/sys/net/oplus_vip_task` | **关键业务流收包线程追踪**：挂载 `kprobe_oplus_vip_task_recvmsg_hook`、`kprobe_oplus_vip_task_timeinfo_hook`、`kretprobe_oplus_vip_task_timeinfo_hook` 及入站 Netfilter 钩子 `oplus_rx_thread_info_input_hook`（无 output 钩子），通过 `report_vip_task_data` 与 `report_vip_task_record_data` 上报 `(dpi_id, tgid, pid)` 与收包耗时分布 |
| **🟡 T2 中危** | 15 | `oplus_network_linkpower_module.ko` | 425,744 | `bd3c824341abe93d` | Genl: `linkpower_netlink` & `comm_netlink`<br>Sysctl: `/proc/sys/net/oplus_asc`<br>`/proc/sys/net/oplus_mdfw`<br>`/proc/sys/net/media_stream_control`<br>`/proc/sys/net/sparse_packet_identify` | **网络唤醒监控、DNS 阻断、Socket 强制销毁与基带防火墙下发**：包含 9 个子模块，除挂载 `handler_tcp_connect`、`handler_udp_connect`、`handler_unix_stream_connect_entry/ret`、`handler_pm_system_irq_wakeup`、`handler_ccif_rx_collect` 采集唤醒源外，还可通过 `sk_pid_hook_dsc_block_dns` 阻断 DNS、通过 `asyn_destroy_sk` / `destroy_sk_asyn` / `msc_close_sk_handler` 强制关闭 Socket，以及通过 `proc_add_mdfw` / `send_mipc_set_packet_fw_to_md` 向 MTK 基带下发包过滤防火墙规则 |
| **🟡 T2 中危** | 16 | `oplus_bsp_midas.ko` | 62,200 | `f9f33dad957d07e2` | `/dev/midas_dev`<br>`/dev/binder_stats`<br>Platform Device: `midas-pdev`（无 `/proc` 节点） | **Binder 跨进程通信统计与 CPU 功耗记账**：挂载 `binder_proc_transaction_hook`、`binder_new_ref_hool`、`binder_del_ref_hook` 与 `midas_record_task_times`（挂载于 `cpufreq_acct_update_power`），以及休眠唤醒回调 `rasm_suspend` / `rasm_resume`，通过 `/dev/midas_dev` 与 `/dev/binder_stats` 的 `ioctl`/`mmap` 供用户态读取 |
| **🟡 T2 中危** | 17 | `oplus_sys_stability_helper.ko` | 50,832 | `12c01790dcba8bec` | Genl: `oplus_frk_nl` (`oplus_frk_genl_family` / `send_to_frk` / `recv_from_frk`)（无 `/proc` 节点） | **系统服务挂起、进程派生、信号发送与低内存监控**：挂载 `copy_process`（`thread_watcher`）、`binder_proc_transaction_finish`（`pending_transaction_watcher`）、`binder_alloc_new_buf_locked`（`binder_buffer_watcher`）、`do_send_sig_info`（`send_signal_catcher`）与 `mm_vmscan_direct_reclaim_begin`（`lowmem_report`），通过 `send_to_frk` 经 Generic Netlink 上报给框架层 |
| **🟢 T3 低危** | 18 | `oplus_bsp_dfr_theia.ko` | 101,664 | `cfc93ecef0570981` | Genl: `theia_kevent`<br>`/proc/theiaPwkReport`<br>`/proc/blackSwitch`<br>`/proc/brightSwitch` | **黑屏/亮屏卡死故障遥测 (Theia DCS)**：注册 MTK 显示通知链 `black_fb_notifier_callback` / `bright_fb_notifier_callback`，异常时通过 `send_black_screen_dcs_msg`、`SendTheiaKevent`、`SendDcsTheiaKevent`、`theia_send_event`、`theia_send_event_atomic` 向 `theia_kevent_pid` 发送事件 |
| **🟢 T3 低危** | 19 | `oplus_bsp_sigkill_diagnosis.ko` | 16,480 | `927020ff6d1d6253` | `/proc/oplus_mem/sigkill_reason` | **进程强杀信号溯源**：挂载 `__tracepoint_android_vh_do_send_sig_info`（回调 `record_sigkill_reason`），在 `/proc/oplus_mem/sigkill_reason`（读取函数 `sigkill_reason_read`）按 `%u,%u,%u,%u\n` 格式输出信号发送方与接收方记录 |
| **🟢 T3 低危** | 20 | `oplus_network_score.ko` | 66,848 | `bee8bf6e213f0085` | Genl: `oplus_score`<br>Sysctl: `/proc/sys/net/oplus_score` | **按 UID 应用网络质量评分上报**：挂载 `oplus_score_postrouting_hook4/6` 与 `oplus_score_input_hook4/6`（调用 `get_skb_dpi_id`），在 `oplus_score_calc_and_report` 中计算评分并通过 `oplus_score_send_netlink_msg` 单播给 `oplus_score_user_pid` |
| **🟢 T3 低危** | 21 | `oplus_network_stats_calc.ko` | 24,768 | `d5c186b52d458cb9` | Genl: `stats_calc`<br>Sysctl: `/proc/sys/net/oplus_stats_calc` | **按网卡与 UID 套接字流量聚合计算**：挂载 `oplus_stats_calc_input_hook` 与 `oplus_stats_calc_output_hook`，调用 `add_iface_uid_stats` 累加哈希表 `s_iface_uid_stats_map`，并通过 `send_netlink_data` 向 `s_user_pid` 单播上报 |
| **🟢 T3 低危** | 22 | `mtk_mbraink.ko` | 159,344 | `37313b83833c2d4e` | `/dev/mbraink` (`mbraink_ioctl`) & Netlink (`mbraink_netlink_send_msg`) | **联发科 MBrain 内核遥测底座**：在 `mbraink_process_tracer_init` 中通过 `for_each_kernel_tracepoint` 挂载 `mbraink_sched_process_fork`、`mbraink_sched_process_exit`、`mbraink_binder_transaction`、`mbraink_trace_android_vh_cpufreq_acct_update_power`，并通过 `mbraink_netlink_send_msg` 与 `mbraink_ioctl` 向用户态输出 |
| **🟢 T3 低危** | 23 | `mtk_mbraink_v6991.ko` | 111,392 | `2862b7dde8a39e0d` | 依赖 `mtk_mbraink.ko` 导出的回调注册接口 | **天玑 9400 (MT6991) MBrain 平台采集器**：实现 `ufs2mbrain_event_notify`、`fpsgo2mbrain_hint_frameinfo`、`fpsgo2mbrain_hint_perfinfo`、`gpu2mbrain_hint_fenceTimeoutNotify`、`update_mbraink_sys_res_record` 等硬件计数器回调 |

## 三、 `oplus_network_data_module.ko` 25 类 Protobuf 消息总线与 4 个共享通道子模块逆向

通过对 `oplus_network_data_module.ko` 的 `.rodata` 与 `.rela.rodata` 重定位表（解析 `netlink__proto__notify_message__field_descriptors` 的 25 个 `ProtobufCFieldDescriptor` 条目）进行逆向，证实 `oplus_network_data_module.ko` 导出了 `notify_netlink_event`、`register_netlink_request`、`register_netlink_inform` 与全部 `netlink__proto__*__descriptor` 符号，作为 **25 类 `notify_message` 上报消息的共享 Protobuf 通信总线（`comm_genl_family`）**：

### 3.1 `oplus_network_data_module.ko` 的 `.symtab` 实存上报描述符与钩子函数

在 `oplus_network_data_module.ko` 的 `.symtab` 中，所有上行 `notify_*` 消息描述符均以 `netlink__proto__notify_<name>__descriptor` 形式存在（**注：本固件全部 23 个 `.ko` 中均不存在 `voip` 相关符号或钩子，此前报告中的 `oplus_voip_nf_hook` / `notify_voip_voice_uid` 系误植，已彻底剔除**）：

* **游戏主服务器与王者荣耀服务器 IPv4/IPv6 上报**：
  * `game_main_stream_monitor_init` 注册出站钩子 **`game_main_stream_nf_output_hook_func`**（`.text+0x25b18`），匹配游戏流量后调用 **`notify_game_main_stream_ip_message`**（`.text+0x25ec8`），使用 `netlink__proto__notify_game_main_server_ip__descriptor` 上报 **`battleIp`、`gameUid`、`ipv6High`、`ipv6Low`** 4 个字段。
  * `tmgp_sgame_init` 注册 `wzry_request_get_server_ip` 响应函数与 `netlink__proto__notify_wzry_server_ip__descriptor`，上报 **`battleIp`** 1 个字段。
* **游戏延迟统计钩子与 `net/oplus_game` sysctl**：
  * `oplus_game_data_hook_init`（`.text+0x24e14`）注册入站钩子 **`oplus_game_data_input_hook`**（`.text+0x25334`）、延迟工作队列回调 **`work_func`**（`.text+0x25570`）、两个 Netlink 请求回调（`set_game_report_enable`、`set_game_latency`）以及 **`/proc/sys/net/oplus_game`** sysctl 目录，使用 `netlink__proto__notify_game_data__descriptor` 上报游戏包延迟数据。
* **32 款 App 深度包检测（DPI）活动信号上报**：
  * `dpi_init` 注册 `dpi_output_hook_v4`、`dpi_input_hook_v4`、`dpi_output_hook_v6`、`dpi_input_hook_v6`，调用 `dpi_handle_match` ➔ `tls_sni_match` / `gquic_sni_match` / `http_request_match` / `http_request_global_match`，命中后通过 **`notify_dpi_result`**（`.text+0xc1d8`）打包 `netlink__proto__notify_dpi_result__descriptor`（含 `uid, levelType, dpiId, state`）并调用 `notify_netlink_event`（`.text+0x12ac`）➔ `send_one_msg`（`.text+0x1364`）单播给用户态。

### 3.2 共享 `comm_netlink` 通道的 4 个外部子模块实存符号与 `.proto` 结构

1. **`oplus_network_dns_cache.ko`（T0 极高危）**：
   * **实存函数符号**：`hfunc`（Netfilter 钩子）、`parse_lib`（DNS 拆包）、`report_nas`（立即上报）、`dns_report_timeout_fun`（定时上报）、`set_dns_cache_enable`。
   * **导入 Protobuf 描述符**：`netlink__proto__dns_meta_data__init`、`netlink__proto__notify_dns_meta_data__descriptor`，上报字段为 **`uid`（字段 1）、`domain`（字段 2，明文域名字符串）、`ttl`（字段 3）**。
2. **`oplus_network_snapshot.ko`（T1 高危）**：
   * **实存函数符号**：
     * DNS 子模块（`oplus_dnsdata_hook_init`）：挂载 **`oplus_dns_data_output_hook`** 与 **`oplus_dns_data_input_hook`**，通过 **`report_dns_data`** 与 **`dns_query_timeout`** 调用 `netlink__proto__dns_normal_data__init` / `netlink__proto__notify_dns_normal_data__descriptor` 上报 **`uid, isRecursion, dnsServer, latency, index, code`**。
     * 快照子模块（`init_module`）：挂载 **`network_stat_output_hook`** 与 **`network_stat_input_hook`**（内部均调用 **`hook_fun`**），通过定时器 **`snapshot_report_timer_function`** 打包 `netlink__proto__notify_network_snapshot__descriptor` 上报按网卡与 `uid` 的吞吐量和 RTT。
3. **`oplus_network_sk_predict.ko`（T1 高危）**：
   * **实存函数符号**：`set_sk_predict_activity_info`、`handler_sys_socket`、`handler_sys_socket_exit`、`handler_inet_release`、`add_tracked_sock`、`notify_sk_predict_result`。
4. **`oplus_network_vip_task.ko`（T2 中危）**：
   * **实存函数符号**：`kprobe_oplus_vip_task_recvmsg_hook`、`kprobe_oplus_vip_task_timeinfo_hook`、`kretprobe_oplus_vip_task_timeinfo_hook`、`oplus_rx_thread_info_input_hook`、`report_vip_task_data_work_handler`、`report_vip_task_data`、`report_vip_task_record_data`。

## 四、 核心高危模块二进制行为精析（严格基于 `.symtab`、`.rodata` 与重定位调用图）

### 4.1 `oplus_secure_guard_new.ko`：13 个 `kretprobe` + 8 个 `kprobe`（共 21 个探针）

在 `oplus_secure_guard_new.ko` 的 `.symtab` 与 `.data` 节中，实际定义了 **13 个 `struct kretprobe` 对象**与 **8 个 `struct kprobe` 对象**，合计 **21 个内核探针**（由 `oplus_harden_init` 统一注册，并在注册成功后将 `.bss` 中的 `oplus_harden_init_succeed` 置为 `1`）：

* **13 个 `kretprobe` 对象（名称均取自 `.symtab`）**：
  1. `sepolicy_reload_kretprobe`（目标符号 `func_name_sepolicy_reload`: `"sel_write_load"`，入口 `entry_handler_sepolicy_reload`，返回 `oplus_sepolicy_reload`）
  2. `socket_kretprobe`（目标符号 `func_name_socket`: `"ip_setsockopt"`，入口 `entry_handler_socket`，返回 `oplus_heapspray_check`）
  3. `socket_ip6_kretprobe`（目标符号 `func_name_socket_ip6`: `"do_ipv6_setsockopt"`，入口 `entry_handler_socket_ip6`，返回 `oplus_heapspray_check`）
  4. `cpuinfo_kretprobe`（目标符号 `func_name_cpu_info`: `"cpuinfo_open"`，入口 `entry_handler_cpuinfo`，返回 `oplus_heapspray_check`）
  5. `do_execveat_common_kretprobe`（目标符号 `func_name_execve`: `"do_execveat_common"`，入口 `do_execveat_common_entry_handler`，返回 `oplus_exe_block_ret_handler`）
  6. `capset_kretprobe`（目标符号 `func_name_capset`: `"cap_capset"`，入口 `uid_entry_handler`，返回 `uid_ret_handler`）
  7. `futex_kretprobe`（目标符号 `func_name_futex`: `"__arm64_sys_futex"`，入口 `uid_entry_handler`，返回 `uid_ret_handler`）
  8. `ppoll_kretprobe`（目标符号 `func_name_ppoll`: `"__arm64_sys_ppoll"`，入口 `uid_entry_handler`，返回 `uid_ret_handler`）
  9. `epoll_pwait_kretprobe`（目标符号 `func_name_epoll_pwait`: `"__arm64_sys_epoll_pwait"`，入口 `uid_entry_handler`，返回 `uid_ret_handler`）
  10. `ioctl_kretprobe`（目标符号 `func_name_ioctl`: `"__arm64_sys_ioctl"`，入口 `uid_entry_handler`，返回 `uid_ret_handler`）
  11. `rt_tgsigqueueinfo_kretprobe`（目标符号 `func_name_rt_tgsigqueueinfo`: `"__arm64_sys_rt_tgsigqueueinfo"`，入口 `uid_entry_handler`，返回 `uid_ret_handler`）
  12. `nanosleep_kretprobe`（目标符号 `func_name_nanosleep`: `"__arm64_sys_nanosleep"`，入口 `uid_entry_handler`，返回 `uid_ret_handler`）
  13. `sigtimedwait_kretprobe`（目标符号 `func_name_sigtimedwait`: `"__arm64_sys_rt_sigtimedwait"`，入口 `uid_entry_handler`，返回 `uid_ret_handler`）
* **8 个 `kprobe` 对象（共用 `handler_pre` ➔ `oplus_harden_pre_handler`）**：
  14. `kp_setregid`（`func_name_setregid`: `"__sys_setregid"`）
  15. `kp_setgid`（`func_name_setgid`: `"__sys_setgid"`）
  16. `kp_setreuid`（`func_name_setreuid`: `"__sys_setreuid"`）
  17. `kp_setesuid`（`func_name_setuid`: `"__sys_setuid"`）
  18. `kp_setresuid`（`func_name_setresuid`: `"__sys_setresuid"`）
  19. `kp_setresgid`（`func_name_setresgid`: `"__sys_setresgid"`）
  20. `kp_setfsuid`（`func_name_setfsuid`: `"__sys_setfsuid"`）
  21. `kp_setfsgid`（`func_name_setfsgid`: `"__sys_setfsgid"`）

### 4.2 `oplus_network_dns_hook.ko`：出站 DNS 劫持伪造应答与丢包调用链

通过对 `oplus_network_dns_hook.ko` 的 `.rela.text` 与 `.rodata.str1.1` 进行核实，该模块在 `.symtab` 中仅包含 4 个函数：`init_module`、`cleanup_module`、`oplus_dns_hook_netlink_rcv_msg`（`.text+0x4`）与 `oplus_dns_hook_output_hook`（`.text+0x474`，长 3,476 字节）：

* **用户态规则下发（`oplus_dns_hook_netlink_rcv_msg`）**：接收用户态 PID（`[%s]:set s_user_pid=%u`）、开关状态（`[%s]:set enable value %d`）以及域名劫持表 `s_hook_addrs` 的增删改清指令（日志字符串：`add url %s %u`、`update url %s %u`、`del url %s %u`、`clear url %s %u`）。
* **出站劫持与伪造包注入调用链（`oplus_dns_hook_output_hook`）**：
  1. 拦截出站 DNS 查询报文并解析查询域名（`[%s]:hook %d parse_querys match %d-%d-%s-%u`）。
  2. 若命中 `s_hook_addrs` 且 `s_first_notify` 开启，调用 `__alloc_skb` ➔ `genlmsg_put` ➔ `nla_put` ➔ `netlink_unicast` 向 `s_user_pid` 发送首次命中通知（`[%s]:send_first_dns_event %s`）。
  3. 紧接着调用 `skb_copy_expand` 分配并扩展新 `sk_buff`（`[%s]:skb_copy_expand failed! size: %u`），调用 `skb_copy_bits` 与 `skb_store_bits` 写入伪造的 DNS 响应载荷与对调后的 IP/UDP 头（`[%s]:skb_store_bits 1 failed!` / `skb_store_bits 2 failed!`）。
  4. 调用 `ip_send_check`、`csum_tcpudp_nofold`、`__skb_checksum_complete` 重算校验和，调用 `nf_ct_attach` 关联连接跟踪，并通过 `ip_route_me_harder` / `ip6_route_me_harder` 与 `ip_local_out` / `ip6_local_out` 将伪造的 DNS 应答包注入协议栈（`[%s]:skb_output return package! match_count %d`），最后调用 `kfree_skb_reason` 释放原包。

### 4.3 `inte.ko`（版本 `0.16`）：二进制实存功能边界

本固件中的 `inte.ko`（日志标识 `[KERNEL_SECURITY_CHECK]:init success! , version :0.16`）仅包含以下两项实存校验逻辑（**不含 OnePlusOSS 后续版本中的 SELinux 状态、挂载权限或 `pacibsp` 首指令检查**）：

1. **模块加载 SHA-256 白名单校验（`hash_probe_entry`）**：挂载 `load_module` 的 `kretprobe`（`hash_probe`）与 `ko_integrity_init.getname_kp`，使用 `crypto_alloc_shash("sha256")` 计算新加载 `.ko` 的哈希，并通过 `check_ko_exist_in_hash_tbl` 比对白名单哈希表 `inte_hash_table`。若未命中（`ko:[%s] hash not found, maybe unknown ko.`）或哈希不符（`ko:[%s] hash diff, maybe modified ko.`），则调用 `add_ko_event` 加入 `ko_events_list` 供 `/proc/inte_ko`（`ko_proc_show`）读取。用户态进程写入 `/proc/inte_ko`（`proc_write_ko`）时会校验进程名 `oplus_kohashpro`（`Invalid process: %s (expected: %s)`）与 `euid`（`[KO_INTEGRITY_VERI):Invalid user, euid : [%u]`）。
2. **系统调用表每小时哈希巡检（`check_task`）**：初始化时查找 `sys_call_table` 并调用 `do_hash` 计算基线哈希 `hash_syscall_table`，随后启动间隔为 **1 小时**（`set DELAYED_WORK succeed. (interval 1H)`）的延迟工作队列 `check_work`（回调函数 **`check_task`**），每小时执行 `Performing hourly check...` 重新计算 `sys_call_table` 哈希，若不一致（`syscall_tbl maybe modified.`）则调用 `add_systbl_event` 写入 `/proc/inte_systbl`（`systbl_proc_show`）。

## 五、 全量 23 模块空壳化补丁规格（严格对齐 `.symtab` 与 `v3.0.1` `manifest.json`）

### 5.1 对 `v3.0.0` 到 `v3.0.1` 补强演进的二进制审计结论

通过对 `oplus_kernel_guard_v3.0.0.zip` 与 `oplus_kernel_guard_v3.0.1.zip` 进行逐字节对比审计：
* **`v3.0.0` 基线**：共修补了 **224 个函数实例**（去重后为 **209 个唯一符号名**，其中 `oplus_network_linkpower_module.ko` 占 51 处实例 / 36 个唯一名），全部 100% 真实存在于 23 个 `.ko` 的 `.symtab` 中。
* **`v3.0.1` 完成的两项核心补强（总计修补 233 个函数实例）**：
  * **补强 1（恢复 `oplus_network_data_module.ko` 的 `net/oplus_game` sysctl 与 Netlink 请求注册）**：`v3.0.0` 曾置空 **`oplus_game_data_hook_init`**（`.text+0x24e14`）与 **`game_main_stream_monitor_init`**（`.text+0x257a8`），导致 `register_net_sysctl_sz("net/oplus_game")`、`nf_register_net_hooks` 及 2 次 `register_netlink_request`（`set_game_report_enable`、`set_game_latency`）未能执行，用户态访问时会收到“未注册”反馈。`v3.0.1` 已将这两个 `*_init` 恢复为原厂指令，改为置空底层 4 个实际钩子与上报函数：**`oplus_game_data_input_hook`**（`.text+0x25334`，`bti c; mov w0, #1; ret` 并清零 `+0x0`/`+0x4` 两条重定位）、**`work_func`**（`.text+0x25570`，返回 `0`）、**`game_main_stream_nf_output_hook_func`**（`.text+0x25b18`，`bti c; mov w0, #1; ret`）以及 **`notify_game_main_stream_ip_message`**（`.text+0x25ec8`，返回 `0`）。
  * **补强 2（置空 7 个自定义 sysctl `proc_handler` 写回调）**：`v3.0.1` 将绑定在 `.data` 段 sysctl 表上的 7 个自定义 `proc_handler`（`linkpower_module` 2 个、`app_monitor` 4 个、`score` 1 个）全部补丁为标准 `pacibsp` 返回 `0` 序列。

### 5.2 10 个包含 `/proc/sys/net/*` 接口模块的完整壳层与 `.symtab` 真实补丁函数表

| 模块名称 (`.ko`) | 必须保留的 `/proc/sys/net/` 目录（共 50 个） | 绑定在 sysctl 上的自定义 `proc_handler`（均以 `pacibsp` 开头，置空返回 `0`） | `.symtab` 实存钩子与上报函数补丁规格（`v3.0.1` 已全部验证通过） |
| :--- | :--- | :--- | :--- |
| `oplus_network_linkpower_module.ko` | `net/oplus_asc`<br>`net/oplus_mdfw`<br>`net/media_stream_control`<br>`net/sparse_packet_identify` | **`proc_add_mdfw`** (`.text+0x1c134`)<br>**`proc_remove_mdfw`** (`.text+0x1c32c`) | **返回 `NF_ACCEPT (1)` 的 Netfilter 钩子**：`asc_input_hook_v4`、`asc_output_hook_v4`、`asc_output_hook_v6`、`asi_local_output_hook_v4`、4 组同名静态 `my_input_hook_v4/v6` 与 `my_output_hook_v4/v6`、`my_output_hook`、`spi_input_hook_v4/v6`、`spi_output_hook_v4/v6`、`hba_input_hook_v4/v6`、`hba_output_hook_v4/v6`、`hba_input_hook`、`hba_output_hook`<br>**返回 `0` 的控制/Kprobe/上报函数**：`send_msg_to_user`（2 处静态同名函数）、`asyn_destroy_sk`、`msc_close_sk_handler`、`hbi_identified_asyn`、`hbi_closed_asyn`、`netlink_send_to_user`、`sk_pid_hook_dsc_block_dns`、`destroy_sk_asyn`、`handler_tcp_connect`、`handler_udp_connect`、`handler_unix_stream_connect_ret`、`handler_unix_stream_connect_entry`、`push_sk_detected_asyn`、`push_sk_destroyed_asyn`、`send_spi_msg_to_uplayer_async`、`enable_firewall`、`send_msg_to_hba_user` + **`proc_add_mdfw`**、**`proc_remove_mdfw`**（共 53 处函数实例） |
| `oplus_network_data_module.ko` | **16 个顶级目录**：`net/oplus_dpi`、`net/oplus_game`、`net/baidu_netdisk`、`net/douyin`、`net/douyin_lite`、`net/kuaishou`、`net/kuaishou_lite`、`net/line`、`net/party`、`net/pubg`、`net/pubg_newstate`、`net/sgame_global`、`net/tiktok`、`net/tmgp_cf`、`net/whatsapp`、`net/youtube`<br>**20 个 `net/oplus_dpi/` 子目录**：`bilibili`、`cnpubg`、`codm`、`ea_fc_mobile`、`efootball`、`facebook`、`freefire`、`freefiremax`、`garena_rov`、`genshin`、`imo`、`instagram`、`jkchess`、`log_stream`、`messenger`、`mlbb`、`moj`、`teams`、`telegram`、`xhs` | 无（全部使用内核标准 `proc_dointvec`） | **保留全部 `*_init` 函数（含 `oplus_game_data_hook_init` 与 `game_main_stream_monitor_init`）不打补丁**；<br>**返回 `NF_ACCEPT (1)` 的 Netfilter 钩子**：`dpi_output_hook_v4`、`dpi_input_hook_v4`、`dpi_output_hook_v6`、`dpi_input_hook_v6`、`wifi_accelerate_output_hook`、`wifi_accelerate_postrouting_hook`、**`oplus_game_data_input_hook`** (`.text+0x25334`)、**`game_main_stream_nf_output_hook_func`** (`.text+0x25b18`)<br>**返回 `0` 的匹配与上报函数**：`notify_netlink_event`、`send_one_msg`、`notify_dpi_result`、`dpi_handle_match`、`tls_sni_match`、`gquic_sni_match`、`http_request_match`、`http_request_global_match`、**`work_func`** (`.text+0x25570`)、**`notify_game_main_stream_ip_message`** (`.text+0x25ec8`)（共 18 处函数实例） |
| `oplus_network_app_monitor.ko` | `net/oplus_apps_monitor`<br>`net/oplus_app_power_monitor` | **`proc_app_power_monitor_start`** (`.text+0x3234`)<br>**`proc_app_power_report_request`** (`.text+0x32c8`)<br>**`proc_app_set_beat_alarm_period`** (`.text+0x3354`)<br>**`proc_app_set_push_alarm_period`** (`.text+0x3498`) | **返回 `NF_ACCEPT (1)` 的钩子**：`oplus_apps_monitor_postrouting_hook4`、`oplus_apps_monitor_input_hook4`、`oplus_apps_monitor_postrouting_hook6`、`oplus_apps_monitor_input_hook6`<br>**返回 `0` 的上报与回调**：`apps_monitor_netlink_send_to_user`、`apps_monitor_report_apps_rtt_to_user`、`apps_monitor_report_dev_rtt_to_user`、`oplus_app_monitor_send_app_info_report`、`oplus_app_monitor_send_beat_alarm`、`oplus_app_monitor_send_push_alarm`、`oplus_app_monitor_send_traffic_alarm` + 上述 4 个 `proc_app_power_*` 回调（共 15 处函数实例） |
| `oplus_network_score.ko` | `net/oplus_score` | **`proc_set_test_link_index`** (`.text+0x3c78`) | **返回 `NF_ACCEPT (1)` 的钩子**：`oplus_score_postrouting_hook4`、`oplus_score_input_hook4`、`oplus_score_postrouting_hook6`、`oplus_score_input_hook6`<br>**返回 `0` 的上报与回调**：`oplus_score_calc_and_report`、`oplus_score_send_netlink_msg` + **`proc_set_test_link_index`**（共 7 处函数实例） |
| `oplus_network_snapshot.ko` | `net/oplus_snapshot`<br>`net/oplus_dnsdata_hook` | 无（`proc_dointvec`） | **返回 `NF_ACCEPT (1)` 的钩子**：`oplus_dns_data_output_hook`、`oplus_dns_data_input_hook`、`network_stat_output_hook`、`network_stat_input_hook`<br>**返回 `0` 的采样与上报函数**：`dns_query_timeout`、`report_dns_data`、`hook_fun`、`snapshot_report_timer_function`（共 8 处） |
| `oplus_network_stats_calc.ko` | `net/oplus_stats_calc` | 无（`proc_dointvec`） | **返回 `NF_ACCEPT (1)` 的钩子**：`oplus_stats_calc_input_hook`、`oplus_stats_calc_output_hook`<br>**返回 `0` 的统计与上报函数**：`add_iface_uid_stats`、`send_netlink_data`（共 4 处） |
| `oplus_network_dns_hook.ko` | `net/oplus_dns_hook` | 无（`proc_dointvec`） | **返回 `NF_ACCEPT (1)` 的钩子**：`oplus_dns_hook_output_hook`<br>**返回 `0` 的 Netlink 接收函数**：`oplus_dns_hook_netlink_rcv_msg`（共 2 处） |
| `oplus_network_dns_cache.ko` | `net/oplus_dns_cache` | 无（`proc_dointvec`） | **返回 `NF_ACCEPT (1)` 的钩子**：`hfunc`<br>**返回 `0` 的解析与上报函数**：`parse_lib`、`report_nas`、`dns_report_timeout_fun`（共 4 处） |
| `oplus_network_sk_predict.ko` | `net/oplus_sk_predict` | 无（`proc_dointvec`） | **返回 `0` 的 Kprobe/Kretprobe 与上报函数**：`notify_sk_predict_result`、`handler_inet_release`、`handler_sys_socket_exit`（共 3 处） |
| `oplus_network_vip_task.ko` | `net/oplus_vip_task` | 无（`proc_dointvec`） | **返回 `NF_ACCEPT (1)` 的钩子**：`oplus_rx_thread_info_input_hook`<br>**返回 `0` 的 Kprobe 与上报函数**：`report_vip_task_data`、`report_vip_task_record_data`、`kprobe_oplus_vip_task_recvmsg_hook`、`kprobe_oplus_vip_task_timeinfo_hook`、`kretprobe_oplus_vip_task_timeinfo_hook`、`report_vip_task_data_work_handler`（共 7 处） |

### 5.3 其余 13 个监控模块的 `.symtab` 真实补丁函数表（完全对应 `v3.0.1` `manifest.json`）

| 序号 | 模块名称 (`.ko`) | 必须保留的外部壳层接口 (`genl` / `/proc` / `/dev`) | `.symtab` 实存被置空函数与返回值契约（完全对齐 `v3.0.1`） |
| :--- | :--- | :--- | :--- |
| 01 | `inte.ko` | `/proc/inte_ko`<br>`/proc/inte_systbl`<br>`/proc/inte_status` | **返回写入长度 `count` (`mov x0, x2`)**：`proc_write_ko`、`proc_write_status`<br>**返回 `0`**：`add_ko_event`、`add_systbl_event`、`check_task`、`ko_proc_show`、`systbl_proc_show`、`hash_probe_entry`（共 8 处） |
| 02 | `oplus_secure_guard_new.ko` | Genl: `secure_guard` (`oplus_security_family`) | **全部 23 个函数置空返回 `0`**：`oplus_exe_block_ret_handler`、`oplus_report_execveat`、`oplus_harden_pre_handler`、`oplus_secure_harden_kevent`、`kevent_send_to_user`、`report_security_event`、`oplus_root_check_succ`、`oplus_root_killed`、`oplus_root_check_pre_handler`、`oplus_root_check_post_handler`、`oplus_heapspray_check`、`oplus_sepolicy_reload`、`oplus_harden_init`（注：`oplus_harden_exit` 首部检查 `oplus_harden_init_succeed == 1`，为 `0` 时直接 `ret` 安全退出）、`handler_pre`、`entry_handler_sepolicy_reload`、`entry_handler_socket`、`entry_handler_socket_ip6`、`entry_handler_cpuinfo`、`do_execveat_common_entry_handler`、`oplus_report_execveat_new`、`uid_ret_handler`、`uid_entry_handler`、`oplus_root_check_succ_upload` |
| 03 | `oplus_patch.ko` | `/proc/kprobe_ctl`<br>`/proc/kprobe_log` | **返回写入长度 `count` (`mov x0, x2`)**：`ctl_write`<br>**返回 `0`**：`log_add`、`hook_enable`、`hook_enable_all`、`hook_register`、`handler_pre_first`、`handler_pre_second`、`log_show`（共 8 处） |
| 04 | `oplus_bsp_file_read_record.ko` | `/proc/oplus_mem/oplus_frr` | **返回写入长度 `count` (`mov x0, x2`)**：`oplus_frr_write`<br>**返回 `0`**：`oplus_frr_read`、`trace_android_vh_filemap_read_hook`、`trace_android_vh_filemap_map_pages_hook`、`trace_android_vh_do_read_fault_hook`、`io_monitor_record`（共 6 处） |
| 05 | `oplus_bsp_dfr_ubt.ko` | Platform Driver: `userspace_backtrace` | **全部 5 个函数置空返回 `0`**：`dump_userspace_backtrace`、`ubt_mmput`、`ubt_mmput_fn`、`access_process_vm_ubt`、`userspace_backtrace_systrigger` |
| 06 | `oplus_network_qr_scan.ko` | Genl: `qr_scan` (`qr_monitor_genl_family`) | **返回 `NF_ACCEPT (1)` 的钩子**：`oplus_filter_qr_v4_send_skb`、`oplus_filter_qr_v6_send_skb`、`oplus_filter_qr_v4_receive_skb`、`oplus_filter_qr_v6_receive_skb`<br>**返回 `0`**：`qr_monitor_netlink_nlmsg_handle`、`oplus_qr_hooks_send_to_user`（共 6 处） |
| 07 | `oplus_network_tcpdump_enhance.ko` | Genl: `tcpdump_netlink` (`tcpdump_genl_family`) | **返回 `NF_ACCEPT (1)` 的钩子**：`tcpdump_output_hook_v4`、`tcpdump_output_hook_v6`<br>**返回 `0`**：`tcpdump_handle_record`、`notify_netlink_event`、`comm_netlink_inform_msg`（共 5 处） |
| 08 | `oplus_bsp_midas.ko` | `/dev/midas_dev`<br>`/dev/binder_stats`<br>Platform Device: `midas-pdev` | **全部 7 个采样与跟踪函数置空返回 `0`**：`binder_proc_transaction_hook`、`binder_new_ref_hool`、`binder_del_ref_hook`、`rasm_suspend`、`rasm_resume`、`midas_record_task_times`、`update_or_create_entry_locked` |
| 09 | `oplus_sys_stability_helper.ko` | Genl: `oplus_frk_nl` (`oplus_frk_genl_family`) | **全部 10 个监控与上报函数置空返回 `0`**：`pending_transaction_watcher_do_work`、`pending_transaction_watcher`、`binder_buffer_watcher`、`send_to_frk`、`do_check_system_server_hang`、`lowmem_report`、`lowmem_report_func`、`send_signal_catcher`、`thread_watcher_do_work`、`thread_watcher` |
| 10 | `oplus_bsp_dfr_theia.ko` | Genl: `theia_kevent`<br>`/proc/theiaPwkReport`<br>`/proc/blackSwitch`<br>`/proc/brightSwitch` | **全部 5 个上报函数置空返回 `0`**：`send_black_screen_dcs_msg`、`SendTheiaKevent`、`SendDcsTheiaKevent`、`theia_send_event`、`theia_send_event_atomic` |
| 11 | `oplus_bsp_sigkill_diagnosis.ko` | `/proc/oplus_mem/sigkill_reason` | **全部 2 个记录与读取函数置空返回 `0`**：`record_sigkill_reason`、`sigkill_reason_read` |
| 12 | `mtk_mbraink.ko` | `/dev/mbraink` & Netlink | **全部 14 个采样、跟踪与 `ioctl` 函数置空返回 `0`**：`mbraink_process_tracer_init`（注：`mbraink_process_tracer_exit` 检查注册标志位，未注册时直接跳过 `tracepoint_probe_unregister`）、`lookup_tracepoints`、`mbraink_sched_process_fork`、`mbraink_sched_process_exit`、`mbraink_binder_transaction`、`mbraink_trace_android_vh_cpufreq_acct_update_power`、`mbraink_sched_process_data_send`、`mbraink_netlink_send_msg`、`logmiscdata2mbrain`、`mbraink_ioctl`、`mbraink_compat_ioctl`、`insert_freq_qos_hook`、`freq_qos_max_notifier_call`、`freq_qos_min_notifier_call` |
| 13 | `mtk_mbraink_v6991.ko` | 依赖 `mtk_mbraink.ko` | **全部 13 个平台采集函数置空返回 `0`**：`ufs2mbrain_event_notify`、`pt2mbrain_hint_low_battery_volt_throttle`、`pt2mbrain_hint_battery_oc_throttle`、`pt2mbrain_ppb_notify_func`、`fpsgo2mbrain_hint_frameinfo`、`fpsgo2mbrain_hint_perfinfo`、`fpsgo2mbrain_hint_deleteperfinfo`、`gpu2mbrain_hint_fenceTimeoutNotify`、`gpu2mbrain_hint_GpuResetDoneNotify`、`mbraink_v6991_set_camera_hw_info`、`update_mbraink_sys_res_record`、`mbraink_sys_res_log`、`mbraink_update_sys_res_record` |
## 六、 v3.1.0 扩展审计：新增 3 个网络遥测模块与 1 个保留模块（26+1 全量闭环）

在原有 23 个监控驱动基础上，`v3.1.0` 对固件中其余 4 个关联模块完成了二进制符号表与重定位审计，使受控空壳模块总数达到 **26 个（合计 264 处函数实例，保留 57 个 `/proc/sys/net/*` sysctl 目录）**，另保留 1 个原厂硬件保护模块：

| 编号 | 模块文件名 (`.ko`) | 大小 (B) | 原厂 SHA-256 (前16位) | `/proc/sys/net/` 目录（+7 个） | `v3.1.0` 处置策略与 `.symtab` 实存补丁函数（共 +25 处） |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 24 | `oplus_network_dns_optimizer.ko` | 152,176 | `9416004c364583bd` | `net/oplus_dns_reserve`<br>`net/oplus_dns_rtx`<br>`net/oplus_dns_race`<br>`net/oplus_dns_fast_retransmit` | **纳入空壳（20 处）**：置空 8 个 DNS Race/Reserve Netfilter 钩子（`oplus_dns_race_postrouting/prerouting_hook4/6`、`oplus_dns_reserve_local_in/postrouting_hook4/6`）及 `oplus_dns_fast_transmit_dns_query`、`oplus_dns_fast_transmit_dns_query_response`、2 处 `parse_dns_data`、`build_dns_response`、`dns_send_work_fn`、`oplus_dns_query_rtx_check`、`oplus_dns_response_input_check`、`dns_race_report_record_timer_function`、`dns_reserve_report_timer_fn`、`dns_rtx_report_work`、`dns_rtx_report_record_timer_function`，完整保留 4 个 sysctl 目录 |
| 25 | `oplus_network_fast_bwe.ko` | 29,264 | `3e0017da4773a3ab` | `net/oplus_fast_bwe` | **纳入空壳（2 处）**：置空 `oplus_fast_bwe_local_in_hook` 与 `report_fast_bwe_result_timer`，完整保留 `net/oplus_fast_bwe` 目录 |
| 26 | `oplus_network_tuning.ko` | 92,216 | `7cbb7bcce1ac914e` | `net/oplus_dev`<br>`net/oplus_bbr` | **纳入空壳（3 处）**：仅置空 `oplus_network_tuning_report_hook`、`tcp_syn_report`、`tcp_syn_hook` 3 个遥测函数，保留 TCP BBR/CUBIC 拥塞控制与 2 个 sysctl 目录 |
| 27 | `oplus_bsp_dfr_combkey_monitor.ko` | 36,168 | `f54b0091bc772022` | 无 | **故意保留原厂**：负责强制长按重启前的 `blkdev_fsync` 数据落盘保护，且其唯一遥测出口 `theia_send_event` 已在 `oplus_bsp_dfr_theia.ko` 中置空 |

同时，`v3.0.2`～`v3.1.0` 对 `mtk_mbraink.ko` 做了精细化改进（补丁数由 14 调整为 20）：恢复 `mbraink_ioctl` 与 `mbraink_compat_ioctl` 原厂分发框架，改为置空底层 8 个数据采集填充子函数（`mbraink_get_process_memory_info`、`mbraink_get_process_stat_info`、`mbraink_get_thread_stat_info`、`mbraink_processname_to_pid`、`mbraink_get_tracing_pid_info`、`mbraink_get_binder_trace_info`、`mbraink_get_cpufreq_trace_info`、`mbraink_get_cpufreq_notifier_info`），确保用户态 `ioctl` 缓冲区正常清零返回。

## 七、 核心 Protobuf 上报数据结构定义（逆向自 `.rela.rodata`）

以下 `.proto` 结构严格还原自 `oplus_network_data_module.ko` 导出的 72 字节 `ProtobufCFieldDescriptor` 数组及各子模块导入符号：

```protobuf
syntax = "proto2";
package netlink.proto;

// 1. oplus_network_dns_cache.ko (T0 极高危): 明文访问域名上报
message dns_meta_data {
    required uint32 uid = 1;
    required string domain = 2;
    required uint32 ttl = 3;
}

message notify_dns_meta_data {
    repeated dns_meta_data dnsInfo = 1;
}

// 2. oplus_network_data_module.ko (T0 极高危): DPI 活动信号与游戏服务器 IP 上报
message notify_dpi_result {
    required uint32 uid = 1;
    required uint32 levelType = 2;
    required uint32 dpiId = 3;
    required uint32 state = 4;
}

message notify_game_main_server_ip {
    required uint32 battleIp = 1;
    required uint32 gameUid = 2;
    optional uint64 ipv6High = 3;
    optional uint64 ipv6Low = 4;
}

message notify_wzry_server_ip {
    required uint32 battleIp = 1;
}

// 3. oplus_network_snapshot.ko (T1 高危): DNS 服务器 IP/时延/RCODE 与按 UID 流量快照
message dns_normal_data {
    required uint32 uid = 1;
    required uint32 isRecursion = 2;
    required uint32 dnsServer = 3;
    required uint32 latency = 4;
    required uint32 index = 5;
    required uint32 code = 6;
}

message notify_network_snapshot_app {
    required uint32 uid = 1;
    required uint32 upTPut = 2;
    required uint32 upTcpTPut = 3;
    required uint32 upTcpValidTPut = 4;
    required uint32 tcpRtt = 5;
    required uint32 upUdpTPut = 6;
    required uint32 upPps = 7;
    required uint32 downTPut = 8;
    required uint32 downTcpTPut = 9;
    required uint32 downTcpValidTPut = 10;
    required uint32 downUdpTPut = 11;
    required uint32 downPps = 12;
}

// 4. oplus_network_sk_predict.ko (T1 高危): 前台 Activity 与 Socket 行为预测
message request_set_sk_predict_activity_info {
    required bool isSet = 1;
    required uint32 uid = 2;
    required uint32 dpiId = 3;
    optional string activityName = 4;
}

message notify_sk_predict_result {
    required uint32 uid = 1;
    required uint32 dpiId = 2;
    required uint32 state = 3;
}

// 5. oplus_network_vip_task.ko (T2 中危): VIP 业务流收包线程追踪
message notify_vip_task_data {
    required uint32 dpi_id = 1;
    required uint32 tgid = 2;
    required uint32 pid = 3;
}

message notify_vip_task_record_data {
    required uint32 over_ten_times = 1;
    repeated uint32 top_three_time = 2;
}
```

## 八、 只读 ELF 完整性、BTI 序言与重定位核验脚本（Python）

以下只读审计脚本用于对照原厂 `.ko`、空壳 `.ko` 与 `manifest.json`，自动验证全部 26 个模块的 SHA-256、函数差异、ARM64 BTI/PAC 序言对齐、`.rela.text` 重定位表清零以及是否误伤 `register_net_sysctl_sz` / `register_netlink_request` 等壳层注册调用：

```python
#!/usr/bin/env python3
"""只读 ELF 内核模块完整性、BTI/PAC 序言与重定位表核验工具"""
import hashlib
import json
import os
import struct
import sys

SHELL_APIS = (
    "register_net_sysctl",
    "proc_create",
    "proc_mkdir",
    "genl_register",
    "misc_register",
    "cdev_add",
    "register_netlink_request",
)

def parse_elf64(data: bytes):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shdrs = [
        struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
        for i in range(e_shnum)
    ]
    shstr_sh = shdrs[e_shstrndx]
    shstr = data[shstr_sh[4] : shstr_sh[4] + shstr_sh[5]]

    def sname(idx: int) -> str:
        end = shstr.find(b"\x00", idx)
        return shstr[idx:end].decode("latin1")

    sections = {sname(s[0]): s for s in shdrs}
    sym_sh = sections[".symtab"]
    str_sh = sections[".strtab"]
    strtab = data[str_sh[4] : str_sh[4] + str_sh[5]]

    syms = []
    text_funcs = []
    for off in range(sym_sh[4], sym_sh[4] + sym_sh[5], 24):
        st_name, st_info, _st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", data, off
        )
        name = ""
        if st_name:
            name = strtab[st_name : strtab.find(b"\x00", st_name)].decode("latin1")
        sec = sname(shdrs[st_shndx][0]) if st_shndx < len(shdrs) else ""
        syms.append((name, st_value, st_size, sec))
        if sec == ".text" and st_size > 0 and (st_info & 0xF) == 2 and not name.startswith("$"):
            text_funcs.append((name, st_value, st_size))
    return sections, syms, text_funcs

def verify_package(stock_dir: str, hollow_dir: str):
    manifest = json.loads(open(os.path.join(hollow_dir, "manifest.json"), encoding="utf-8").read())
    total = len(manifest["drivers"])
    passed_sha = 0
    total_patched = 0
    total_rela_err = 0
    total_bti_err = 0
    total_shell_warn = 0

    for fn, info in sorted(manifest["drivers"].items()):
        h_path = os.path.join(hollow_dir, fn)
        s_path = os.path.join(stock_dir, fn)
        h_data = open(h_path, "rb").read()
        s_data = open(s_path, "rb").read()

        if hashlib.sha256(h_data).hexdigest() == info["sha256"] and len(h_data) == info["size"]:
            passed_sha += 1
        else:
            print(f"[FAIL-SHA] {fn}: manifest mismatch")

        sections, syms, text_funcs = parse_elf64(s_data)
        t_off, t_sz = sections[".text"][4], sections[".text"][5]
        r_off, r_sz = sections[".rela.text"][4], sections[".rela.text"][5]

        # 1. 检查被修改的 .text 指令是否仍存在未清零的重定位项
        for v_off in range(0, t_sz, 4):
            if s_data[t_off + v_off : t_off + v_off + 4] != h_data[t_off + v_off : t_off + v_off + 4]:
                for roff in range(r_off, r_off + r_sz, 24):
                    r_offset, r_info, _r_addend = struct.unpack_from("<QQq", h_data, roff)
                    if r_offset == v_off and (r_info & 0xFFFFFFFF) != 0:
                        print(f"[FAIL-RELA] {fn} @.text+{hex(v_off)} active rela={r_info & 0xFFFFFFFF}")
                        total_rela_err += 1

        # 2. 检查被修补函数的 BTI/PAC 序言与壳层注册调用
        for fname, fval, fsz in sorted(text_funcs, key=lambda x: x[1]):
            clen = min(16, fsz)
            if s_data[t_off + fval : t_off + fval + clen] != h_data[t_off + fval : t_off + fval + clen]:
                total_patched += 1
                prologue = h_data[t_off + fval : t_off + fval + 4].hex()
                if prologue not in ("3f2303d5", "5f2403d5"):
                    print(f"[FAIL-BTI] {fn}: {fname} prologue={prologue}")
                    total_bti_err += 1
                for roff in range(r_off, r_off + r_sz, 24):
                    r_offset, r_info, _r_addend = struct.unpack_from("<QQq", s_data, roff)
                    if fval <= r_offset < fval + fsz:
                        callee = syms[r_info >> 32][0]
                        if any(k in callee for k in SHELL_APIS):
                            print(f"[WARN-SHELL] {fn}: {fname} calls {callee}")
                            total_shell_warn += 1

    print(
        f"DONE: sha={passed_sha}/{total}, patched={total_patched}, "
        f"rela_err={total_rela_err}, bti_err={total_bti_err}, shell_warn={total_shell_warn}"
    )

if __name__ == "__main__":
    verify_package(sys.argv[1], sys.argv[2])
```

## 九、 `OPlus Kernel Guard v3.1.0` 完整工程代码清单

以下为 `oplus_kernel_guard_v3.1.0.zip` 中的全部核心配置文件、启动期抢占脚本、跨 Boot 防砖熔断器与生命周期控制源码（逐字完整收录）。

### 9.1 `module.prop`

```properties
id=oplus_kernel_guard
name=OPlus Kernel Guard
version=v3.1.0
versionCode=310
author=Antigravity
description=欧加 MT6991 GKI 6.6 空壳绿灯守护模组（26 模块 PAC/BTI 空壳驻留 | 优先 mount --bind 抢占 + 早期遗留回滚替换 | Fail-Closed 双哈希硬门禁 | crash_guard 崩溃归因熔断 | 无自动杀进程）。无需元模块。
```

### 9.2 `config.conf`

```sh
# OPlus Kernel Guard v3.1.0 Configuration
# 可通过 KernelSU / APatch WebUI 或直接编辑本文件调整模式

# 运行模式:
#   hollow_26  (默认) = 26 个监控/网络遥测驱动空壳驻留（未预载模块 mount --bind 抢占，已预载模块带完整回滚替换）
#   hollow_v2         = 旧版兼容模式 (15 卸载 + 8 空壳替换)
#   step1_only        = 保守模式 (仅卸载 4 个纯非网络无上报驱动)
GUARD_MODE="hollow_26"

# 是否启用 post-fs-data 启动期 mount --bind 抢占覆盖 /vendor/lib/modules & /vendor_dlkm/lib/modules
BIND_PREEMPT_ENABLE=1

# 是否在挂载后自动调用 ksu_susfs add_sus_mount 隐藏挂载项 (默认关闭 0，保证诊断透明；按需开启 1)
SUSFS_AUTO_HIDE=0

# 目标内核 vermagic 校验 (Fail-Closed 双哈希硬门禁: 空壳 sha256 + 原厂 stock_sha256)
EXPECTED_UNAME="6.6.118-android15-8-o-g15bab650beb0-4k"
FORCE_HOLLOW_SWAP=0

# post-fs-data 早期检查 (针对在 first_stage_init 已提前加载的模块)
EARLY_SWAP_ENABLE=1
EARLY_SWAP_MODULES="inte oplus_secure_guard_new"

# 26 个空壳绿灯驱动列表 (23 核心监控 + dns_optimizer / fast_bwe / tuning 遥测；combkey_monitor 保留原厂 fsync 保护)
HOLLOW_26_LIST="inte oplus_secure_guard_new oplus_patch oplus_network_data_module oplus_network_dns_hook oplus_network_qr_scan oplus_bsp_file_read_record oplus_bsp_dfr_theia oplus_network_dns_cache oplus_network_snapshot oplus_network_sk_predict oplus_network_vip_task oplus_network_linkpower_module oplus_network_score oplus_network_tcpdump_enhance oplus_network_app_monitor oplus_network_stats_calc oplus_bsp_midas mtk_mbraink mtk_mbraink_v6991 oplus_sys_stability_helper oplus_bsp_sigkill_diagnosis oplus_bsp_dfr_ubt oplus_network_dns_optimizer oplus_network_fast_bwe oplus_network_tuning"

# 旧版兼容列表
STEP1_MODULES="oplus_bsp_dfr_ubt oplus_bsp_file_read_record oplus_bsp_sigkill_diagnosis oplus_bsp_midas"
RMMOD_LIST="oplus_network_dns_cache oplus_network_sk_predict oplus_network_snapshot oplus_network_vip_task oplus_network_linkpower_module oplus_network_score oplus_network_tcpdump_enhance oplus_network_app_monitor oplus_network_stats_calc oplus_bsp_dfr_ubt oplus_bsp_midas oplus_sys_stability_helper oplus_bsp_sigkill_diagnosis mtk_mbraink_v6991 mtk_mbraink"
HOLLOW_SWAP_LIST="inte oplus_secure_guard_new oplus_patch oplus_network_dns_hook oplus_network_qr_scan oplus_network_data_module oplus_bsp_file_read_record oplus_bsp_dfr_theia"

# 自定义补充卸载 / 白名单保护 (空格分隔模块名，不含 .ko)
CUSTOM_UNLOAD_MODULES=""
PROTECT_MODULES=""

# 开机延迟复检与观察期配置
RECHECK_DELAY_SEC=10
PROBING_TIMEOUT=60
```

### 9.3 `customize.sh`

```sh
#!/system/bin/sh
# OPlus Kernel Guard Installer Script v3.0.0

[ -z "$MODPATH" ] && MODPATH="/data/adb/modules/oplus_kernel_guard"
[ -z "$ARCH" ] && ARCH=$(getprop ro.product.cpu.abi | grep -q "arm64" && echo "arm64" || echo "other")

if ! type ui_print >/dev/null 2>&1; then
    ui_print() { echo "$1"; }
fi
if ! type abort >/dev/null 2>&1; then
    abort() { ui_print "$1"; exit 1; }
fi
if ! type set_perm >/dev/null 2>&1; then
    set_perm() { chown "$2:$3" "$1" 2>/dev/null; chmod "$4" "$1" 2>/dev/null; }
fi
if ! type set_perm_recursive >/dev/null 2>&1; then
    set_perm_recursive() {
        find "$1" -type d -exec chmod "$4" {} + 2>/dev/null
        find "$1" -type f -exec chmod "$5" {} + 2>/dev/null
        chown -R "$2:$3" "$1" 2>/dev/null
    }
fi

export GUARD_ID="oplus_kernel_guard"

ui_print "***************************************************"
ui_print "         OPlus Kernel Guard v3.1.0                 "
ui_print " 26 模块空壳驻留 · 双哈希硬门禁 · 无自动杀进程     "
ui_print "***************************************************"

KVER=$(uname -r)
ui_print "- 设备架构: $ARCH"
ui_print "- 当前内核: $KVER"
if [ "$KVER" != "6.6.118-android15-8-o-g15bab650beb0-4k" ]; then
    ui_print "! 注意: 当前内核与预编译空壳 vermagic 不一致"
    ui_print "! Fail-Closed 双哈希硬门禁将自动拦截空壳挂载与加载"
fi

OLD_CONF="/data/adb/modules/oplus_kernel_guard/config.conf"
if [ -f "$OLD_CONF" ] && [ "$MODPATH" != "/data/adb/modules/oplus_kernel_guard" ]; then
    if grep -q "HOLLOW_26_LIST=" "$OLD_CONF" 2>/dev/null; then
        ui_print "- 检测到 v3.1 配置，保留现有 config.conf"
        cp -f "$OLD_CONF" "$MODPATH/config.conf"
    else
        ui_print "- 升级至 v3.1.0：启用默认 hollow_26 配置 (SUSFS 自动隐藏默认关闭)"
    fi
fi

rm -rf "${MODPATH:?}/system"

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/guard_ctl.sh" 0 0 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm_recursive "$MODPATH/crash_guard" 0 0 0755 0755
set_perm_recursive "$MODPATH/hollow_modules" 0 0 0755 0644
set_perm_recursive "$MODPATH/webroot" 0 0 0755 0644

if [ -x "$MODPATH/crash_guard/crash_guard.sh" ]; then
    "$MODPATH/crash_guard/crash_guard.sh" preserve-or-init
    init_res=$?
    if [ "$init_res" -eq 2 ]; then
        ui_print "! [重装保护] 检测到历史跨 Boot 熔断锁定状态 (TRIPPED)！"
        ui_print "! 已保留熔断并物理锁定所有 .ko.tripped，开机后不会挂载/加载空壳"
        ui_print "! 排查后可在 WebUI 点击「复位熔断器」解除锁定"
    else
        ui_print "- 跨 Boot 熔断保护器 (crash_guard) 就绪: NORMAL"
    fi
fi

ui_print "- 默认模式: hollow_26 (26 个空壳驻留，优先 mount --bind 抢占，失败验证回滚原厂)"
ui_print "- 安全约束: 校验空壳 sha256 + 原厂 stock_sha256；禁止自动强杀用户态进程"
ui_print "- 安装完成！请重启设备以激活启动期防护。"
ui_print "***************************************************"
```

### 9.4 `post-fs-data.sh`

```sh
#!/system/bin/sh
# OPlus Kernel Guard Early Boot (post-fs-data) Hook
# 在第二阶段 vendor_modprobe 加载驱动前执行 mount --bind 抢占，
# 并对已在 first_stage_init 加载的个别模块执行早期无感热替换

SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
MODDIR="${SCRIPT_DIR:-/data/adb/modules/oplus_kernel_guard}"
CTL="$MODDIR/guard_ctl.sh"
CG="$MODDIR/crash_guard/crash_guard.sh"

export PATH="/system/bin:/system/xbin:/vendor/bin:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"
export GUARD_ID="oplus_kernel_guard"

if [ -x "$CG" ]; then
    if ! sh "$CG" check >/dev/null 2>&1; then
        exit 0
    fi
fi

[ -f "$CTL" ] && sh "$CTL" early_preempt
exit 0
```

### 9.5 `service.sh`

```sh
#!/system/bin/sh
# OPlus Kernel Guard Post-Boot Service v3.0.0

SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
MODDIR="${SCRIPT_DIR:-/data/adb/modules/oplus_kernel_guard}"
CONFIG="$MODDIR/config.conf"
CTL="$MODDIR/guard_ctl.sh"
CG="$MODDIR/crash_guard/crash_guard.sh"

export PATH="/system/bin:/system/xbin:/vendor/bin:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"
export GUARD_ID="oplus_kernel_guard"

update_prop_desc() {
    new_desc="$1"
    prop_file="$MODDIR/module.prop"
    [ -f "$prop_file" ] || return 0
    grep -v '^description=' "$prop_file" > "${prop_file}.tmp" 2>/dev/null
    printf 'description=%s\n' "$new_desc" >> "${prop_file}.tmp"
    mv -f "${prop_file}.tmp" "$prop_file"
}

WAIT_COUNT=0
until [ "$(getprop sys.boot_completed)" = "1" ] || [ "$WAIT_COUNT" -ge 90 ]; do
    sleep 2
    WAIT_COUNT=$((WAIT_COUNT + 1))
done
sleep 4

# 1. 跨 Boot 熔断开机自检
if [ -x "$CG" ]; then
    if ! sh "$CG" check; then
        update_prop_desc "【熔断跳闸】已阻止空壳驱动挂载/加载，防止无限重启。请打开 WebUI 或执行 crash_guard reset 复位"
        sh "$CTL" status_json > "$MODDIR/status.json" 2>/dev/null
        exit 0
    fi
fi

# 2. 执行守护策略与状态核验
sh "$CTL" apply

RECHECK_DELAY_SEC=10
PROBING_TIMEOUT=60
[ -f "$CONFIG" ] && . "$CONFIG"
if [ -n "$RECHECK_DELAY_SEC" ] && [ "$RECHECK_DELAY_SEC" -gt 0 ] 2>/dev/null; then
    sleep "$RECHECK_DELAY_SEC"
    sh "$CTL" apply quiet
fi

# 3. 启动 60s 单例看门狗（若处于 PROBING 状态）
if [ -x "$CG" ]; then
    cg_state=$(sh "$CG" status 2>/dev/null | sed -n 's/.*"state":"\([^"]*\)".*/\1/p')
    if [ "$cg_state" = "PROBING" ]; then
        sh "$CG" watchdog "${PROBING_TIMEOUT:-60}" >/dev/null 2>&1 &
    fi
fi

case "${GUARD_MODE:-hollow_26}" in
    hollow_26|hollow_23)
        update_prop_desc "【26空壳驻留】优先 mount --bind 抢占 | 双哈希门禁 | crash_guard 崩溃归因保护中"
        ;;
    hollow_v2)
        update_prop_desc "【兼容模式 v2】15安全卸载 + 8空壳绿灯 | crash_guard 保护中"
        ;;
    *)
        update_prop_desc "【Step 1 保守模式】仅卸载4个无上报非网络驱动 | crash_guard 就绪"
        ;;
esac
exit 0
```

### 9.6 `action.sh`

```sh
#!/system/bin/sh
# OPlus Kernel Guard Action Script v3.1.0

SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
MODDIR="${SCRIPT_DIR:-/data/adb/modules/oplus_kernel_guard}"
CONFIG="$MODDIR/config.conf"
CTL="$MODDIR/guard_ctl.sh"
CG="$MODDIR/crash_guard/crash_guard.sh"
LOGFILE="$MODDIR/guard.log"
SWAP_MARK_DIR="$MODDIR/.runtime/swapped"
BOUND_MARK_DIR="$MODDIR/.runtime/bound"
STOCK_VERIFIED_DIR="$MODDIR/.runtime/stock_verified"

export PATH="/system/bin:/system/xbin:/vendor/bin:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"
export GUARD_ID="oplus_kernel_guard"
[ -f "$CONFIG" ] && . "$CONFIG"
[ "$GUARD_MODE" = "hollow_23" ] && GUARD_MODE="hollow_26"
[ -z "$HOLLOW_26_LIST" ] && HOLLOW_26_LIST="$HOLLOW_23_LIST"

echo "================================================="
echo "      OPlus Kernel Guard v3.1.0 状态面板         "
echo "================================================="
echo "内核版本: $(uname -r) ($(uname -m))"
echo "当前模式: ${GUARD_MODE:-hollow_26}"

if [ -x "$CG" ]; then
    cg_json=$(sh "$CG" status 2>/dev/null)
    cg_state=$(printf '%s' "$cg_json" | sed -n 's/.*"state":"\([^"]*\)".*/\1/p')
    cg_fail=$(printf '%s' "$cg_json" | sed -n 's/.*"fail_count":\([0-9]*\).*/\1/p')
    cg_max=$(printf '%s' "$cg_json" | sed -n 's/.*"max_fail":\([0-9]*\).*/\1/p')
    cg_br=$(printf '%s' "$cg_json" | sed -n 's/.*"boot_reason":"\([^"]*\)".*/\1/p')
    cg_reason=$(printf '%s' "$cg_json" | sed -n 's/.*"trip_reason":"\([^"]*\)".*/\1/p')
    echo "熔断器状态 (crash_guard): ${cg_state:-UNKNOWN} (计数: ${cg_fail:-0}/${cg_max:-2}, bootreason=${cg_br:-unknown})"
    [ -n "$cg_reason" ] && echo "熔断原因: $cg_reason"
    if [ "$cg_state" = "TRIPPED" ]; then
        echo "-------------------------------------------------"
        echo "[!] 熔断器已跳闸锁定！所有空壳驱动已被重命名为 .ko.tripped"
        echo "[!] 排查确认无误后，请在 WebUI 点击「手动复位熔断器」或执行:"
        echo "    sh $CG reset"
        echo "================================================="
        exit 0
    fi
fi

echo "-------------------------------------------------"
echo "正在执行 Fail-Closed 双哈希门禁检查与守护状态同步..."
sh "$CTL" apply

if [ "${GUARD_MODE:-hollow_26}" = "hollow_26" ]; then
    echo "-------------------------------------------------"
    echo "【一】26 个空壳绿灯驱动驻留状态 (需实时挂载/哈希核验):"
    for M in $HOLLOW_26_LIST; do
        sv=""
        [ -f "$STOCK_VERIFIED_DIR/$M" ] && sv=" [stock_sha256 OK]"
        if grep -q "^${M} " /proc/modules 2>/dev/null; then
            if [ -f "$BOUND_MARK_DIR/$M" ] && grep -Eq " /vendor(_dlkm)?/lib/modules/${M}\.ko " /proc/mounts 2>/dev/null; then
                echo "  [🟢 抢占挂载] $M${sv}"
            elif [ -f "$SWAP_MARK_DIR/$M" ]; then
                echo "  [🟢 热替换壳] $M${sv}"
            else
                echo "  [🟡 原厂驻留] $M"
            fi
        else
            echo "  [⚪ 未加载]   $M"
        fi
    done
elif [ "${GUARD_MODE:-hollow_26}" = "hollow_v2" ]; then
    echo "-------------------------------------------------"
    echo "【一】8 个空壳驱动 + 15 个安全卸载驱动状态:"
    for M in $HOLLOW_SWAP_LIST; do
        if grep -q "^${M} " /proc/modules 2>/dev/null; then
            [ -f "$SWAP_MARK_DIR/$M" ] && echo "  [🟢 空壳在线] $M" || echo "  [🟡 原厂驻留] $M"
        else
            echo "  [⚪ 未加载]   $M"
        fi
    done
else
    echo "-------------------------------------------------"
    echo "Step 1 目标模块当前内核态检查:"
    for M in $STEP1_MODULES; do
        grep -q "^${M} " /proc/modules 2>/dev/null && echo "  [🔴 仍驻留] $M" || echo "  [✅ 已清空] $M"
    done
fi

echo "-------------------------------------------------"
echo "最近日志 (后 15 行):"
[ -f "$LOGFILE" ] && tail -n 15 "$LOGFILE"
echo "================================================="
```

### 9.7 `uninstall.sh`

```sh
#!/system/bin/sh
# OPlus Kernel Guard Uninstaller Script v3.1.0
# 仅卸载本模块在 .runtime/mounted_targets.list 中登记过的挂载点，避免误伤其他模块

MODDIR="/data/adb/modules/oplus_kernel_guard"
MOUNTED_LIST="$MODDIR/.runtime/mounted_targets.list"

if [ -f "$MOUNTED_LIST" ]; then
    # 逆序卸载：先卸载各 .ko 绑定，最后卸载 /dev/.kcache tmpfs
    sed '1!G;h;$!d' "$MOUNTED_LIST" 2>/dev/null | while IFS= read -r mp; do
        [ -z "$mp" ] && continue
        if grep -q " ${mp} " /proc/mounts 2>/dev/null; then
            umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || true
        fi
    done
fi

rm -rf /dev/.kcache /dev/.okg_swapped /dev/.okg_bound /dev/.okg_bind "$MODDIR/.runtime"
rm -f "$MODDIR/guard.log" "$MODDIR/status.json"
```

### 9.8 `guard_ctl.sh`

```sh
#!/system/bin/sh
# OPlus Kernel Guard v3.1.0 Core Controller
# 26 模块空壳驻留（优先启动期 mount --bind 抢占 + 早期遗留带验证回滚替换）
# + Fail-Closed 双哈希硬门禁 (hollow sha256 + stock_sha256)
# + 全局并发锁 + 无自动 SIGKILL + crash_guard 崩溃归因熔断器

SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
MODDIR="${SCRIPT_DIR:-/data/adb/modules/oplus_kernel_guard}"
CONFIG="$MODDIR/config.conf"
LOGFILE="$MODDIR/guard.log"
STATUSFILE="$MODDIR/status.json"
HOLLOW_DIR="$MODDIR/hollow_modules"
MANIFEST_FILE="$HOLLOW_DIR/manifest.json"
CRASH_GUARD="$MODDIR/crash_guard/crash_guard.sh"
RUNTIME_DIR="$MODDIR/.runtime"
SWAP_MARK_DIR="$RUNTIME_DIR/swapped"
BOUND_MARK_DIR="$RUNTIME_DIR/bound"
STOCK_VERIFIED_DIR="$RUNTIME_DIR/stock_verified"
RUNTIME_BOOT_FILE="$RUNTIME_DIR/boot_id"
MOUNTED_LIST_FILE="$RUNTIME_DIR/mounted_targets.list"
CTL_LOCK_DIR="$RUNTIME_DIR/.ctl.lock"
BIND_STAGE_DIR="/dev/.kcache"

export PATH="/system/bin:/system/xbin:/vendor/bin:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"
export GUARD_ID="oplus_kernel_guard"

ALL_TRACKED_MODULES="
inte
oplus_secure_guard_new
oplus_patch
oplus_network_data_module
oplus_network_dns_hook
oplus_network_qr_scan
oplus_bsp_file_read_record
oplus_bsp_dfr_theia
oplus_network_dns_cache
oplus_network_snapshot
oplus_network_sk_predict
oplus_network_vip_task
oplus_network_linkpower_module
oplus_network_score
oplus_network_tcpdump_enhance
oplus_network_app_monitor
oplus_network_stats_calc
oplus_bsp_midas
mtk_mbraink
mtk_mbraink_v6991
oplus_sys_stability_helper
oplus_bsp_sigkill_diagnosis
oplus_bsp_dfr_ubt
oplus_network_dns_optimizer
oplus_network_fast_bwe
oplus_network_tuning
oplus_bsp_dfr_combkey_monitor
"

MONITOR_NODES="
/proc/inte_ko
/proc/inte_systbl
/proc/inte_status
/proc/kprobe_ctl
/proc/kprobe_log
/proc/oplus_mem/oplus_frr
/proc/oplus_mem/sigkill_reason
/proc/sys/net/oplus_dns_cache
/proc/sys/net/oplus_snapshot
/proc/sys/net/oplus_game
/proc/sys/net/oplus_asc
/proc/sys/net/oplus_mdfw
/proc/sys/net/oplus_dns_race
/proc/sys/net/oplus_fast_bwe
/proc/sys/net/oplus_bbr
/dev/midas_dev
/dev/mbraink
"

get_runtime_boot_id() {
    bid=""
    if [ -r /proc/sys/kernel/random/boot_id ]; then
        bid="$(tr -d '\r\n ' < /proc/sys/kernel/random/boot_id 2>/dev/null)"
    fi
    if [ -z "$bid" ] && [ -r /proc/stat ]; then
        while IFS=' ' read -r k v rest; do
            if [ "$k" = "btime" ] && [ -n "$v" ]; then
                bid="btime_${v}"
                break
            fi
        done < /proc/stat
    fi
    [ -z "$bid" ] && bid="unknown"
    printf '%s' "$bid"
}

ensure_runtime_session() {
    cur_bid="$(get_runtime_boot_id)"
    saved_bid=""
    [ -f "$RUNTIME_BOOT_FILE" ] && saved_bid="$(tr -d '\r\n ' < "$RUNTIME_BOOT_FILE" 2>/dev/null)"
    if [ "$cur_bid" = "unknown" ] || [ -z "$saved_bid" ] || [ "$saved_bid" != "$cur_bid" ]; then
        rm -rf "$SWAP_MARK_DIR" "$BOUND_MARK_DIR" "$STOCK_VERIFIED_DIR" "$MOUNTED_LIST_FILE" 2>/dev/null
        mkdir -p "$RUNTIME_DIR" 2>/dev/null
        [ "$cur_bid" != "unknown" ] && printf '%s\n' "$cur_bid" > "$RUNTIME_BOOT_FILE" 2>/dev/null
    fi
}

CTL_LOCK_OWNED=0
release_ctl_lock() {
    if [ "$CTL_LOCK_OWNED" -eq 1 ]; then
        rm -rf "$CTL_LOCK_DIR" 2>/dev/null || true
        CTL_LOCK_OWNED=0
    fi
}

acquire_ctl_lock() {
    mkdir -p "$RUNTIME_DIR" 2>/dev/null
    cur_bid="$(get_runtime_boot_id)"
    waited=0
    while ! mkdir "$CTL_LOCK_DIR" 2>/dev/null; do
        if [ -f "$CTL_LOCK_DIR/pid" ] && [ -f "$CTL_LOCK_DIR/boot_id" ]; then
            l_pid="$(tr -d ' \t\r\n' < "$CTL_LOCK_DIR/pid" 2>/dev/null)"
            l_bid="$(tr -d ' \t\r\n' < "$CTL_LOCK_DIR/boot_id" 2>/dev/null)"
            if [ -n "$l_bid" ] && [ "$l_bid" != "$cur_bid" ]; then
                rm -rf "$CTL_LOCK_DIR" 2>/dev/null || true
                continue
            elif [ -n "$l_pid" ] && ! kill -0 "$l_pid" 2>/dev/null; then
                rm -rf "$CTL_LOCK_DIR" 2>/dev/null || true
                continue
            fi
        fi
        waited=$((waited + 1))
        if [ "$waited" -ge 15 ]; then
            log_msg "[LOCK_TIMEOUT] 已有并发控制任务持有锁 ($CTL_LOCK_DIR)，跳过本次操作"
            return 1
        fi
        sleep 1
    done
    CTL_LOCK_OWNED=1
    trap 'release_ctl_lock' EXIT INT TERM HUP
    printf '%s\n' "$cur_bid" > "$CTL_LOCK_DIR/boot_id" 2>/dev/null
    printf '%s\n' "$$" > "$CTL_LOCK_DIR/pid" 2>/dev/null
    return 0
}

load_config() {
    GUARD_MODE="hollow_26"
    BIND_PREEMPT_ENABLE=1
    SUSFS_AUTO_HIDE=0
    EXPECTED_UNAME="6.6.118-android15-8-o-g15bab650beb0-4k"
    FORCE_HOLLOW_SWAP=0
    EARLY_SWAP_ENABLE=1
    EARLY_SWAP_MODULES="inte oplus_secure_guard_new"
    HOLLOW_26_LIST="inte oplus_secure_guard_new oplus_patch oplus_network_data_module oplus_network_dns_hook oplus_network_qr_scan oplus_bsp_file_read_record oplus_bsp_dfr_theia oplus_network_dns_cache oplus_network_snapshot oplus_network_sk_predict oplus_network_vip_task oplus_network_linkpower_module oplus_network_score oplus_network_tcpdump_enhance oplus_network_app_monitor oplus_network_stats_calc oplus_bsp_midas mtk_mbraink mtk_mbraink_v6991 oplus_sys_stability_helper oplus_bsp_sigkill_diagnosis oplus_bsp_dfr_ubt oplus_network_dns_optimizer oplus_network_fast_bwe oplus_network_tuning"
    HOLLOW_23_LIST="$HOLLOW_26_LIST"
    STEP1_MODULES="oplus_bsp_dfr_ubt oplus_bsp_file_read_record oplus_bsp_sigkill_diagnosis oplus_bsp_midas"
    RMMOD_LIST="oplus_network_dns_cache oplus_network_sk_predict oplus_network_snapshot oplus_network_vip_task oplus_network_linkpower_module oplus_network_score oplus_network_tcpdump_enhance oplus_network_app_monitor oplus_network_stats_calc oplus_bsp_dfr_ubt oplus_bsp_midas oplus_sys_stability_helper oplus_bsp_sigkill_diagnosis mtk_mbraink_v6991 mtk_mbraink"
    HOLLOW_SWAP_LIST="inte oplus_secure_guard_new oplus_patch oplus_network_dns_hook oplus_network_qr_scan oplus_network_data_module oplus_bsp_file_read_record oplus_bsp_dfr_theia"
    CUSTOM_UNLOAD_MODULES=""
    PROTECT_MODULES=""
    RECHECK_DELAY_SEC=10
    PROBING_TIMEOUT=60

    if [ -f "$CONFIG" ]; then
        . "$CONFIG"
    fi
    # 兼容旧配置名 hollow_23 -> hollow_26
    [ "$GUARD_MODE" = "hollow_23" ] && GUARD_MODE="hollow_26"
    [ -z "$HOLLOW_26_LIST" ] && HOLLOW_26_LIST="$HOLLOW_23_LIST"
    ensure_runtime_session
}

trim_log() {
    if [ -f "$LOGFILE" ]; then
        lines=$(wc -l < "$LOGFILE" 2>/dev/null)
        if [ -n "$lines" ] && [ "$lines" -gt 500 ] 2>/dev/null; then
            tail -n 250 "$LOGFILE" > "$LOGFILE.tmp" && mv -f "$LOGFILE.tmp" "$LOGFILE"
        fi
    fi
}

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOGFILE"
}

norm_name() {
    echo "$1" | tr '-' '_'
}

is_in_list() {
    target="$1"
    for item in $2; do
        [ "$(norm_name "$item")" = "$target" ] && return 0
    done
    return 1
}

check_vermagic_ok() {
    [ "$FORCE_HOLLOW_SWAP" = "1" ] && return 0
    kver="$(uname -r 2>/dev/null)"
    [ "$kver" = "$EXPECTED_UNAME" ] && return 0
    return 1
}

manifest_get_field() {
    ko_base="$1"
    field="$2"
    sed -n "/\"$ko_base\":/,/}/p" "$MANIFEST_FILE" 2>/dev/null | sed -n "s/.*\"$field\":[[:space:]]*\"\([0-9a-fA-F]\{64\}\)\".*/\1/p" | head -n 1
}

find_vendor_ko() {
    fk_mod="$1"
    if [ -f "/vendor/lib/modules/${fk_mod}.ko" ]; then
        echo "/vendor/lib/modules/${fk_mod}.ko"
        return 0
    fi
    fk_dash="$(echo "$fk_mod" | tr '_' '-')"
    if [ -f "/vendor/lib/modules/${fk_dash}.ko" ]; then
        echo "/vendor/lib/modules/${fk_dash}.ko"
        return 0
    fi
    found=$(find /vendor/lib/modules /vendor_dlkm/lib/modules -maxdepth 3 \( -name "${fk_mod}.ko" -o -name "${fk_dash}.ko" \) 2>/dev/null | head -n 1)
    [ -n "$found" ] && echo "$found" && return 0
    return 1
}

is_path_mounted() {
    [ -n "$1" ] && grep -q " $1 " /proc/mounts 2>/dev/null
}

# 严格 Fail-Closed 硬门禁: vermagic + 架构 + 内核版本 + 空壳 SHA-256 + 设备原厂 stock_sha256
verify_hard_gate() {
    ko_file="$1"
    target_ko="$2"
    if [ ! -f "$ko_file" ]; then
        log_msg "[HARD_GATE] 拒绝: 空壳驱动文件不存在 ($ko_file)"
        return 1
    fi

    cur_rel="$(uname -r 2>/dev/null)"
    cur_arch="$(uname -m 2>/dev/null)"
    vm="$(strings "$ko_file" 2>/dev/null | grep "^vermagic=" | head -n 1 | cut -d= -f2- | tr -d '\r\n\t' | sed 's/ *$//')"
    if [ -z "$vm" ]; then
        vm="$(grep -a -o "vermagic=[ -~]*" "$ko_file" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '\r\n\t' | sed 's/ *$//')"
    fi
    if [ -z "$vm" ]; then
        vm="$(grep -a -o "vermagic=[^[:cntrl:]]*" "$ko_file" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '\r\n\t' | sed 's/ *$//')"
    fi
    if [ -z "$vm" ]; then
        log_msg "[HARD_GATE] 拒绝: 无法提取 vermagic ($ko_file)"
        return 2
    fi

    ko_rel=""
    ko_arch=""
    for tok in $vm; do
        [ -z "$ko_rel" ] && ko_rel="$tok"
        ko_arch="$tok"
    done

    if [ "$FORCE_HOLLOW_SWAP" != "1" ]; then
        if [ "$ko_arch" != "$cur_arch" ]; then
            log_msg "[HARD_GATE] 架构不匹配! 系统=$cur_arch, 驱动=$ko_arch ($ko_file)"
            return 3
        fi
        if [ "$ko_rel" != "$cur_rel" ]; then
            log_msg "[HARD_GATE] 内核版本不匹配! 系统=$cur_rel, 驱动=$ko_rel ($ko_file)"
            return 4
        fi
        if [ ! -f "$MANIFEST_FILE" ]; then
            log_msg "[HARD_GATE] 拒绝 (Fail-Closed): 缺少 manifest.json"
            return 5
        fi
        if ! command -v sha256sum >/dev/null 2>&1; then
            log_msg "[HARD_GATE] 拒绝 (Fail-Closed): 系统缺少 sha256sum，无法验证镜像完整性"
            return 5
        fi
    fi

    if [ -f "$MANIFEST_FILE" ] && command -v sha256sum >/dev/null 2>&1; then
        ko_base="${ko_file##*/}"
        nm="$(norm_name "${ko_base%.ko}")"
        expected_sha="$(manifest_get_field "$ko_base" "sha256")"
        expected_stock="$(manifest_get_field "$ko_base" "stock_sha256")"

        if [ -z "$expected_sha" ] || [ -z "$expected_stock" ]; then
            if [ "$FORCE_HOLLOW_SWAP" != "1" ]; then
                log_msg "[HARD_GATE] 拒绝: manifest.json 缺少 $ko_base 的双哈希记录"
                return 5
            fi
        else
            actual_sha=$(sha256sum "$ko_file" 2>/dev/null | cut -d' ' -f1)
            if [ "$expected_sha" != "$actual_sha" ]; then
                log_msg "[HARD_GATE] 空壳 SHA-256 完整性校验失败 ($ko_base)! 期望=$expected_sha, 实际=$actual_sha"
                return 5
            fi

            # 校验设备上对应原厂 .ko 的 stock_sha256，防止同内核版本不同固件构建间误加载
            [ -z "$target_ko" ] && target_ko=$(find_vendor_ko "$nm")
            if [ "$FORCE_HOLLOW_SWAP" != "1" ]; then
                if [ -z "$target_ko" ] || [ ! -f "$target_ko" ]; then
                    log_msg "[HARD_GATE] 拒绝: 设备上未找到对应原厂驱动 ($nm)，无法核验 stock_sha256"
                    return 6
                fi
                if is_path_mounted "$target_ko"; then
                    if [ ! -f "$STOCK_VERIFIED_DIR/$nm" ]; then
                        log_msg "[HARD_GATE] 拒绝: $target_ko 已被外部挂载且未经本次会话原厂哈希校验"
                        return 6
                    fi
                else
                    actual_stock=$(sha256sum "$target_ko" 2>/dev/null | cut -d' ' -f1)
                    if [ "$expected_stock" != "$actual_stock" ]; then
                        log_msg "[HARD_GATE] 原厂驱动 stock_sha256 不匹配 ($ko_base)! 期望=$expected_stock, 设备实际=$actual_stock"
                        return 6
                    fi
                    mkdir -p "$STOCK_VERIFIED_DIR" 2>/dev/null
                    printf '%s\n' "$actual_stock" > "$STOCK_VERIFIED_DIR/$nm" 2>/dev/null
                fi
            fi
        fi
    fi

    return 0
}

any_hollow_active() {
    for dir in "$SWAP_MARK_DIR" "$BOUND_MARK_DIR"; do
        if [ -d "$dir" ]; then
            for f in "$dir"/*; do
                [ -e "$f" ] && return 0
            done
        fi
    done
    return 1
}

query_proc_module() {
    q_mod="$(norm_name "$1")"
    MOD_LOADED=0
    MOD_SIZE=0
    MOD_REF=0
    MOD_USED="-"
    [ -r /proc/modules ] || return 1
    while IFS=' ' read -r m_name m_size m_ref m_used m_rest; do
        if [ "$(norm_name "$m_name")" = "$q_mod" ]; then
            MOD_LOADED=1
            MOD_SIZE="$m_size"
            MOD_REF="$m_ref"
            MOD_USED="${m_used%,}"
            [ -z "$MOD_USED" ] && MOD_USED="-"
            return 0
        fi
    done < /proc/modules
    return 1
}

find_susfs_bin() {
    if command -v ksu_susfs >/dev/null 2>&1; then
        command -v ksu_susfs
        return 0
    fi
    for p in /data/adb/ksu/bin/ksu_susfs /data/adb/ap/bin/ksu_susfs /data/adb/modules/susfs4ksu/tools/ksu_susfs /data/adb/susfs4ksu/ksu_susfs; do
        if [ -x "$p" ]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

record_mounted_target() {
    mp="$1"
    [ -z "$mp" ] && return 0
    mkdir -p "$RUNTIME_DIR" 2>/dev/null
    if [ ! -f "$MOUNTED_LIST_FILE" ] || ! grep -Fxq "$mp" "$MOUNTED_LIST_FILE" 2>/dev/null; then
        printf '%s\n' "$mp" >> "$MOUNTED_LIST_FILE" 2>/dev/null
    fi
}

# 安全卸载：绝不强杀任何用户态进程；模块忙碌时仅记录 BUSY 并跳过
unload_one() {
    raw_mod="$1"
    quiet_mode="$2"
    mod="$(norm_name "$raw_mod")"
    [ -z "$mod" ] && return 0

    if is_in_list "$mod" "$PROTECT_MODULES"; then
        [ "$quiet_mode" != "quiet" ] && log_msg "[PROTECT] $mod 在白名单中，跳过卸载"
        return 0
    fi

    query_proc_module "$mod"
    if [ "$MOD_LOADED" -eq 0 ]; then
        [ "$quiet_mode" != "quiet" ] && log_msg "[ABSENT] $mod 未在内核中加载"
        return 0
    fi

    if [ "$MOD_USED" != "-" ] || [ "$MOD_REF" -gt 0 ] 2>/dev/null; then
        log_msg "[BUSY] 跳过 $mod: 模块正被使用 (ref=$MOD_REF, used=$MOD_USED)，禁止强杀进程"
        return 1
    fi

    rm_out=$(rmmod "$mod" 2>&1)
    rm_rc=$?
    query_proc_module "$mod"
    if [ "$MOD_LOADED" -eq 0 ]; then
        rm -f "$SWAP_MARK_DIR/$mod" "$BOUND_MARK_DIR/$mod" 2>/dev/null
        log_msg "[RMMOD_OK] 已卸载监控驱动: $mod"
        return 0
    else
        log_msg "[RMMOD_FAIL] 卸载失败: $mod (rc=$rm_rc, ref=$MOD_REF, msg=$rm_out)"
        return 1
    fi
}

# 启动期 mount --bind 抢占覆盖（仅对尚未加载进内核的模块挂载，保留已加载模块原厂路径以支持安全回滚）
bind_preempt_one() {
    mod="$(norm_name "$1")"
    [ -z "$mod" ] && return 0

    if is_in_list "$mod" "$PROTECT_MODULES"; then
        log_msg "[PROTECT] $mod 在白名单中，跳过 mount --bind 抢占"
        return 0
    fi

    hollow_ko="$HOLLOW_DIR/${mod}.ko"
    if [ -f "${hollow_ko}.tripped" ] && [ ! -f "$hollow_ko" ]; then
        return 1
    fi

    target_ko=$(find_vendor_ko "$mod")
    if [ -z "$target_ko" ]; then
        return 0
    fi

    query_proc_module "$mod"
    if [ "$MOD_LOADED" -eq 1 ]; then
        # 已在 first_stage_init 提前进入内核：暂不覆写 target_ko，确保早期热替换失败时可恢复真正的原厂 .ko
        return 0
    fi

    if is_path_mounted "$target_ko"; then
        return 0
    fi

    if ! verify_hard_gate "$hollow_ko" "$target_ko"; then
        return 1
    fi

    mkdir -p "$BIND_STAGE_DIR" "$BOUND_MARK_DIR" 2>/dev/null
    susfs_bin=""
    [ "$SUSFS_AUTO_HIDE" = "1" ] && susfs_bin=$(find_susfs_bin 2>/dev/null)
    if ! is_path_mounted "$BIND_STAGE_DIR"; then
        if mount -t tmpfs -o mode=0755 tmpfs "$BIND_STAGE_DIR" 2>/dev/null; then
            record_mounted_target "$BIND_STAGE_DIR"
            [ -n "$susfs_bin" ] && "$susfs_bin" add_sus_mount "$BIND_STAGE_DIR" >/dev/null 2>&1 || true
        fi
    fi

    staged_ko="$BIND_STAGE_DIR/${mod}.ko"
    cp -f "$hollow_ko" "$staged_ko" || return 1
    chmod 0644 "$staged_ko" 2>/dev/null
    if ! chcon --reference="$target_ko" "$staged_ko" 2>/dev/null; then
        ref_ctx=$(ls -Z "$target_ko" 2>/dev/null | sed -n 's/.*\(u:object_r:[^:[:space:]]*:[^[:space:]]*\).*/\1/p' | head -n 1)
        if [ -n "$ref_ctx" ]; then
            chcon "$ref_ctx" "$staged_ko" 2>/dev/null || chcon u:object_r:vendor_file:s0 "$staged_ko" 2>/dev/null || true
        else
            chcon u:object_r:vendor_file:s0 "$staged_ko" 2>/dev/null || true
        fi
    fi

    if mount -o bind "$staged_ko" "$target_ko" 2>/dev/null; then
        record_mounted_target "$target_ko"
        [ -n "$susfs_bin" ] && "$susfs_bin" add_sus_mount "$target_ko" >/dev/null 2>&1 || true
        if [ -x "$CRASH_GUARD" ]; then
            if ! sh "$CRASH_GUARD" arm >/dev/null 2>&1; then
                umount "$target_ko" 2>/dev/null
                log_msg "[FUSE_ERROR] crash_guard 上膛失败，已撤销 $target_ko 挂载抢占"
                return 1
            fi
        fi
        date '+%s' > "$BOUND_MARK_DIR/$mod"
        log_msg "[BIND_PREEMPT] 已抢占挂载 $target_ko -> 空壳 $mod (待 vendor_modprobe 原生加载)"
        return 0
    else
        log_msg "[BIND_WARN] mount --bind 失败: $target_ko"
        return 1
    fi
}

# 回滚辅助：若目标路径曾被 bind-mount，先卸载挂载暴露真实原厂 .ko 再重载并验证 MOD_LOADED=1
rollback_stock_module() {
    rb_mod="$1"
    vpath=$(find_vendor_ko "$rb_mod")
    if [ -z "$vpath" ]; then
        log_msg "[ROLLBACK_FAIL] 未找到原厂模块路径，无法恢复 $rb_mod"
        return 1
    fi
    if is_path_mounted "$vpath"; then
        umount "$vpath" 2>/dev/null || umount -l "$vpath" 2>/dev/null
        rm -f "$BOUND_MARK_DIR/$rb_mod" 2>/dev/null
    fi
    rb_out=$(insmod "$vpath" 2>&1)
    rb_rc=$?
    query_proc_module "$rb_mod"
    if [ "$rb_rc" -eq 0 ] && [ "$MOD_LOADED" -eq 1 ]; then
        log_msg "[ROLLBACK_OK] 已验证恢复原厂模块: $rb_mod ($vpath)"
        return 0
    else
        log_msg "[ROLLBACK_FAIL] 恢复原厂 $rb_mod 失败 (rc=$rb_rc, loaded=$MOD_LOADED, msg=$rb_out)"
        return 1
    fi
}

restore_paused_deps() {
    deps_to_restore="$1"
    prefer_hollow="$2"
    for rdep in $deps_to_restore; do
        if [ "$prefer_hollow" = "1" ] && [ "$GUARD_MODE" = "hollow_26" ] && [ -f "$HOLLOW_DIR/${rdep}.ko" ]; then
            r_vpath=$(find_vendor_ko "$rdep")
            if verify_hard_gate "$HOLLOW_DIR/${rdep}.ko" "$r_vpath"; then
                if insmod "$HOLLOW_DIR/${rdep}.ko" >> "$LOGFILE" 2>&1; then
                    mkdir -p "$SWAP_MARK_DIR" 2>/dev/null
                    date '+%s' > "$SWAP_MARK_DIR/$rdep"
                    log_msg "[DEP_HOLLOW_RESTORE] 已以空壳版恢复下游模块: $rdep"
                    continue
                fi
            fi
        fi
        rpath=$(find_vendor_ko "$rdep")
        if [ -n "$rpath" ]; then
            if insmod "$rpath" >> "$LOGFILE" 2>&1; then
                log_msg "[DEP_RESTORE] 已恢复下游模块: $rdep"
            else
                log_msg "[DEP_RESTORE_WARN] 恢复下游模块 $rdep 失败 ($rpath)"
            fi
        fi
    done
}

# 安全热替换（绝不杀进程；无论 early 或 boot 模式，空壳失败均强制回滚并验证原厂恢复）
swap_one_hollow() {
    raw_mod="$1"
    quiet_mode="$2"
    early_mode="$3"
    mod="$(norm_name "$raw_mod")"
    [ -z "$mod" ] && return 0

    if is_in_list "$mod" "$PROTECT_MODULES"; then
        [ "$quiet_mode" != "quiet" ] && log_msg "[PROTECT] $mod 在白名单中，跳过空壳替换"
        return 0
    fi

    if [ -x "$CRASH_GUARD" ]; then
        if ! sh "$CRASH_GUARD" allow-load >/dev/null 2>&1; then
            [ "$quiet_mode" != "quiet" ] && log_msg "[FUSE_BLOCKED] crash_guard 处于熔断锁定状态，禁止加载 $mod"
            return 1
        fi
    fi

    hollow_ko="$HOLLOW_DIR/${mod}.ko"
    if [ -f "${hollow_ko}.tripped" ] && [ ! -f "$hollow_ko" ]; then
        [ "$quiet_mode" != "quiet" ] && log_msg "[FUSE_TRIPPED] $mod 已被物理锁定为 .ko.tripped"
        return 1
    fi

    if [ "$early_mode" = "early" ] && [ "$mod" = "oplus_secure_guard_new" ]; then
        if ! grep -q "^oplusboot " /proc/modules 2>/dev/null; then
            log_msg "[EARLY_DEFER] oplusboot 尚未加载，推迟 oplus_secure_guard_new 到 service 阶段"
            return 0
        fi
    fi

    target_ko=$(find_vendor_ko "$mod")
    query_proc_module "$mod"
    if [ "$MOD_LOADED" -eq 1 ]; then
        if [ -f "$SWAP_MARK_DIR/$mod" ]; then
            [ "$quiet_mode" != "quiet" ] && log_msg "[ALREADY_HOLLOW] $mod 已处于空壳热替换状态"
            return 0
        fi
        if [ -f "$BOUND_MARK_DIR/$mod" ] && is_path_mounted "$target_ko"; then
            [ "$quiet_mode" != "quiet" ] && log_msg "[ALREADY_HOLLOW] $mod 已处于抢占挂载空壳状态"
            return 0
        fi
    fi

    if ! verify_hard_gate "$hollow_ko" "$target_ko"; then
        return 1
    fi

    # 暂停下游内核依赖模块
    saved_deps=""
    if [ "$MOD_LOADED" -eq 1 ] && [ "$MOD_USED" != "-" ]; then
        deps_space=$(echo "$MOD_USED" | tr ',' ' ')
        for dep in $deps_space; do
            dep_norm="$(norm_name "$dep")"
            [ -z "$dep_norm" ] && continue
            d_err=$(rmmod "$dep_norm" 2>&1)
            if [ $? -eq 0 ]; then
                log_msg "[DEP_PAUSE] 临时卸载依赖模块 $dep_norm (以释放 $mod)"
                if [ "$GUARD_MODE" = "hollow_26" ] || ! is_in_list "$dep_norm" "$RMMOD_LIST $CUSTOM_UNLOAD_MODULES"; then
                    saved_deps="$saved_deps $dep_norm"
                fi
            else
                log_msg "[DEP_FAIL] 无法卸载依赖模块 $dep_norm ($d_err)，中止 $mod 热替换并恢复已暂停依赖"
                restore_paused_deps "$saved_deps" "0"
                return 1
            fi
        done
    fi

    # 暂停依赖后重新查询：若仍存在用户态文件描述符引用 (ref > 0)，绝不强杀进程，立即回滚依赖并跳过
    query_proc_module "$mod"
    if [ "$MOD_LOADED" -eq 1 ] && [ "$MOD_REF" -gt 0 ] 2>/dev/null; then
        log_msg "[BUSY] 跳过 $mod 热替换: 存在用户态活动句柄 (ref=$MOD_REF, used=$MOD_USED)，禁止强杀系统进程"
        restore_paused_deps "$saved_deps" "0"
        return 1
    fi

    did_rmmod=0
    if [ "$MOD_LOADED" -eq 1 ]; then
        rm_out=$(rmmod "$mod" 2>&1)
        query_proc_module "$mod"
        if [ "$MOD_LOADED" -eq 1 ]; then
            log_msg "[SWAP_FAIL] 卸载原厂 $mod 失败 ($rm_out)，恢复已暂停依赖"
            restore_paused_deps "$saved_deps" "0"
            return 1
        fi
        did_rmmod=1
    fi

    if [ -x "$CRASH_GUARD" ]; then
        if ! sh "$CRASH_GUARD" arm >/dev/null 2>&1; then
            log_msg "[FUSE_ERROR] crash_guard 上膛失败，安全回滚恢复原厂 $mod"
            [ "$did_rmmod" -eq 1 ] && rollback_stock_module "$mod"
            restore_paused_deps "$saved_deps" "0"
            return 1
        fi
    fi

    ins_out=$(insmod "$hollow_ko" 2>&1)
    ins_rc=$?
    query_proc_module "$mod"
    if [ "$ins_rc" -eq 0 ] && [ "$MOD_LOADED" -eq 1 ]; then
        mkdir -p "$SWAP_MARK_DIR" 2>/dev/null
        date '+%s' > "$SWAP_MARK_DIR/$mod"
        log_msg "[HOLLOW_OK] 已换入空壳绿灯驱动: $mod"
        restore_paused_deps "$saved_deps" "1"
        return 0
    else
        log_msg "[HOLLOW_FAIL] 载入空壳 $mod 失败 (rc=$ins_rc: $ins_out)"
        if [ -x "$CRASH_GUARD" ] && ! any_hollow_active; then
            sh "$CRASH_GUARD" abort-probe "insmod $mod 失败 (rc=$ins_rc)" >/dev/null 2>&1
        fi
        # 无论 early 还是 boot 模式，只要已卸载原厂模块，必须执行并验证原厂回滚
        if [ "$did_rmmod" -eq 1 ]; then
            rollback_stock_module "$mod"
        fi
        restore_paused_deps "$saved_deps" "0"
        return 1
    fi
}

ensure_watchdog() {
    if [ -x "$CRASH_GUARD" ] && any_hollow_active; then
        cg_state=$(sh "$CRASH_GUARD" status 2>/dev/null | sed -n 's/.*"state":"\([^"]*\)".*/\1/p')
        if [ "$cg_state" = "PROBING" ]; then
            sh "$CRASH_GUARD" watchdog "${PROBING_TIMEOUT:-60}" >/dev/null 2>&1 &
        fi
    fi
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n\r' '  '
}

generate_status_json() {
    load_config
    kver="$(uname -r 2>/dev/null)"
    karch="$(uname -m 2>/dev/null)"
    ts="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    vm_ok="false"
    check_vermagic_ok && vm_ok="true"

    cg_state="UNKNOWN"
    cg_fail=0
    cg_max_fail=2
    cg_wd="false"
    cg_bid=""
    cg_br=""
    cg_reason=""
    if [ -x "$CRASH_GUARD" ]; then
        cg_raw=$(sh "$CRASH_GUARD" status 2>/dev/null)
        s_tmp=$(printf '%s' "$cg_raw" | sed -n 's/.*"state":"\([^"]*\)".*/\1/p')
        [ -n "$s_tmp" ] && cg_state="$s_tmp"
        f_tmp=$(printf '%s' "$cg_raw" | sed -n 's/.*"fail_count":\([0-9]*\).*/\1/p')
        [ -n "$f_tmp" ] && cg_fail="$f_tmp"
        mf_tmp=$(printf '%s' "$cg_raw" | sed -n 's/.*"max_fail":\([0-9]*\).*/\1/p')
        [ -n "$mf_tmp" ] && cg_max_fail="$mf_tmp"
        w_tmp=$(printf '%s' "$cg_raw" | sed -n 's/.*"watchdog_alive":\([a-z]*\).*/\1/p')
        [ -n "$w_tmp" ] && cg_wd="$w_tmp"
        cg_bid=$(printf '%s' "$cg_raw" | sed -n 's/.*"current_boot_id":"\([^"]*\)".*/\1/p')
        cg_br=$(printf '%s' "$cg_raw" | sed -n 's/.*"boot_reason":"\([^"]*\)".*/\1/p')
        cg_reason=$(printf '%s' "$cg_raw" | sed -n 's/.*"trip_reason":"\([^"]*\)".*/\1/p')
    fi

    tripped_cnt=0
    for tk in "$HOLLOW_DIR"/*.ko.tripped; do
        [ -e "$tk" ] && tripped_cnt=$((tripped_cnt + 1))
    done

    proc_mods=""
    [ -r /proc/modules ] && proc_mods="$(cat /proc/modules 2>/dev/null)"

    hollow26_total=0
    hollow26_online=0
    bind_count=0
    stock_verified_count=0
    for m in $HOLLOW_26_LIST; do
        hollow26_total=$((hollow26_total + 1))
        nm="$(norm_name "$m")"
        tko=$(find_vendor_ko "$nm")
        [ -f "$STOCK_VERIFIED_DIR/$nm" ] && stock_verified_count=$((stock_verified_count + 1))
        m_is_bound=0
        if [ -f "$BOUND_MARK_DIR/$nm" ] && is_path_mounted "$tko"; then
            m_is_bound=1
            bind_count=$((bind_count + 1))
        fi
        if echo "$proc_mods" | grep -q "^${nm} " && { [ -f "$SWAP_MARK_DIR/$nm" ] || [ "$m_is_bound" -eq 1 ]; }; then
            hollow26_online=$((hollow26_online + 1))
        fi
    done

    step1_total=0
    step1_cleared=0
    for m in $STEP1_MODULES; do
        step1_total=$((step1_total + 1))
        nm="$(norm_name "$m")"
        if ! echo "$proc_mods" | grep -q "^${nm} "; then
            step1_cleared=$((step1_cleared + 1))
        fi
    done

    rmmod_total=0
    rmmod_cleared=0
    for m in $RMMOD_LIST; do
        rmmod_total=$((rmmod_total + 1))
        nm="$(norm_name "$m")"
        if ! echo "$proc_mods" | grep -q "^${nm} "; then
            rmmod_cleared=$((rmmod_cleared + 1))
        fi
    done

    hollow_total=0
    hollow_online=0
    for m in $HOLLOW_SWAP_LIST; do
        hollow_total=$((hollow_total + 1))
        nm="$(norm_name "$m")"
        tko=$(find_vendor_ko "$nm")
        if echo "$proc_mods" | grep -q "^${nm} " && { [ -f "$SWAP_MARK_DIR/$nm" ] || { [ -f "$BOUND_MARK_DIR/$nm" ] && is_path_mounted "$tko"; }; }; then
            hollow_online=$((hollow_online + 1))
        fi
    done

    mod_json=""
    first=1
    for m in $ALL_TRACKED_MODULES; do
        nm="$(norm_name "$m")"
        line=$(echo "$proc_mods" | grep "^${nm} " | head -n 1)
        tko=$(find_vendor_ko "$nm")
        m_swapped="false"
        m_bound="false"
        m_mount_active="false"
        m_stock_ver="false"
        [ -f "$STOCK_VERIFIED_DIR/$nm" ] && m_stock_ver="true"
        if is_path_mounted "$tko"; then
            m_mount_active="true"
            [ -f "$BOUND_MARK_DIR/$nm" ] && m_bound="true"
        fi
        if [ -n "$line" ]; then
            set -- $line
            m_loaded="true"
            m_size="${2:-0}"
            m_ref="${3:-0}"
            m_used="${4%,}"
            [ -z "$m_used" ] && m_used="-"
            if [ -f "$SWAP_MARK_DIR/$nm" ] || [ "$m_bound" = "true" ]; then
                m_swapped="true"
            fi
        else
            m_loaded="false"
            m_size="0"
            m_ref="0"
            m_used="-"
        fi
        [ "$first" -eq 0 ] && mod_json="${mod_json},"
        first=0
        mod_json="${mod_json}{\"name\":\"$nm\",\"loaded\":$m_loaded,\"swapped\":$m_swapped,\"bound\":$m_bound,\"mount_active\":$m_mount_active,\"stock_verified\":$m_stock_ver,\"size\":$m_size,\"ref\":$m_ref,\"used_by\":\"$(json_escape "$m_used")\"}"
    done

    node_json=""
    nfirst=1
    for p in $MONITOR_NODES; do
        if [ -e "$p" ]; then
            ex="true"
            prev=""
            if [ -d "$p" ]; then
                prev="dir(ok)"
            elif [ -r "$p" ] && [ "$p" != "/dev/midas_dev" ] && [ "$p" != "/dev/mbraink" ] && [ "$p" != "/proc/kprobe_ctl" ]; then
                prev=$(head -n 2 "$p" 2>/dev/null)
            fi
        else
            ex="false"
            prev=""
        fi
        [ "$nfirst" -eq 0 ] && node_json="${node_json},"
        nfirst=0
        node_json="${node_json}{\"path\":\"$p\",\"exists\":$ex,\"preview\":\"$(json_escape "$prev")\"}"
    done

    sus_json="\"$(json_escape "$BIND_STAGE_DIR")\""
    for m in $HOLLOW_26_LIST; do
        nm="$(norm_name "$m")"
        tko=$(find_vendor_ko "$nm")
        [ -z "$tko" ] && tko="/vendor/lib/modules/${nm}.ko"
        sus_json="${sus_json},\"$(json_escape "$tko")\""
    done

    sus_auto="false"
    [ "$SUSFS_AUTO_HIDE" = "1" ] && sus_auto="true"

    printf '{"guard_mode":"%s","kernel_release":"%s","kernel_arch":"%s","vermagic_match":%s,"stock_verified_count":%d,"susfs_auto_hide":%s,"timestamp":"%s","cg_state":"%s","cg_fail_count":%s,"cg_max_fail":%s,"cg_watchdog_alive":%s,"cg_boot_id":"%s","cg_boot_reason":"%s","cg_reason":"%s","tripped_ko_count":%d,"hollow26_total":%d,"hollow26_online":%d,"hollow23_total":%d,"hollow23_online":%d,"bind_count":%d,"step1_total":%d,"step1_cleared":%d,"rmmod_total":%d,"rmmod_cleared":%d,"hollow_total":%d,"hollow_online":%d,"modules":[%s],"nodes":[%s],"sus_paths":[%s]}\n' \
        "$(json_escape "${GUARD_MODE:-hollow_26}")" \
        "$(json_escape "$kver")" \
        "$(json_escape "$karch")" \
        "$vm_ok" \
        "$stock_verified_count" \
        "$sus_auto" \
        "$(json_escape "$ts")" \
        "$(json_escape "$cg_state")" \
        "$cg_fail" \
        "$cg_max_fail" \
        "$cg_wd" \
        "$(json_escape "$cg_bid")" \
        "$(json_escape "$cg_br")" \
        "$(json_escape "$cg_reason")" \
        "$tripped_cnt" \
        "$hollow26_total" \
        "$hollow26_online" \
        "$hollow26_total" \
        "$hollow26_online" \
        "$bind_count" \
        "$step1_total" \
        "$step1_cleared" \
        "$rmmod_total" \
        "$rmmod_cleared" \
        "$hollow_total" \
        "$hollow_online" \
        "$mod_json" \
        "$node_json" \
        "$sus_json"
}

cmd_sus_paths() {
    load_config
    printf '%s\n' "$BIND_STAGE_DIR"
    for m in $HOLLOW_26_LIST; do
        nm="$(norm_name "$m")"
        tko=$(find_vendor_ko "$nm")
        [ -z "$tko" ] && tko="/vendor/lib/modules/${nm}.ko"
        printf '%s\n' "$tko"
    done
}

cmd_early_preempt() {
    load_config
    [ "$GUARD_MODE" = "step1_only" ] && return 0
    if [ -x "$CRASH_GUARD" ]; then
        if ! sh "$CRASH_GUARD" allow-load >/dev/null 2>&1; then
            return 0
        fi
    fi

    acquire_ctl_lock || return 0
    trim_log
    log_msg "=== [post-fs-data] 启动期抢占与早期防护开始 (mode=$GUARD_MODE) ==="

    if [ "$GUARD_MODE" = "hollow_26" ]; then
        if [ "$BIND_PREEMPT_ENABLE" = "1" ]; then
            for m in $HOLLOW_26_LIST; do
                bind_preempt_one "$m"
            done
        fi
        # 若有模块在 first_stage_init 已提前加载，则在用户态守护启动前执行早期替换（含完整原厂回滚验证）
        for m in $HOLLOW_26_LIST; do
            nm="$(norm_name "$m")"
            query_proc_module "$nm"
            if [ "$MOD_LOADED" -eq 1 ] && [ ! -f "$BOUND_MARK_DIR/$nm" ] && [ ! -f "$SWAP_MARK_DIR/$nm" ]; then
                swap_one_hollow "$nm" "" "early"
            fi
        done
    else
        if [ "$EARLY_SWAP_ENABLE" = "1" ]; then
            for m in $EARLY_SWAP_MODULES; do
                swap_one_hollow "$m" "" "early"
            done
        fi
    fi
    release_ctl_lock
}

cmd_apply() {
    quiet_mode="$1"
    load_config
    acquire_ctl_lock || return 1
    trim_log

    if [ "$quiet_mode" != "quiet" ]; then
        log_msg "================================================="
        log_msg "执行 OPlus Kernel Guard v3.1.0 策略 (mode=$GUARD_MODE)"
    fi

    if [ "$GUARD_MODE" = "hollow_26" ]; then
        for m in $HOLLOW_26_LIST; do
            nm="$(norm_name "$m")"
            tko=$(find_vendor_ko "$nm")
            query_proc_module "$nm"
            if [ "$MOD_LOADED" -eq 1 ]; then
                if [ -f "$SWAP_MARK_DIR/$nm" ] || { [ -f "$BOUND_MARK_DIR/$nm" ] && is_path_mounted "$tko"; }; then
                    [ "$quiet_mode" != "quiet" ] && log_msg "[GREEN_OK] $nm 已为空壳驻留态 (mount_active=$(is_path_mounted "$tko" && echo 1 || echo 0), stock_verified=$([ -f "$STOCK_VERIFIED_DIR/$nm" ] && echo 1 || echo 0))"
                else
                    swap_one_hollow "$nm" "$quiet_mode" "boot"
                fi
            else
                [ "$quiet_mode" != "quiet" ] && log_msg "[ABSENT] $nm 当前未在内核加载"
            fi
        done
        ensure_watchdog
    elif [ "$GUARD_MODE" = "step1_only" ]; then
        for m in $STEP1_MODULES $CUSTOM_UNLOAD_MODULES; do
            unload_one "$m" "$quiet_mode"
        done
    else
        for m in $RMMOD_LIST $CUSTOM_UNLOAD_MODULES; do
            unload_one "$m" "$quiet_mode"
        done
        for m in $HOLLOW_SWAP_LIST; do
            swap_one_hollow "$m" "$quiet_mode" "boot"
        done
        ensure_watchdog
    fi

    generate_status_json > "$STATUSFILE"
    if [ "$quiet_mode" != "quiet" ]; then
        log_msg "策略执行完毕"
    fi
    release_ctl_lock
}

case "$1" in
    early_preempt|early_swap)
        cmd_early_preempt
        ;;
    apply)
        cmd_apply "$2"
        ;;
    unload_single)
        load_config
        acquire_ctl_lock || exit 1
        trim_log
        rc=0
        if [ -n "$2" ]; then
            unload_one "$2" ""
            rc=$?
            generate_status_json > "$STATUSFILE"
        fi
        release_ctl_lock
        exit "$rc"
        ;;
    swap_single)
        load_config
        acquire_ctl_lock || exit 1
        trim_log
        rc=0
        if [ -n "$2" ]; then
            swap_one_hollow "$2" "" "boot"
            rc=$?
            ensure_watchdog
            generate_status_json > "$STATUSFILE"
        fi
        release_ctl_lock
        exit "$rc"
        ;;
    status_json)
        generate_status_json
        ;;
    sus_paths)
        cmd_sus_paths
        ;;
    *)
        echo "Usage: $0 {early_preempt|apply [quiet]|unload_single <mod>|swap_single <mod>|status_json|sus_paths}"
        exit 1
        ;;
esac
```

### 9.9 `crash_guard/crash_guard.sh`

```sh
#!/system/bin/sh
# ==============================================================================
# OPlus Kernel Guard - 跨 Boot 防无限重启熔断器 (crash_guard)
#
# 五层防无限重启架构:
#   1. 真正 36 位 UUID Boot ID 校验 (/proc/sys/kernel/random/boot_id)
#   2. insmod 失败主动回滚 (abort-probe)，不计入崩溃次数
#   3. 状态机校验 (NORMAL|PROBING|TRIPPED) 与损坏自愈/锁定兜底
#   4. 原子落盘 (tmp + sync + mv + sync) 与目录并发锁 (含陈旧锁所有权证明)
#   5. 单例 60 秒后台看门狗 (watchdog) + 双目录持久化防重装擦除
# ==============================================================================

CG_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
[ -z "$CG_DIR" ] && CG_DIR="${0%/*}"
[ "$CG_DIR" = "$0" ] && CG_DIR="."
BASE_DIR="$(cd "${CG_DIR}/.." 2>/dev/null && pwd)"
[ -z "$BASE_DIR" ] && BASE_DIR="${CG_DIR}/.."

export PATH="/system/bin:/system/xbin:/vendor/bin:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"
GUARD_ID="${GUARD_ID:-oplus_kernel_guard}"
STATE_DIR="${BASE_DIR}/.crash_guard"
EXT_GUARD_DIR="${EXT_GUARD_DIR:-/data/adb/${GUARD_ID}_guard}"
mkdir -p "$STATE_DIR" "$EXT_GUARD_DIR" 2>/dev/null

STATE_FILE="${STATE_DIR}/state"
EXT_STATE_FILE="${EXT_GUARD_DIR}/state"
BOOT_ID_FILE="${STATE_DIR}/last_boot_id"
EXT_BOOT_ID_FILE="${EXT_GUARD_DIR}/last_boot_id"
FAIL_CNT_FILE="${STATE_DIR}/fail_count"
EXT_FAIL_CNT_FILE="${EXT_GUARD_DIR}/fail_count"
REASON_FILE="${STATE_DIR}/trip_reason"
EXT_REASON_FILE="${EXT_GUARD_DIR}/trip_reason"
LOG_FILE="${STATE_DIR}/guard.log"
LOCK_DIR="${STATE_DIR}/.guard_lock"
WATCHDOG_PID_FILE="${STATE_DIR}/watchdog.pid"
WATCHDOG_BOOT_FILE="${STATE_DIR}/watchdog.boot_id"
WATCHDOG_LOCK_DIR="${STATE_DIR}/watchdog.lock"

MAX_FAIL="${MAX_FAIL:-2}"
PROBING_TIMEOUT="${PROBING_TIMEOUT:-60}"

log_msg() {
    ts="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo '0000-00-00 00:00:00')"
    msg="[$ts][crash_guard] $*"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null
    echo "$msg" >> "${EXT_GUARD_DIR}/guard.log" 2>/dev/null
    echo "[crash_guard] $*"
}

is_valid_uuid() {
    val="$1"
    [ -z "$val" ] && return 1
    len=$(printf '%s' "$val" | wc -c | tr -d ' ')
    [ "$len" -ne 36 ] && return 1
    case "$val" in
        ????????-????-????-????-????????????) return 0 ;;
        *) return 1 ;;
    esac
}

get_system_boot_id() {
    raw_id=""
    if [ -r /proc/sys/kernel/random/boot_id ]; then
        raw_id="$(tr -d '\r\n ' < /proc/sys/kernel/random/boot_id 2>/dev/null)"
    fi

    if is_valid_uuid "$raw_id"; then
        printf '%s' "$raw_id"
        return 0
    fi

    if [ -r /proc/stat ]; then
        while IFS=' ' read -r k v rest; do
            if [ "$k" = "btime" ] && [ -n "$v" ]; then
                printf 'btime_%s' "$v"
                return 0
            fi
        done < /proc/stat
    fi

    printf 'boot_fallback_%s' "$(date +%Y%m%d%H%M%S 2>/dev/null || echo 0)"
}

atomic_write_file() {
    target_file="$1"
    content="$2"
    dir="${target_file%/*}"
    mkdir -p "$dir" 2>/dev/null
    tmp_file="${target_file}.tmp.$$"

    if ! printf '%s\n' "$content" > "$tmp_file" 2>/dev/null; then
        log_msg "【错误】无法写入临时状态文件: $tmp_file"
        rm -f "$tmp_file" 2>/dev/null
        return 1
    fi

    sync 2>/dev/null
    if ! mv -f "$tmp_file" "$target_file" 2>/dev/null; then
        log_msg "【错误】原子重命名失败: $tmp_file -> $target_file"
        rm -f "$tmp_file" 2>/dev/null
        return 1
    fi

    sync 2>/dev/null
    return 0
}

LOCK_OWNED=0
cleanup_owned_lock() {
    if [ "$LOCK_OWNED" -eq 1 ]; then
        rm -rf "$LOCK_DIR" 2>/dev/null || true
        LOCK_OWNED=0
    fi
}

acquire_lock() {
    wait_time=0
    cur_bid="$(get_system_boot_id)"
    while ! mkdir "$LOCK_DIR" 2>/dev/null; do
        if [ -f "$LOCK_DIR/pid" ] && [ -f "$LOCK_DIR/boot_id" ]; then
            l_pid="$(tr -d ' \t\r\n' < "$LOCK_DIR/pid" 2>/dev/null)"
            l_bid="$(tr -d ' \t\r\n' < "$LOCK_DIR/boot_id" 2>/dev/null)"
            if [ -n "$l_bid" ] && [ "$l_bid" != "$cur_bid" ]; then
                rm -rf "$LOCK_DIR" 2>/dev/null || true
                continue
            elif [ -n "$l_pid" ] && ! kill -0 "$l_pid" 2>/dev/null; then
                rm -rf "$LOCK_DIR" 2>/dev/null || true
                continue
            fi
        fi
        wait_time=$((wait_time + 1))
        if [ "$wait_time" -ge 10 ]; then
            log_msg "【错误】获取状态锁超时 ($LOCK_DIR 仍由活动进程持有)"
            return 1
        fi
        sleep 1
    done
    LOCK_OWNED=1
    trap 'cleanup_owned_lock' EXIT INT TERM HUP
    atomic_write_file "$LOCK_DIR/boot_id" "$cur_bid"
    atomic_write_file "$LOCK_DIR/pid" "$$"
    return 0
}

release_lock() {
    if [ "$LOCK_OWNED" -eq 1 ]; then
        rm -rf "$LOCK_DIR" 2>/dev/null || true
        LOCK_OWNED=0
    fi
}

validate_state_string() {
    case "$1" in
        NORMAL|PROBING|TRIPPED) return 0 ;;
        *) return 1 ;;
    esac
}

get_state() {
    s=""
    if [ -f "$STATE_FILE" ]; then
        s="$(tr -d '\r\n ' < "$STATE_FILE" 2>/dev/null)"
    fi

    if validate_state_string "$s"; then
        printf '%s' "$s"
        return 0
    fi

    if [ -f "$EXT_STATE_FILE" ]; then
        s="$(tr -d '\r\n ' < "$EXT_STATE_FILE" 2>/dev/null)"
        if validate_state_string "$s"; then
            log_msg "[自愈] 从外部持久文件恢复状态: $s"
            atomic_write_file "$STATE_FILE" "$s"
            printf '%s' "$s"
            return 0
        fi
    fi

    atomic_write_file "$STATE_FILE" "TRIPPED"
    atomic_write_file "$EXT_STATE_FILE" "TRIPPED" 2>/dev/null || true
    atomic_write_file "$REASON_FILE" "状态文件损坏或非法($s)，已持久化锁定为 TRIPPED" 2>/dev/null || true
    atomic_write_file "$EXT_REASON_FILE" "状态文件损坏或非法($s)，已持久化锁定为 TRIPPED" 2>/dev/null || true
    log_msg "【警告】检测到状态文件损坏或非法($s)，已持久化锁定为 TRIPPED！"
    printf 'TRIPPED'
    return 2
}

set_state() {
    new_s="$1"
    if ! validate_state_string "$new_s"; then
        log_msg "【错误】拒绝写入非法状态值: $new_s"
        return 1
    fi
    atomic_write_file "$STATE_FILE" "$new_s" || return 1
    atomic_write_file "$EXT_STATE_FILE" "$new_s" 2>/dev/null || true
    return 0
}

get_fail_count() {
    fc=""
    [ -f "$FAIL_CNT_FILE" ] && fc="$(tr -d '\r\n ' < "$FAIL_CNT_FILE" 2>/dev/null)"
    case "$fc" in
        ''|*[!0-9]*)
            [ -f "$EXT_FAIL_CNT_FILE" ] && fc="$(tr -d '\r\n ' < "$EXT_FAIL_CNT_FILE" 2>/dev/null)"
            ;;
    esac
    case "$fc" in
        ''|*[!0-9]*) printf '0' ;;
        *) printf '%s' "$fc" ;;
    esac
}

set_fail_count() {
    atomic_write_file "$FAIL_CNT_FILE" "$1"
    atomic_write_file "$EXT_FAIL_CNT_FILE" "$1" 2>/dev/null || true
}

trip_fuse() {
    reason="$1"
    [ -z "$reason" ] && reason="跨 Boot 监测到内核崩溃或看门狗异常触发"

    acquire_lock
    set_state "TRIPPED"
    atomic_write_file "$REASON_FILE" "$reason"
    atomic_write_file "$EXT_REASON_FILE" "$reason" 2>/dev/null || true
    release_lock

    log_msg "【!!! 跨 Boot 物理熔断器跳闸 !!!】已永久阻断空壳驱动加载。原因: $reason"

    for ko in "${BASE_DIR}"/*.ko "${BASE_DIR}/hollow_modules"/*.ko "${BASE_DIR}/driver_manager"/*.ko "${BASE_DIR}/driver_manager/kernels"/*.ko; do
        if [ -f "$ko" ] && [ "${ko%.tripped}" = "$ko" ]; then
            mv -f "$ko" "${ko}.tripped" 2>/dev/null
            log_msg "  -> 驱动物理锁定: $ko -> ${ko}.tripped"
        fi
    done
}

get_boot_reason() {
    br=""
    if command -v getprop >/dev/null 2>&1; then
        br="$(getprop sys.boot.reason 2>/dev/null | tr -d '\r\n ')"
        [ -z "$br" ] && br="$(getprop ro.boot.bootreason 2>/dev/null | tr -d '\r\n ')"
    fi
    if [ -z "$br" ] && [ -r /proc/cmdline ]; then
        br="$(sed -n 's/.*androidboot\.bootreason=\([^[:space:]]*\).*/\1/p' /proc/cmdline 2>/dev/null | head -n 1 | tr -d '\r\n ')"
    fi
    [ -z "$br" ] && br="unknown"
    printf '%s' "$br"
}

is_crash_boot_reason() {
    r_low="$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
    case "$r_low" in
        *panic*|*watchdog*|*wdog*|*hang*|*hw_reset*|*crash*|*fatal*|*dm-verity*|*ocp*|*rpm_err*|*tz_err*|*ap_wdt*|*ke_*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

check_boot() {
    acquire_lock || return 1
    cur_state="$(get_state)"
    cur_boot_id="$(get_system_boot_id)"
    last_boot_id="$(tr -d '\r\n ' < "$BOOT_ID_FILE" 2>/dev/null)"
    [ -z "$last_boot_id" ] && last_boot_id="$(tr -d '\r\n ' < "$EXT_BOOT_ID_FILE" 2>/dev/null)"
    fail_count="$(get_fail_count)"
    boot_reason="$(get_boot_reason)"
    release_lock

    log_msg "跨 Boot 熔断自检: 状态=$cur_state, 失败计数=$fail_count/$MAX_FAIL, 启动原因=$boot_reason, 当前BootID=$cur_boot_id, 记录BootID=$last_boot_id"

    if [ "$cur_state" = "TRIPPED" ]; then
        reason="$(cat "$REASON_FILE" 2>/dev/null || cat "$EXT_REASON_FILE" 2>/dev/null || echo '未知原因')"
        log_msg "【熔断器处于锁定状态】禁止空壳驱动加载！熔断原因: $reason"
        return 1
    fi

    if [ "$cur_state" = "PROBING" ]; then
        if [ -n "$last_boot_id" ] && [ "$last_boot_id" != "$cur_boot_id" ]; then
            fail_count=$((fail_count + 1))
            set_fail_count "$fail_count"

            if is_crash_boot_reason "$boot_reason"; then
                log_msg "【重大安全事件】检测到异常崩溃重启 (reason=$boot_reason, BootID: ${last_boot_id} -> ${cur_boot_id})！"
                trip_fuse "检测到异常内核/硬件崩溃重启 (reason=${boot_reason}, BootID: ${last_boot_id} -> ${cur_boot_id})"
                return 1
            fi

            if [ "$fail_count" -ge "$MAX_FAIL" ]; then
                log_msg "【重大安全事件】连续 ${fail_count} 次在观察期内发生重启 (reason=$boot_reason, BootID: ${last_boot_id} -> ${cur_boot_id})！"
                trip_fuse "连续 ${fail_count} 次未完成 ${PROBING_TIMEOUT}s 观察期即重启 (reason=${boot_reason}, BootID: ${last_boot_id} -> ${cur_boot_id})"
                return 1
            fi

            log_msg "【警告】观察期内发生非崩溃类重启 (reason=$boot_reason, fail_count=${fail_count}/${MAX_FAIL})，不立即跳闸；下一次观察期仍异常将触发锁定"
            acquire_lock && set_state "NORMAL" && release_lock
            return 0
        else
            log_msg "同一 Boot 会话内重复调用自检，保持当前试运行观察状态"
            return 0
        fi
    fi

    return 0
}

allow_load() {
    cur_bid="$(get_system_boot_id)"
    if [ "$cur_bid" = "unknown" ] || [ -z "$cur_bid" ]; then
        log_msg "【硬门禁拦截】Boot ID 缺失，保守拒绝加载驱动 (Fail-Closed)"
        return 1
    fi
    cur_state="$(get_state)"
    [ "$cur_state" = "TRIPPED" ] && return 1
    return 0
}

arm_probe() {
    acquire_lock || return 1
    cur_boot_id="$(get_system_boot_id)"
    cur_state="$(get_state)"

    if [ "$cur_state" = "TRIPPED" ]; then
        log_msg "【拒绝上膛】熔断器处于 TRIPPED 状态"
        release_lock
        return 1
    fi

    if [ "$cur_state" = "PROBING" ]; then
        last_bid="$(tr -d '\r\n ' < "$BOOT_ID_FILE" 2>/dev/null)"
        if [ "$last_bid" = "$cur_boot_id" ]; then
            release_lock
            return 0
        fi
    fi

    if ! set_state "PROBING"; then
        log_msg "【致命错误】无法原子写入 PROBING 状态，拒绝加载驱动"
        release_lock
        return 1
    fi

    atomic_write_file "$BOOT_ID_FILE" "$cur_boot_id"
    atomic_write_file "$EXT_BOOT_ID_FILE" "$cur_boot_id" 2>/dev/null || true
    release_lock

    log_msg "熔断器已上膛: PROBING (BootID: $cur_boot_id)，启动 ${PROBING_TIMEOUT}s 平稳观察期"
    return 0
}

abort_probe() {
    reason="$1"
    [ -z "$reason" ] && reason="insmod 驱动加载失败或取消"

    acquire_lock || return 1
    cur_state="$(get_state)"
    if [ "$cur_state" = "PROBING" ]; then
        set_state "NORMAL"
        log_msg "[主动中止] $reason -> 探测安全回滚为 NORMAL (不计入崩溃)"
    fi
    release_lock
    return 0
}

disarm_probe() {
    acquire_lock || return 1
    cur_state="$(get_state)"
    if [ "$cur_state" = "TRIPPED" ]; then
        release_lock
        return 1
    fi
    set_state "NORMAL"
    set_fail_count "0"
    rm -f "$REASON_FILE" "$EXT_REASON_FILE" 2>/dev/null
    release_lock
    log_msg "[✔] 驱动已平稳运行满 ${PROBING_TIMEOUT} 秒，熔断探测安全解除，状态恢复为 NORMAL"
    return 0
}

reset_fuse() {
    acquire_lock || return 1
    set_state "NORMAL"
    set_fail_count "0"
    rm -f "$REASON_FILE" "$EXT_REASON_FILE" 2>/dev/null
    release_lock
    log_msg "[✔] 管理员已手动复位熔断器，状态重置为 NORMAL"

    for ko_tripped in "${BASE_DIR}"/*.ko.tripped "${BASE_DIR}/hollow_modules"/*.ko.tripped "${BASE_DIR}/driver_manager"/*.ko.tripped "${BASE_DIR}/driver_manager/kernels"/*.ko.tripped; do
        if [ -f "$ko_tripped" ]; then
            mv -f "$ko_tripped" "${ko_tripped%.tripped}" 2>/dev/null
            log_msg "  -> 驱动物理锁定解除: ${ko_tripped%.tripped}"
        fi
    done
    return 0
}

preserve_or_init() {
    acquire_lock || return 1
    ext_s=""
    [ -f "$EXT_STATE_FILE" ] && ext_s="$(tr -d '\r\n ' < "$EXT_STATE_FILE" 2>/dev/null)"
    cur_s=""
    [ -f "$STATE_FILE" ] && cur_s="$(tr -d '\r\n ' < "$STATE_FILE" 2>/dev/null)"

    if [ "$ext_s" = "TRIPPED" ] || [ "$cur_s" = "TRIPPED" ]; then
        set_state "TRIPPED"
        if [ -f "$EXT_REASON_FILE" ]; then
            cp -f "$EXT_REASON_FILE" "$REASON_FILE" 2>/dev/null || true
        fi
        log_msg "[重装保护] 继承历史熔断跳闸状态 (TRIPPED)，拒绝静默重置！"
        # 重装/升级后同步锁定新解压的 .ko，防止被立即误加载
        for ko in "${BASE_DIR}"/*.ko "${BASE_DIR}/hollow_modules"/*.ko; do
            if [ -f "$ko" ] && [ "${ko%.tripped}" = "$ko" ]; then
                mv -f "$ko" "${ko}.tripped" 2>/dev/null
            fi
        done
        release_lock
        return 2
    fi

    if [ "$ext_s" = "PROBING" ] || [ "$cur_s" = "PROBING" ]; then
        cur_bid="$(get_system_boot_id)"
        saved_bid=""
        [ -f "$BOOT_ID_FILE" ] && saved_bid="$(tr -d '\r\n ' < "$BOOT_ID_FILE" 2>/dev/null)"
        [ -z "$saved_bid" ] && [ -f "$EXT_BOOT_ID_FILE" ] && saved_bid="$(tr -d '\r\n ' < "$EXT_BOOT_ID_FILE" 2>/dev/null)"

        if [ -n "$saved_bid" ] && [ "$saved_bid" = "$cur_bid" ]; then
            set_state "PROBING"
            atomic_write_file "$BOOT_ID_FILE" "$saved_bid"
            atomic_write_file "$EXT_BOOT_ID_FILE" "$saved_bid" 2>/dev/null || true
            log_msg "[重装保护] 同一启动会话内在线升级，保留 PROBING 状态 (BootID: $saved_bid)"
            release_lock
            return 0
        else
            set_state "TRIPPED"
            reason_msg="检测到上次启动停留在 PROBING 试运行期即发生重启并重装 (BootID: ${saved_bid:-unknown} -> ${cur_bid})"
            atomic_write_file "$REASON_FILE" "$reason_msg"
            atomic_write_file "$EXT_REASON_FILE" "$reason_msg" 2>/dev/null || true
            log_msg "[重装保护] $reason_msg -> 升级锁定为 TRIPPED！"
            for ko in "${BASE_DIR}"/*.ko "${BASE_DIR}/hollow_modules"/*.ko; do
                if [ -f "$ko" ] && [ "${ko%.tripped}" = "$ko" ]; then
                    mv -f "$ko" "${ko}.tripped" 2>/dev/null
                fi
            done
            release_lock
            return 2
        fi
    fi

    set_state "NORMAL"
    set_fail_count "0"
    release_lock
    log_msg "[初始化] 熔断器就绪: NORMAL"
    return 0
}

is_watchdog_alive() {
    cur_bid="$(get_system_boot_id)"
    [ "$cur_bid" = "unknown" ] || [ -z "$cur_bid" ] && return 1
    [ -f "$WATCHDOG_PID_FILE" ] && [ -f "$WATCHDOG_BOOT_FILE" ] || return 1
    wpid="$(tr -d ' \t\r\n' < "$WATCHDOG_PID_FILE" 2>/dev/null)"
    wbid="$(tr -d ' \t\r\n' < "$WATCHDOG_BOOT_FILE" 2>/dev/null)"

    [ "$wbid" = "$cur_bid" ] || return 1
    [ -n "$wpid" ] && kill -0 "$wpid" 2>/dev/null || return 1

    if [ -r "/proc/$wpid/cmdline" ]; then
        tr '\000' ' ' < "/proc/$wpid/cmdline" 2>/dev/null | grep -q "crash_guard" || return 1
    else
        return 1
    fi
    return 0
}

run_watchdog() {
    timeout="$1"
    [ -z "$timeout" ] && timeout="$PROBING_TIMEOUT"

    if is_watchdog_alive; then
        old_pid="$(tr -d ' \t\r\n' < "$WATCHDOG_PID_FILE" 2>/dev/null)"
        log_msg "已有看门狗进程 (PID $old_pid) 运行中，跳过重复启动"
        return 0
    fi

    cur_bid="$(get_system_boot_id)"
    if ! mkdir "$WATCHDOG_LOCK_DIR" 2>/dev/null; then
        if is_watchdog_alive; then
            return 0
        fi
        if [ -f "$WATCHDOG_PID_FILE" ] && [ -f "$WATCHDOG_BOOT_FILE" ]; then
            wpid="$(tr -d ' \t\r\n' < "$WATCHDOG_PID_FILE" 2>/dev/null)"
            wbid="$(tr -d ' \t\r\n' < "$WATCHDOG_BOOT_FILE" 2>/dev/null)"
            if [ "$wbid" != "$cur_bid" ] || { [ -n "$wpid" ] && ! kill -0 "$wpid" 2>/dev/null; }; then
                rm -rf "$WATCHDOG_LOCK_DIR" "$WATCHDOG_PID_FILE" "$WATCHDOG_BOOT_FILE" 2>/dev/null || true
                if ! mkdir "$WATCHDOG_LOCK_DIR" 2>/dev/null; then
                    return 0
                fi
            else
                return 0
            fi
        else
            return 0
        fi
    fi

    cleanup_watchdog_lock() {
        rm -rf "$WATCHDOG_LOCK_DIR" "$WATCHDOG_PID_FILE" "$WATCHDOG_BOOT_FILE" 2>/dev/null || true
    }
    trap 'cleanup_watchdog_lock' EXIT INT TERM HUP

    atomic_write_file "$WATCHDOG_BOOT_FILE" "$cur_bid"
    atomic_write_file "$WATCHDOG_PID_FILE" "$$"

    log_msg "单例看门狗启动 (PID $$, BootID $cur_bid): 观察期 ${timeout} 秒..."

    w_count=0
    while [ "$w_count" -lt 30 ]; do
        boot_comp="$(getprop sys.boot_completed 2>/dev/null)"
        [ "$boot_comp" = "1" ] && break
        sleep 2
        w_count=$((w_count + 1))
    done

    sleep "$timeout"

    cur_state="$(get_state)"
    if [ "$cur_state" = "PROBING" ]; then
        disarm_probe
    fi

    cleanup_watchdog_lock
}

json_esc() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n\r' '  '
}

print_status() {
    st="$(get_state)"
    fc="$(get_fail_count)"
    bid="$(tr -d '\r\n ' < "$BOOT_ID_FILE" 2>/dev/null)"
    [ -z "$bid" ] && bid="$(tr -d '\r\n ' < "$EXT_BOOT_ID_FILE" 2>/dev/null)"
    cur_bid="$(get_system_boot_id)"
    br="$(get_boot_reason)"
    rs="$(cat "$REASON_FILE" 2>/dev/null || cat "$EXT_REASON_FILE" 2>/dev/null || true)"
    wd_alive="false"
    is_watchdog_alive && wd_alive="true"

    printf '{"module":"crash_guard","guard_id":"%s","state":"%s","fail_count":%s,"max_fail":%s,"probing_timeout_seconds":%s,"watchdog_alive":%s,"current_boot_id":"%s","recorded_boot_id":"%s","boot_reason":"%s","trip_reason":"%s"}\n' \
        "$(json_esc "$GUARD_ID")" \
        "$(json_esc "$st")" \
        "$fc" \
        "$MAX_FAIL" \
        "$PROBING_TIMEOUT" \
        "$wd_alive" \
        "$(json_esc "$cur_bid")" \
        "$(json_esc "$bid")" \
        "$(json_esc "$br")" \
        "$(json_esc "$rs")"
}

case "$1" in
    check)
        check_boot
        ;;
    allow-load)
        allow_load
        ;;
    arm)
        arm_probe
        ;;
    abort-probe)
        shift
        abort_probe "$@"
        ;;
    disarm)
        disarm_probe
        ;;
    trip)
        shift
        trip_fuse "$*"
        ;;
    reset)
        reset_fuse
        ;;
    preserve-or-init)
        preserve_or_init
        ;;
    watchdog)
        shift
        run_watchdog "$@"
        ;;
    status)
        print_status
        ;;
    *)
        echo "Usage: $0 {check|allow-load|arm|abort-probe [reason]|disarm|trip [reason]|reset|preserve-or-init|watchdog [sec]|status}"
        exit 1
        ;;
esac
```

### 9.10 `hollow_modules/manifest.json`

```json
{
  "schema_version": 4,
  "architecture": "26_hollow_preempt",
  "target_kernel": "6.6.118-android15-8-o-g15bab650beb0-4k",
  "target_arch": "aarch64",
  "drivers": {
    "inte.ko": {
      "module": "inte",
      "size": 51320,
      "sha256": "ad03f43d33c5b8722f6935f3cbbb78ea25cdd1f630b96576685cf4fb20f4ded0",
      "stock_sha256": "485f4520648576d8c1c37618ef112b856f0148970f4ab18d1538b7493e45ef67",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 8,
      "neutralized_relas": 0
    },
    "oplus_secure_guard_new.ko": {
      "module": "oplus_secure_guard_new",
      "size": 78008,
      "sha256": "1529ed14e9e6a918503d3c01e3f476db639dba890c6e74de82485d2dd91caf71",
      "stock_sha256": "ac3a7e312ed6b949b6e1447b9529a617e1e45b3538ff3d933ea9a407d7af5d39",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 23,
      "neutralized_relas": 0
    },
    "oplus_patch.ko": {
      "module": "oplus_patch",
      "size": 31912,
      "sha256": "f5a82bf825be167ed6dacff9cb5746f5d8f61a1cb24886417fd67b9b764752f4",
      "stock_sha256": "75da2dc99f6d4c22b01012d0fa76975619e378a74347219805fb21275504970c",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 8,
      "neutralized_relas": 0
    },
    "oplus_network_data_module.ko": {
      "module": "oplus_network_data_module",
      "size": 1341544,
      "sha256": "e40a3ab53a3e0caca28021c56ec83fbc80fd496ce5db86ad718c702786d8c0c8",
      "stock_sha256": "b2cd7c8bbbbd11206c2d703780bdad80761b0fc6e59d1a05fd9e2af984db8e42",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 18,
      "neutralized_relas": 2
    },
    "oplus_network_dns_hook.ko": {
      "module": "oplus_network_dns_hook",
      "size": 33208,
      "sha256": "c5a9d2f63e4f5c9d2ac21d149bc84854bc89113f7fc52cefabf65083b71f8301",
      "stock_sha256": "a4659e0d70d2bfb6fb4a399a6b8bc1b3d987b60c9fee52440f546859a091cac4",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 2,
      "neutralized_relas": 0
    },
    "oplus_network_qr_scan.ko": {
      "module": "oplus_network_qr_scan",
      "size": 29336,
      "sha256": "0ab245adf919f7ba7297dde81e805e88d93ab3b4dbecd31aa3cb1274857adce4",
      "stock_sha256": "87c6a579d24b66406be8281e40aa1744991c42ac6d13ac131beb1088f37269b1",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 6,
      "neutralized_relas": 0
    },
    "oplus_bsp_file_read_record.ko": {
      "module": "oplus_bsp_file_read_record",
      "size": 29176,
      "sha256": "dc18dec7dd8998544a8abb0a90341ca3d0a9e828d02b2878a1040b9db33c00e8",
      "stock_sha256": "4422c07f9cd3adade29f206eda8d185c12d062a1e07ce927df0d32afd472b227",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 6,
      "neutralized_relas": 0
    },
    "oplus_bsp_dfr_theia.ko": {
      "module": "oplus_bsp_dfr_theia",
      "size": 101664,
      "sha256": "2a283605349ce7e483b642234eaa171de72ec469e15d9472ab41a5882c499238",
      "stock_sha256": "cfc93ecef0570981352222b04ad51e7eb148c4ef319ca6d64c89cf630a0a4ad0",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 5,
      "neutralized_relas": 0
    },
    "oplus_network_dns_cache.ko": {
      "module": "oplus_network_dns_cache",
      "size": 26952,
      "sha256": "459f9096a80f74517ce5fccd252edcddd796be9dbaf3489ff926564eb4d8ce22",
      "stock_sha256": "3cbf3ee2d318f7d20fa6c15806e90fea733f2b9632734febc8d2f23c492921c6",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 4,
      "neutralized_relas": 4
    },
    "oplus_network_snapshot.ko": {
      "module": "oplus_network_snapshot",
      "size": 55800,
      "sha256": "4969766c7d126e0da48177ccf13eb9bcd412cb7c472b340360eb6cb41015a7da",
      "stock_sha256": "981dd6a7367e739d1cdf588f3c96ce6ad96fcc6c34ce2b0e205b442094023b48",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 8,
      "neutralized_relas": 2
    },
    "oplus_network_sk_predict.ko": {
      "module": "oplus_network_sk_predict",
      "size": 25296,
      "sha256": "45353b06c208cd2d79d2bdd4c0c0e6637e8e73ad2dabff9a0038f5f29eecfd1c",
      "stock_sha256": "83c0feed1d6d54337fc5969cf62a1f7f1cbe80a8ca33333d527eb3a2bd72fa92",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 3,
      "neutralized_relas": 0
    },
    "oplus_network_vip_task.ko": {
      "module": "oplus_network_vip_task",
      "size": 42568,
      "sha256": "6738f954d73265717d03f879fd872e2ed0d153b38400766cdef893068462cdbc",
      "stock_sha256": "cde9d9672e38678b460806509da2a3c1cc208c4e48c51191941b21ec00cc57a5",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 7,
      "neutralized_relas": 7
    },
    "oplus_network_linkpower_module.ko": {
      "module": "oplus_network_linkpower_module",
      "size": 425744,
      "sha256": "f567c2d677250e556fa0bc4489945954539e1303e2f38b46223707436457a913",
      "stock_sha256": "bd3c824341abe93df15f8c750c7d28adcaf0eca74b94ccf967e5578cb40cd414",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 53,
      "neutralized_relas": 4
    },
    "oplus_network_score.ko": {
      "module": "oplus_network_score",
      "size": 66848,
      "sha256": "e7514931291191feb4eba72a7365418b39e551496e05045ed06636e86d0a0f09",
      "stock_sha256": "bee8bf6e213f0085e332297fbd49a72f107764efd2dc40a882edf79ae0b7c586",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 7,
      "neutralized_relas": 0
    },
    "oplus_network_tcpdump_enhance.ko": {
      "module": "oplus_network_tcpdump_enhance",
      "size": 29888,
      "sha256": "d2e17e661c05dc06170dbd141a5d1ee8394d4e86fbafbd58c4f4f03ba71229d1",
      "stock_sha256": "e187f2d1c4cd7c24127f836d5e9bd0183e6dc6a5e8f07ca48aeb0e80327a41d9",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 5,
      "neutralized_relas": 4
    },
    "oplus_network_app_monitor.ko": {
      "module": "oplus_network_app_monitor",
      "size": 61112,
      "sha256": "2f29449194bf5cf9c20d913c37031aca4b12283acba33377c922158703b7273f",
      "stock_sha256": "4dc295ffde5cea2676cbe161b688e909fc451d1f1316a9534763c4d132d9729c",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 15,
      "neutralized_relas": 0
    },
    "oplus_network_stats_calc.ko": {
      "module": "oplus_network_stats_calc",
      "size": 24768,
      "sha256": "01b20d76a9481c7b956d0e3464e065af0fe7b4bf905d4aa47f96b7862020b3e9",
      "stock_sha256": "d5c186b52d458cb9dc131455a539f43af3c3053da0af67572de325b8e3ad0466",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 4,
      "neutralized_relas": 0
    },
    "oplus_bsp_midas.ko": {
      "module": "oplus_bsp_midas",
      "size": 62200,
      "sha256": "f6680311acebe5f5676e20dbf3532589b8a6684dc9f29e1f8fba1f9ca0eeeb29",
      "stock_sha256": "f9f33dad957d07e27d4b78c13543792fd7c1e48b6c760ebe6bd39ad767bcc0e2",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 7,
      "neutralized_relas": 4
    },
    "mtk_mbraink.ko": {
      "module": "mtk_mbraink",
      "size": 159344,
      "sha256": "2ad9501e0fe5116455dd424c308bc9812f7fe7afa21a2f3de42bfb3ccb1aeded",
      "stock_sha256": "37313b83833c2d4ed455ced776998ed725eddbc3c0d2df69764cc42e667fb07f",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 20,
      "neutralized_relas": 1
    },
    "mtk_mbraink_v6991.ko": {
      "module": "mtk_mbraink_v6991",
      "size": 111392,
      "sha256": "1a26b7936690e96f46b7f64992ae4494ef0e816842d2a890f02c8eb1e693e9d3",
      "stock_sha256": "2862b7dde8a39e0d488faed75401b45bc1914dd42897062ac5def3053e909a70",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 13,
      "neutralized_relas": 1
    },
    "oplus_sys_stability_helper.ko": {
      "module": "oplus_sys_stability_helper",
      "size": 50832,
      "sha256": "7cb763a6c018ba1f4945dd9ea71f9584c9cf6fd007c49412b8e630d9b5d034a2",
      "stock_sha256": "12c01790dcba8bec14720fe5eaf83c5b4de4e7cbe887ace64839da2926c5c25d",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 10,
      "neutralized_relas": 0
    },
    "oplus_bsp_sigkill_diagnosis.ko": {
      "module": "oplus_bsp_sigkill_diagnosis",
      "size": 16480,
      "sha256": "7216453f3e7385ff456078ca9a35dc85c7a01f2da82ece9f2319132a76414445",
      "stock_sha256": "927020ff6d1d6253028b58de1f9dba7308c172e38f2b162254aca72dc63d6fd9",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 2,
      "neutralized_relas": 0
    },
    "oplus_bsp_dfr_ubt.ko": {
      "module": "oplus_bsp_dfr_ubt",
      "size": 23472,
      "sha256": "b94e4e77d893b003cf066a0a5b5ee77dcbf7f8745423d742d8ed1de7645bce23",
      "stock_sha256": "6a674fa4860513675a85f62155c90bff982be54ec17ac12a29fd3911d62782fe",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 5,
      "neutralized_relas": 0
    },
    "oplus_network_dns_optimizer.ko": {
      "module": "oplus_network_dns_optimizer",
      "size": 152176,
      "sha256": "83624b2b9f1872a7533c0e160e9abc9980a5736b3aabbc7df434205e9bf40c3e",
      "stock_sha256": "9416004c364583bdf6b2f20152d53e8d13ae7e317a73c885a8f874fae2c6ed44",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 20,
      "neutralized_relas": 12
    },
    "oplus_network_fast_bwe.ko": {
      "module": "oplus_network_fast_bwe",
      "size": 29264,
      "sha256": "5911b29d4f159cd6da1c9286cc3f4be11de8f85f89e425b63776a2ee603003e9",
      "stock_sha256": "3e0017da4773a3abf83262819c3ca98150df21f2cc56f015391834165b06a618",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 2,
      "neutralized_relas": 0
    },
    "oplus_network_tuning.ko": {
      "module": "oplus_network_tuning",
      "size": 92216,
      "sha256": "755bd71005847613d91ca0399c9cb4046a88c2c51519e74f95bbd2084417dd7d",
      "stock_sha256": "7cbb7bcce1ac914e24225d0a4a0259255322cffaf341a319b6286233ee3f8011",
      "vermagic": "6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64",
      "kernel_release": "6.6.118-android15-8-o-g15bab650beb0-4k",
      "arch": "aarch64",
      "patched_functions": 3,
      "neutralized_relas": 4
    }
  }
}
```
