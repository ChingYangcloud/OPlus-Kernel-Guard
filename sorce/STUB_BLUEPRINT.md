# OPlus Kernel Guard — 空壳驱动（Green Stub）技术准备蓝图

## 1. 目标内核 ABI 与编译环境核验

通过对 [oplus_mt6991_monitoring_drivers_23.zip](file:///D:/adb/colorossave/kernelsave/oplus_mt6991_monitoring_drivers_23.zip) 与 [vendor_modules.tar.gz](file:///D:/adb/colorossave/kernelsave/vendor_modules.tar.gz) 全部 369 个 `.ko` 进行 ELF 取证，确认目标内核环境如下：

- **目标 `vermagic`**：`6.6.118-android15-8-o-g15bab650beb0-4k SMP preempt mod_unload modversions aarch64`
- **模块签名状态**：全部 23 个目标 `.ko` 均为未签名（`sig=False`），且 [`.config`](file:///D:/adb/kernel/.config) 中 `# CONFIG_MODULE_SIG_FORCE is not set`
- **编译链与源码**：
  - 源码树：`D:/adb/kernel_workspace/common`（Linux `6.6.118`）
  - 编译器：`D:/adb/kernel_workspace/clang18/bin/clang`（Android clang 18.0.0, r510928）
  - 关键 ABI 选项：`CONFIG_CFI_CLANG=y`、`CONFIG_ARM64_PTR_AUTH_KERNEL=y`、`CONFIG_MODVERSIONS=y`
- **符号 CRC 表**：已从 369 个原厂模块提取 4,800 条导出符号 CRC 至 [stock_sym_crcs.txt](stock_sym_crcs.txt)，供 `modpost` 自动写入与原厂一致的 `__versions` 段。

---

## 2. 分模块替换策略总览

### A. 仅卸载（无需空壳，Step 1 已处理）
以下 4 个非网络模块无用户态 Netlink 主动上报，且无任何反向依赖，直接 `rmmod` 即可：
- `oplus_bsp_dfr_ubt`
- `oplus_bsp_file_read_record`
- `oplus_bsp_sigkill_diagnosis`
- `oplus_bsp_midas`（注：若用户态 `midas` 服务强依赖 `/dev/midas_dev` ioctl 返回成功，可作为备选制作空壳字符设备）

### B. 优先替换为空壳驱动（返回“绿色无异常”）

#### 1) `inte.ko`（已就绪原型：[inte.c](stubs/inte_stub/inte.c)）
- **交互接口**：`/proc/inte_ko`、`/proc/inte_systbl`、`/proc/inte_status`（`proc_set_user` 归属 UID/GID `1000`）。
- **校验进程**：写入操作要求 `comm == "oplus_kohashpro"` 且 `euid == 1000`。
- **空壳“绿色无异常”契约**：
  - 移除 `load_module` `kretprobe` 与 `sys_call_table` SHA-256 扫描。
  - `GET /proc/inte_ko` 与 `GET /proc/inte_systbl` 返回空（0 条异常事件）。
  - `GET /proc/inte_status` 返回 `<unix_timestamp>:true\n`。
  - `WRITE` 节点按原进程/EUID 校验后直接返回 `count`（成功接收）。

#### 2) `oplus_secure_guard_new.ko`
- **Generic Netlink 协议**：
  - `genl_family.name = "secure_guard"`，`version = 1`，`hdrsize = 0`，`maxattr = 2`，`n_ops = 1`
  - 接收用户态守护进程 `kevent_pid` 注册命令（`sendpid`），后续不再挂载 20 个 `kprobe`/`kretprobe`（提权检测、`do_execveat_common`、`sel_write_load`、`setsockopt` 堆喷射等），也不再触发 `SIGKILL` 与异常上报。
- **绿色信号表现**：守护进程成功绑定 `secure_guard` genl family 并注册 PID，内核零安全事件上行。

#### 3) `oplus_sys_stability_helper.ko` & `oplus_bsp_dfr_theia.ko`
- `oplus_sys_stability_helper.ko`：
  - `genl_family.name = "oplus_frk_nl"`，`version = 1`，`maxattr = 1`，`n_ops = 1`（`cmd = 1`）
  - 移除 `copy_process`、`binder_proc_transaction_finish`、`do_send_sig_info`、`direct_reclaim` 钩子；空壳接受命令注册，零卡顿/线程异常上报。
- `oplus_bsp_dfr_theia.ko`：
  - `genl_family.name = "theia_monitor"`，`version = 1`，`maxattr = 3`，`n_ops = 1`
  - 保留 `/proc` 开关节点与 5 个导出符号（`black_screen_timer_restart`、`bright_screen_timer_restart`、`set_pwk_flag`、`theia_send_event`、`theia_send_event_atomic`）供 `oplus_bsp_dfr_combkey_monitor` 链接，内部全部空操作返回 `0`。

#### 4) `oplus_network_*` 网络监控套件
按 ELF 符号解码，各独立 Netlink family 参数如下（均为 `version = 1`, `hdrsize = 0`, `n_ops = 1`, `cmd = 1`）：

| 模块名 | `genl_family.name` | `maxattr` | 导出符号数 | 备注 |
| --- | --- | --- | --- | --- |
| `oplus_network_data_module` | `comm_netlink` | `3` | `734` | 被 9 个子模块依赖（含 `register_netlink_request` / `notify_netlink_event`） |
| `oplus_network_dns_hook` | `dns_hook` | `5` | `0` | 独立 Netlink + `net/oplus_dns_hook` sysctl |
| `oplus_network_qr_scan` | `qr_monitor` | `6` | `0` | 独立 Netlink |
| `oplus_network_tcpdump_enhance` | `tcpdump_netlink` | `3` | `0` | 独立 Netlink |
| `oplus_network_app_monitor` | `apps_monitor` | `17` | `3` | `net/oplus_apps_monitor` 等 sysctl |
| `oplus_network_stats_calc` | `oplus_stats` | `3` | `0` | `net/oplus_stats_calc` sysctl |
| `oplus_network_score` | `net_score` | `12` | `0` | `net/oplus_score` sysctl（依赖 `data_module`） |
| `oplus_network_linkpower_module` | `linkpower` | `999` | `6` | `net/oplus_asc` & `net/oplus_mdfw` sysctl + 双向指令含 `BLOCK_DNS`/`CLOSE_SK` |

- **空壳策略**：先为无导出依赖的子模块（`dns_hook`、`qr_scan`、`tcpdump_enhance`、`stats_calc`、`score`）建立标准 genl 空壳（接受用户态注册与配置下发并返回 `0`，不注册 Netfilter/Kprobe）；`data_module` 若需保留 `dns_optimizer`/`fast_bwe`/`tuning` 兼容性，则可采用纯转发/静默空壳或连同子模块整体卸载。

#### 5) `mtk_mbraink.ko` & `mtk_mbraink_v6991.ko`
- `mtk_mbraink.ko`：`genl_family.name = "MBRAINK_LINK"`，`version = 1`，`maxattr = 1`，`n_ops = 1`（`cmd = 1`），保留 16 个框架注册导出桩函数与 cdev ioctl 返回 `0`。

---

## 3. 构建与校验脚本

- [prepare_kbuild.sh](prepare_kbuild.sh)：在 `/tmp/okg_kbuild_out` 准备 GKI `6.6.118` + `vermagic` 对齐环境与 `Module.symvers`。
- [build_stub.sh](build_stub.sh)：编译指定 `stubs/<name>` 并输出 `.ko` 至当前目录 `out/`。
