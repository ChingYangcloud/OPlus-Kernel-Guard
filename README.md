# OPlus Kernel Guard (欧加 ARM64 GKI 内核监控逆向研究与空壳防御工程)

> **声明：由于作者比较懒所以文案由美国大豆包整理。**

本项目开源整理自对 **OPPO / OnePlus / Realme（欧加）Android GKI (`6.6.118-android15-8-o-g15bab650beb0-4k`, MT6991 天玑 9400+ 及全系 ARM64 GKI 6.x)** 原厂内核监控、审计与网络深度包检测（DPI）驱动的二进制符号取证，以及最新发布的 **OPlus Kernel Guard v4.1.0 Universal** 通用 ARM64 原位空壳绿灯防御方案。

* 🌐 **官方网站与研究博客**：https://chingyangkernel.ai.studio
* 📢 **官方 Telegram 频道**：https://t.me/ChingyangKernel

---

## 🚀 最新版本：OPlus Kernel Guard v4.1.0 Universal

> **Universal 架构革新（v4.0.0 -> v4.1.0）**：卡刷包内**不再预置任何绑定单一机型的 `.ko` 二进制**，仅内置一个 **8.4 KB 零 libc 静态原生 ARM64 ELF 修补器（`bin/okg_patcher`）** 与纯文本规则表（`rules.conf`，覆盖 26 个监控/网络遥测驱动、248 条函数规则）。在**安装阶段**与 **OTA 内核升级后的首次重启**，自动基于本机纯净的 `/vendor_dlkm/lib/modules/*.ko`（或 `/vendor/lib/modules/*.ko`）原地生成空壳驱动与 `manifest.json`。

* **适用范围**：OPPO / OnePlus / Realme 全系 **ARM64 GKI 6.x** 机型，兼容 **KernelSU / APatch / Magisk**（免元模块）。
* **100% 继承本机 ABI / 签名接口**：
  * 直接修补本机原厂 `.ko` 的 `.text` 目标函数入口（保留 `entry - 4` 处的 4 字节 **KCFI Type ID**、`__versions` 符号 CRC、`.modinfo vermagic`、`__ksymtab` 导出表及 `/proc` · `/dev` · `sysctl` · `genl_family` 注册逻辑）。
  * 自动识别函数序言是否含 `paciasp`（16B `paciasp; mov ...; autiasp; ret` vs 12B `bti c; mov ...; ret`），并将被覆盖序言内的 `.rela.text` 重定位项安全置为 `R_AARCH64_NONE`；高通等非 MTK 平台自动跳过 `mtk_mbraink*`。
* **安装期 + OTA 自动重建**：`customize.sh` 安装时自动生成空壳与 `manifest.json`；OTA 升级内核后首次开机 `post-fs-data.sh` 在任何 `mount --bind` 前提取真实原厂 `vermagic`（不受 SUSFS `uname` 伪装干扰），不一致即自动重新修补。
* **生产级安全硬化**：**Fail-Closed 双哈希硬门禁** + **禁止自动 `SIGKILL`** + **拓扑逆序并发暂停/恢复** + **跨 Boot 崩溃归因熔断器（`crash_guard`）** + WebUI 手动触发「重建本机空壳」。
* **下载地址**：[GitHub Releases (`v4.1.0`)](https://github.com/ChingYangcloud/OPlus-Kernel-Guard/releases/tag/v4.1.0)（`oplus_kernel_guard_v4.1.0_universal.zip`，SHA-256: `4776d9cd7d6a491df62b4cd4dadc6758ec962f272d3888e90ea126be60907c17`）

---

## 📂 仓库内容导航

| 文件 / 目录 | 说明 |
| :--- | :--- |
| [oplus_kernel_monitoring_complete_code_report.md](./oplus_kernel_monitoring_complete_code_report.md) | 23 核心监控 `.ko` + 3 遥测 `.ko`（26+1）完整 `.symtab` / `.rodata` / `.rela.rodata` 二进制核实研究报告（含 Protobuf 上报结构定义与 ELF 完整性审计脚本） |
| [sorce/README.md](./sorce/README.md) | 空壳驱动构建工具说明 |
| [sorce/STUB_BLUEPRINT.md](./sorce/STUB_BLUEPRINT.md) | Generic Netlink 家族、`/proc`、`/dev`、`sysctl` 与符号导出接口技术蓝图 |
| [sorce/hollow_patcher.py](./sorce/hollow_patcher.py) | ARM64 原位 ELF 空壳绿灯补丁脚本（`paciasp` 16B / `bti c` 12B 原位补丁 + `.rela.text` 重定位 `R_AARCH64_NONE` 清零） |
| [sorce/manifest.json](./sorce/manifest.json) | 全部 26 个空壳 `.ko` 的 `sha256`、`stock_sha256`、`vermagic` 与补丁函数统计清单 |
| [sorce/stubs/inte_stub/inte.c](./sorce/stubs/inte_stub/inte.c) | `inte.ko` 独立 C 源码绿灯空壳参考原型及 Kbuild 脚本（`prepare_kbuild.sh` / `build_stub.sh` / `stock_sym_crcs.txt`） |
| **GitHub Releases (`v4.1.0`)** | 最新通用版 `oplus_kernel_guard_v4.1.0_universal.zip`（支持全系欧加 ARM64 GKI 6.x） |
| **GitHub Releases (`v3.1.0`)** | 历史机型直装版 `oplus_kernel_guard_v3.1.0.zip`、`oplus_mt6991_monitoring_drivers_23.zip`、`vendor_modules.tar.gz` 完整样本 |

---

## 🔍 核心研究发现摘要

1. **23 + 3 全量驱动危害分级（T0 极高危 ～ T3 低危）**：
   * **T0 极高危（6 个）**：`oplus_patch.ko`（`/proc/kprobe_ctl` 任意函数动态 Hook）、`oplus_secure_guard_new.ko`（13 `kretprobe` + 8 `kprobe` = 21 探针提权监控与 `SIGKILL` 强杀）、`oplus_network_dns_hook.ko`（出站 UDP 53 劫持伪造注入并丢弃原包）、`oplus_network_dns_cache.ko`（明文 `domain` Protobuf 上报）、`oplus_network_data_module.ko`（`comm_netlink` 25 类 Protobuf 总线与 32 款 App TLS/QUIC SNI DPI 检测及游戏 IP 上报）、`oplus_bsp_dfr_ubt.ko`（`get_user_pages_remote` 跨进程读取用户态虚拟内存）。
   * **T1 高危（6 个）**：`oplus_bsp_file_read_record.ko`（VFS `d_path()` 文件全路径监控）、`oplus_network_qr_scan.ko`（扫码订单/支付状态位嗅探）、`oplus_network_sk_predict.ko`（前台 `activityName` 与 Socket 关联）、`oplus_network_snapshot.ko`（DNS 服务器/时延/RCODE 与 UID 流量快照）、`oplus_network_tcpdump_enhance.ko`、`inte.ko`（v0.16 `load_module` 白名单与每小时 `sys_call_table` 哈希巡检）。
   * **T2 中危（5 个） & T3 低危（6 个）**：涵盖长连接心跳/重传监控、`oplus_network_linkpower_module.ko`（`sk_pid_hook_dsc_block_dns`、`asyn_destroy_sk` 与 MTK 基带 MIPC 防火墙下发）、`oplus_bsp_midas.ko`、Theia 黑/亮屏事件与 MT6991 MBrain 平台遥测；`oplus_network_dns_optimizer.ko`、`oplus_network_fast_bwe.ko`、`oplus_network_tuning.ko` 纳入空壳，`oplus_bsp_dfr_combkey_monitor.ko` 故意保留原厂以维持强制重启 `blkdev_fsync` 落盘保护。
2. **空壳防御演进（`v3.1.0` -> `v4.1.0 Universal`）**：
   * 采用 **0 `rmmod` 全量 26 模块空壳驻留**：保留 50 个 `/proc/sys/net/*` 目录、`comm_netlink` / `secure_guard` / `oplus_frk_nl` Generic Netlink 家族与 `/proc`/`/dev` 壳层，返回无害绿灯信号，防止用户态守护进程因节点缺失引发卡死或异常上报。
   * **Fail-Closed 双哈希硬门禁 + 5 层 `crash_guard` 抗无限重启熔断器**：强制比对 `hollow sha256` 与设备原厂 `stock_sha256`；结合 36 位 UUID `boot_id`、`abort-probe` 自动回滚、`NORMAL|PROBING|TRIPPED` 状态机、原子落盘与 60 秒单例 watchdog 保障跨 Boot 安全。

---

> 再次声明：**由于作者比较懒所以文案由美国大豆包整理。**
