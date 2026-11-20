# OPlus MT6991 空壳驱动源码与构建工具 (v3.1.0)

本目录汇集 **OPlus Kernel Guard v3.1.0** 所使用的空壳驱动构建源码与参考工程（已剔除编译中间文件，所有脚本路径均相对当前目录自适应）：

## 1. 全量 26 模块空壳驱动构建器（v3.1.0 实际产物来源）
- `hollow_patcher.py`：可复现的 ARM64 原位 ELF 空壳绿灯补丁脚本。默认相对读取上层目录 `../oplus_mt6991_monitoring_drivers_23.zip`（23 核心监控驱动）与 `../vendor_modules.tar.gz`（补充 3 个网络遥测驱动：`oplus_network_dns_optimizer.ko`、`oplus_network_fast_bwe.ko`、`oplus_network_tuning.ko`；另 `oplus_bsp_dfr_combkey_monitor.ko` 经评估保留原厂以维持 `blkdev_fsync` 落盘保护）。
  - 保留 `init_module` / `/proc` / `/dev` / `sysctl` / Generic Netlink / `__ksymtab` 导出符号与 `vermagic`；
  - 对目标函数按 `paciasp`（16 字节 `paciasp; mov ...; autiasp; ret`）与非 `paciasp`（12 字节 `bti c; mov ...; ret`）规则原位补丁，并将被覆盖序言内的 `.rela.text` 重定位条目清零为 `R_AARCH64_NONE`；
  - 默认输出至当前目录下的 `out_hollow/`（包含 26 个空壳 `.ko` 及 `manifest.json`，可通过 `OKG_OUT_DIR` / `OKG_STOCK_ZIP` / `OKG_VENDOR_TAR` 环境变量自定义路径）。
- `manifest.json`：v3.1.0 全部 26 个空壳 `.ko` 的 `sha256`、`stock_sha256`、`vermagic` 与补丁函数统计清单（供 Fail-Closed 双哈希硬门禁校验）。

## 2. 独立 C 源码空壳编译 SDK（Kbuild 参考）
- `stubs/inte_stub/inte.c` & `stubs/inte_stub/Makefile`：`inte.ko` 从零编写的 C 语言绿灯空壳源码（标准 `proc_create` + `seq_read` 接口桩）。
- `prepare_kbuild.sh` & `build_stub.sh`：相对脚本所在目录运行，对齐 GKI `6.6.118-android15-8-o-g15bab650beb0-4k` `vermagic` 与 KABI 的外部模块编译脚本（输出至当前目录下的 `out/`）。
- `stock_sym_crcs.txt`：从原厂 369 个模块提取的 `__versions` 符号 CRC 清单。
- `STUB_BLUEPRINT.md`：各目标监控驱动的 `genl_family`、`/proc`、`sysctl` 与符号导出接口蓝图。
