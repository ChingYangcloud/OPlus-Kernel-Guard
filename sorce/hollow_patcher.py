#!/usr/bin/env python3
"""
Reproducible ARM64 In-Place ELF Hollow-Green Patcher for OPlus MT6991 (GKI 6.6).
Generates all 26 hollow green .ko drivers from pristine stock binaries:
  - Preserves init_module / /proc / /dev / sysctl / Generic Netlink / __ksymtab
  - Uses paciasp; ...; autiasp; ret (16B) for PAC functions
  - Uses bti c; ...; ret (12B) for non-PAC functions (EL1 BTI hardware safe)
  - Neutralizes .rela.text entries inside overwritten [0..plen) to R_AARCH64_NONE
  - Patches all same-named static symbols across multi-TU linked .ko modules
  - Emits manifest.json with both sha256 & stock_sha256 for fail-closed verification
"""
import hashlib
import json
import os
import struct
import tarfile
import zipfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STOCK_ZIP = os.environ.get(
    "OKG_STOCK_ZIP",
    os.path.normpath(os.path.join(SCRIPT_DIR, "..", "oplus_mt6991_monitoring_drivers_23.zip")),
)
VENDOR_TAR = os.environ.get(
    "OKG_VENDOR_TAR",
    os.path.normpath(os.path.join(SCRIPT_DIR, "..", "vendor_modules.tar.gz")),
)
OUT_DIR = os.environ.get("OKG_OUT_DIR", os.path.join(SCRIPT_DIR, "out_hollow"))

PACIASP = bytes.fromhex("3f2303d5")
BTI_C = bytes.fromhex("5f2403d5")
AUTIASP_RET = bytes.fromhex("bf2303d5c0035fd6")
PLAIN_RET = bytes.fromhex("c0035fd6")

PATCH_BYTES_PAC = {
    "RET_0": PACIASP + bytes.fromhex("00008052") + AUTIASP_RET,
    "RET_1": PACIASP + bytes.fromhex("20008052") + AUTIASP_RET,
    "RET_COUNT": PACIASP + bytes.fromhex("e00302aa") + AUTIASP_RET,
}

PATCH_BYTES_NOPAC = {
    "RET_0": BTI_C + bytes.fromhex("00008052") + PLAIN_RET,
    "RET_1": BTI_C + bytes.fromhex("20008052") + PLAIN_RET,
    "RET_COUNT": BTI_C + bytes.fromhex("e00302aa") + PLAIN_RET,
}

PATCH_PLAN = {
    # === Core 8 (from v2.2.0) ===
    "inte.ko": {
        "add_ko_event": "RET_0",
        "add_systbl_event": "RET_0",
        "check_task": "RET_0",
        "ko_proc_show": "RET_0",
        "systbl_proc_show": "RET_0",
        "hash_probe_entry": "RET_0",
        "proc_write_ko": "RET_COUNT",
        "proc_write_status": "RET_COUNT",
    },
    "oplus_secure_guard_new.ko": {
        "oplus_harden_init": "RET_0",
        "kevent_send_to_user": "RET_0",
        "report_security_event": "RET_0",
        "oplus_root_killed": "RET_0",
        "oplus_root_check_succ": "RET_0",
        "oplus_root_check_succ_upload": "RET_0",
        "oplus_root_check_post_handler": "RET_0",
        "oplus_root_check_pre_handler": "RET_0",
        "uid_entry_handler": "RET_0",
        "uid_ret_handler": "RET_0",
        "do_execveat_common_entry_handler": "RET_0",
        "oplus_exe_block_ret_handler": "RET_0",
        "oplus_report_execveat": "RET_0",
        "oplus_report_execveat_new": "RET_0",
        "oplus_harden_pre_handler": "RET_0",
        "oplus_secure_harden_kevent": "RET_0",
        "oplus_heapspray_check": "RET_0",
        "entry_handler_socket": "RET_0",
        "entry_handler_socket_ip6": "RET_0",
        "entry_handler_cpuinfo": "RET_0",
        "entry_handler_sepolicy_reload": "RET_0",
        "oplus_sepolicy_reload": "RET_0",
        "handler_pre": "RET_0",
    },
    "oplus_patch.ko": {
        "ctl_write": "RET_COUNT",
        "log_show": "RET_0",
        "log_add": "RET_0",
        "hook_register": "RET_0",
        "hook_enable": "RET_0",
        "hook_enable_all": "RET_0",
        "handler_pre_first": "RET_0",
        "handler_pre_second": "RET_0",
    },
    "oplus_network_data_module.ko": {
        "dpi_output_hook_v4": "RET_1",
        "dpi_input_hook_v4": "RET_1",
        "dpi_output_hook_v6": "RET_1",
        "dpi_input_hook_v6": "RET_1",
        "wifi_accelerate_output_hook": "RET_1",
        "wifi_accelerate_postrouting_hook": "RET_1",
        "oplus_game_data_input_hook": "RET_1",
        "work_func": "RET_0",
        "game_main_stream_nf_output_hook_func": "RET_1",
        "notify_game_main_stream_ip_message": "RET_0",
        "notify_netlink_event": "RET_0",
        "send_one_msg": "RET_0",
        "notify_dpi_result": "RET_0",
        "tls_sni_match": "RET_0",
        "gquic_sni_match": "RET_0",
        "http_request_match": "RET_0",
        "http_request_global_match": "RET_0",
        "dpi_handle_match": "RET_0",
    },
    "oplus_network_dns_hook.ko": {
        "oplus_dns_hook_output_hook": "RET_1",
        "oplus_dns_hook_netlink_rcv_msg": "RET_0",
    },
    "oplus_network_qr_scan.ko": {
        "oplus_filter_qr_v4_send_skb": "RET_1",
        "oplus_filter_qr_v6_send_skb": "RET_1",
        "oplus_filter_qr_v4_receive_skb": "RET_1",
        "oplus_filter_qr_v6_receive_skb": "RET_1",
        "qr_monitor_netlink_nlmsg_handle": "RET_0",
        "oplus_qr_hooks_send_to_user": "RET_0",
    },
    "oplus_bsp_file_read_record.ko": {
        "oplus_frr_write": "RET_COUNT",
        "oplus_frr_read": "RET_0",
        "io_monitor_record": "RET_0",
        "trace_android_vh_filemap_read_hook": "RET_0",
        "trace_android_vh_filemap_map_pages_hook": "RET_0",
        "trace_android_vh_do_read_fault_hook": "RET_0",
    },
    "oplus_bsp_dfr_theia.ko": {
        "SendTheiaKevent": "RET_0",
        "SendDcsTheiaKevent": "RET_0",
        "theia_send_event": "RET_0",
        "theia_send_event_atomic": "RET_0",
        "send_black_screen_dcs_msg": "RET_0",
    },
    # === Newly Hollowed 15 (Zero-rmmod Full-Green Architecture) ===
    "oplus_network_dns_cache.ko": {
        "hfunc": "RET_1",
        "parse_lib": "RET_0",
        "report_nas": "RET_0",
        "dns_report_timeout_fun": "RET_0",
    },
    "oplus_network_snapshot.ko": {
        "oplus_dns_data_output_hook": "RET_1",
        "oplus_dns_data_input_hook": "RET_1",
        "network_stat_output_hook": "RET_1",
        "network_stat_input_hook": "RET_1",
        "hook_fun": "RET_0",
        "report_dns_data": "RET_0",
        "snapshot_report_timer_function": "RET_0",
        "dns_query_timeout": "RET_0",
    },
    "oplus_network_sk_predict.ko": {
        "handler_sys_socket_exit": "RET_0",
        "handler_inet_release": "RET_0",
        "notify_sk_predict_result": "RET_0",
    },
    "oplus_network_vip_task.ko": {
        "oplus_rx_thread_info_input_hook": "RET_1",
        "kprobe_oplus_vip_task_recvmsg_hook": "RET_0",
        "kprobe_oplus_vip_task_timeinfo_hook": "RET_0",
        "kretprobe_oplus_vip_task_timeinfo_hook": "RET_0",
        "report_vip_task_data": "RET_0",
        "report_vip_task_record_data": "RET_0",
        "report_vip_task_data_work_handler": "RET_0",
    },
    "oplus_network_linkpower_module.ko": {
        "asc_input_hook_v4": "RET_1",
        "asc_output_hook_v4": "RET_1",
        "asc_output_hook_v6": "RET_1",
        "asi_local_output_hook_v4": "RET_1",
        "my_input_hook_v4": "RET_1",
        "my_input_hook_v6": "RET_1",
        "my_output_hook_v4": "RET_1",
        "my_output_hook_v6": "RET_1",
        "spi_input_hook_v4": "RET_1",
        "spi_input_hook_v6": "RET_1",
        "spi_output_hook_v4": "RET_1",
        "spi_output_hook_v6": "RET_1",
        "hba_input_hook_v4": "RET_1",
        "hba_input_hook_v6": "RET_1",
        "hba_output_hook_v4": "RET_1",
        "hba_output_hook_v6": "RET_1",
        "hba_input_hook": "RET_1",
        "hba_output_hook": "RET_1",
        "my_output_hook": "RET_1",
        "sk_pid_hook_dsc_block_dns": "RET_0",
        "asyn_destroy_sk": "RET_0",
        "destroy_sk_asyn": "RET_0",
        "msc_close_sk_handler": "RET_0",
        "enable_firewall": "RET_0",
        "send_msg_to_user": "RET_0",
        "netlink_send_to_user": "RET_0",
        "send_msg_to_hba_user": "RET_0",
        "send_spi_msg_to_uplayer_async": "RET_0",
        "hbi_identified_asyn": "RET_0",
        "hbi_closed_asyn": "RET_0",
        "push_sk_detected_asyn": "RET_0",
        "push_sk_destroyed_asyn": "RET_0",
        "handler_tcp_connect": "RET_0",
        "handler_udp_connect": "RET_0",
        "handler_unix_stream_connect_ret": "RET_0",
        "handler_unix_stream_connect_entry": "RET_0",
        "proc_add_mdfw": "RET_0",
        "proc_remove_mdfw": "RET_0",
    },
    "oplus_network_score.ko": {
        "oplus_score_postrouting_hook4": "RET_1",
        "oplus_score_input_hook4": "RET_1",
        "oplus_score_postrouting_hook6": "RET_1",
        "oplus_score_input_hook6": "RET_1",
        "oplus_score_send_netlink_msg": "RET_0",
        "oplus_score_calc_and_report": "RET_0",
        "proc_set_test_link_index": "RET_0",
    },
    "oplus_network_tcpdump_enhance.ko": {
        "tcpdump_output_hook_v4": "RET_1",
        "tcpdump_output_hook_v6": "RET_1",
        "tcpdump_handle_record": "RET_0",
        "comm_netlink_inform_msg": "RET_0",
        "notify_netlink_event": "RET_0",
    },
    "oplus_network_app_monitor.ko": {
        "oplus_apps_monitor_postrouting_hook4": "RET_1",
        "oplus_apps_monitor_input_hook4": "RET_1",
        "oplus_apps_monitor_postrouting_hook6": "RET_1",
        "oplus_apps_monitor_input_hook6": "RET_1",
        "apps_monitor_netlink_send_to_user": "RET_0",
        "apps_monitor_report_apps_rtt_to_user": "RET_0",
        "apps_monitor_report_dev_rtt_to_user": "RET_0",
        "oplus_app_monitor_send_app_info_report": "RET_0",
        "oplus_app_monitor_send_beat_alarm": "RET_0",
        "oplus_app_monitor_send_push_alarm": "RET_0",
        "oplus_app_monitor_send_traffic_alarm": "RET_0",
        "proc_app_power_monitor_start": "RET_0",
        "proc_app_power_report_request": "RET_0",
        "proc_app_set_beat_alarm_period": "RET_0",
        "proc_app_set_push_alarm_period": "RET_0",
    },
    "oplus_network_stats_calc.ko": {
        "oplus_stats_calc_input_hook": "RET_1",
        "oplus_stats_calc_output_hook": "RET_1",
        "send_netlink_data": "RET_0",
        "add_iface_uid_stats": "RET_0",
    },
    "oplus_bsp_midas.ko": {
        "update_or_create_entry_locked": "RET_0",
        "binder_proc_transaction_hook": "RET_0",
        "binder_new_ref_hool": "RET_0",
        "binder_del_ref_hook": "RET_0",
        "midas_record_task_times": "RET_0",
        "rasm_suspend": "RET_0",
        "rasm_resume": "RET_0",
    },
    "mtk_mbraink.ko": {
        "lookup_tracepoints": "RET_0",
        "mbraink_sched_process_fork": "RET_0",
        "mbraink_sched_process_exit": "RET_0",
        "mbraink_binder_transaction": "RET_0",
        "mbraink_trace_android_vh_cpufreq_acct_update_power": "RET_0",
        "mbraink_sched_process_data_send": "RET_0",
        "mbraink_netlink_send_msg": "RET_0",
        "logmiscdata2mbrain": "RET_0",
        "mbraink_process_tracer_init": "RET_0",
        "insert_freq_qos_hook": "RET_0",
        "freq_qos_max_notifier_call": "RET_0",
        "freq_qos_min_notifier_call": "RET_0",
        "mbraink_get_process_memory_info": "RET_0",
        "mbraink_get_process_stat_info": "RET_0",
        "mbraink_get_thread_stat_info": "RET_0",
        "mbraink_processname_to_pid": "RET_0",
        "mbraink_get_tracing_pid_info": "RET_0",
        "mbraink_get_binder_trace_info": "RET_0",
        "mbraink_get_cpufreq_trace_info": "RET_0",
        "mbraink_get_cpufreq_notifier_info": "RET_0",
    },
    "mtk_mbraink_v6991.ko": {
        "ufs2mbrain_event_notify": "RET_0",
        "pt2mbrain_hint_low_battery_volt_throttle": "RET_0",
        "pt2mbrain_hint_battery_oc_throttle": "RET_0",
        "pt2mbrain_ppb_notify_func": "RET_0",
        "fpsgo2mbrain_hint_frameinfo": "RET_0",
        "fpsgo2mbrain_hint_perfinfo": "RET_0",
        "fpsgo2mbrain_hint_deleteperfinfo": "RET_0",
        "gpu2mbrain_hint_fenceTimeoutNotify": "RET_0",
        "gpu2mbrain_hint_GpuResetDoneNotify": "RET_0",
        "mbraink_sys_res_log": "RET_0",
        "update_mbraink_sys_res_record": "RET_0",
        "mbraink_update_sys_res_record": "RET_0",
        "mbraink_v6991_set_camera_hw_info": "RET_0",
    },
    "oplus_sys_stability_helper.ko": {
        "send_to_frk": "RET_0",
        "binder_buffer_watcher": "RET_0",
        "pending_transaction_watcher": "RET_0",
        "pending_transaction_watcher_do_work": "RET_0",
        "do_check_system_server_hang": "RET_0",
        "lowmem_report": "RET_0",
        "lowmem_report_func": "RET_0",
        "thread_watcher": "RET_0",
        "thread_watcher_do_work": "RET_0",
        "send_signal_catcher": "RET_0",
    },
    "oplus_bsp_sigkill_diagnosis.ko": {
        "record_sigkill_reason": "RET_0",
        "sigkill_reason_read": "RET_0",
    },
    "oplus_bsp_dfr_ubt.ko": {
        "access_process_vm_ubt": "RET_0",
        "dump_userspace_backtrace": "RET_0",
        "ubt_mmput": "RET_0",
        "ubt_mmput_fn": "RET_0",
        "userspace_backtrace_systrigger": "RET_0",
    },
    # === Newly Audited 3 Network Telemetry Modules (v3.1.0 -> 26 Total) ===
    # Note: oplus_bsp_dfr_combkey_monitor.ko is intentionally retained untouched for blkdev_fsync
    # emergency sync safety; its only telemetry sink (theia_send_event) is already hollowed in theia.ko.
    "oplus_network_dns_optimizer.ko": {
        "oplus_dns_race_postrouting_hook4": "RET_1",
        "oplus_dns_race_prerouting_hook4": "RET_1",
        "oplus_dns_race_postrouting_hook6": "RET_1",
        "oplus_dns_race_prerouting_hook6": "RET_1",
        "oplus_dns_reserve_local_in_hook4": "RET_1",
        "oplus_dns_reserve_local_in_hook6": "RET_1",
        "oplus_dns_reserve_postrouting_hook4": "RET_1",
        "oplus_dns_reserve_postrouting_hook6": "RET_1",
        "dns_race_report_record_timer_function": "RET_0",
        "dns_reserve_report_timer_fn": "RET_0",
        "dns_rtx_report_work": "RET_0",
        "dns_rtx_report_record_timer_function": "RET_0",
        "dns_send_work_fn": "RET_0",
        "oplus_dns_query_rtx_check": "RET_0",
        "oplus_dns_response_input_check": "RET_0",
        "oplus_dns_fast_transmit_dns_query": "RET_0",
        "oplus_dns_fast_transmit_dns_query_response": "RET_0",
        "parse_dns_data": "RET_0",
        "build_dns_response": "RET_0",
    },
    "oplus_network_fast_bwe.ko": {
        "oplus_fast_bwe_local_in_hook": "RET_1",
        "report_fast_bwe_result_timer": "RET_0",
    },
    "oplus_network_tuning.ko": {
        # Preserves BBR/CUBIC congestion control, net/oplus_bbr & net/oplus_dev sysctls
        "oplus_network_tuning_report_hook": "RET_1",
        "tcp_syn_hook": "RET_0",
        "tcp_syn_report": "RET_0",
    },
}


def patch_module(raw_bytes: bytes, mod_name: str, plan: dict) -> tuple[bytes, list, int]:
    buf = bytearray(raw_bytes)
    e_shoff = struct.unpack_from("<Q", buf, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 58)
    shdrs = [struct.unpack_from("<IIQQQQIIQQ", buf, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    shstr = buf[shdrs[e_shstrndx][4]:shdrs[e_shstrndx][4] + shdrs[e_shstrndx][5]]

    def sname(idx):
        return shstr[idx:shstr.find(b"\x00", idx)].decode("utf-8", "replace")

    secs = {sname(sh[0]): (i, sh) for i, sh in enumerate(shdrs)}
    text_idx, text_sh = secs[".text"]
    text_off, text_sz = text_sh[4], text_sh[5]

    rela_sh = secs.get(".rela.text", (None, None))[1]
    rela_entries = []
    if rela_sh:
        r_off_sec, r_sz_sec = rela_sh[4], rela_sh[5]
        for idx in range(r_sz_sec // 24):
            ro = r_off_sec + idx * 24
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", buf, ro)
            rela_entries.append((ro, r_offset, r_info))

    _, sym_sh = secs[".symtab"]
    str_sh = shdrs[sym_sh[6]]
    st_raw = buf[sym_sh[4]:sym_sh[4] + sym_sh[5]]
    str_raw = buf[str_sh[4]:str_sh[4] + str_sh[5]]

    funcs = {}
    for off in range(0, len(st_raw), 24):
        sn, si, so, ss, sv, sz = struct.unpack_from("<IBBHQQ", st_raw, off)
        if sn and ss == text_idx and (si & 0xF) == 2:
            name = str_raw[sn:str_raw.find(b"\x00", sn)].decode("utf-8", "replace")
            funcs.setdefault(name, []).append((sv, sz))

    report = []
    neutralized_relas = 0
    for fn, ptype in plan.items():
        if fn not in funcs:
            raise RuntimeError(f"{mod_name}: missing STT_FUNC {fn}")
        for sv, sz in funcs[fn]:
            foff = text_off + sv
            has_pac = bytes(buf[foff:foff + 4]) == PACIASP
            patch = PATCH_BYTES_PAC[ptype] if has_pac else PATCH_BYTES_NOPAC[ptype]
            if sz < len(patch):
                raise RuntimeError(f"{mod_name}:{fn} too small ({sz} < {len(patch)})")
            if sv + len(patch) > text_sz:
                raise RuntimeError(f"{mod_name}:{fn} exceeds .text bounds")
            for ro, r_offset, r_info in rela_entries:
                if sv <= r_offset < sv + len(patch) and r_info != 0:
                    # Rewrite overwritten prologue relocation to R_AARCH64_NONE (0)
                    struct.pack_into("<Q", buf, ro + 8, 0)
                    neutralized_relas += 1
            buf[foff:foff + len(patch)] = patch
            report.append((fn, ptype, has_pac, foff, len(patch)))

    return bytes(buf), report, neutralized_relas


def extract_vermagic(raw_bytes: bytes) -> str:
    e_shoff = struct.unpack_from("<Q", raw_bytes, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", raw_bytes, 58)
    shdrs = [struct.unpack_from("<IIQQQQIIQQ", raw_bytes, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    shstr = raw_bytes[shdrs[e_shstrndx][4]:shdrs[e_shstrndx][4] + shdrs[e_shstrndx][5]]
    for sh in shdrs:
        name = shstr[sh[0]:shstr.find(b"\x00", sh[0])].decode("utf-8", "replace")
        if name == ".modinfo":
            for entry in raw_bytes[sh[4]:sh[4] + sh[5]].split(b"\x00"):
                if entry.startswith(b"vermagic="):
                    return entry[9:].decode("utf-8", "replace").strip()
    return ""


def load_stock_bytes(zf: zipfile.ZipFile, tf: tarfile.TarFile, mod_fn: str) -> bytes:
    zip_member = "monitoring_drivers/" + mod_fn
    if zip_member in zf.namelist():
        return zf.read(zip_member)
    for tar_member in (f"vendor/lib/modules/{mod_fn}", f"vendor_dlkm/lib/modules/{mod_fn}"):
        try:
            f = tf.extractfile(tar_member)
            if f is not None:
                return f.read()
        except KeyError:
            pass
    raise FileNotFoundError(f"Stock module not found in ZIP or TAR: {mod_fn}")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    manifest_drivers = {}
    with zipfile.ZipFile(STOCK_ZIP, "r") as zf, tarfile.open(VENDOR_TAR, "r:gz") as tf:
        for mod_fn, plan in PATCH_PLAN.items():
            raw = load_stock_bytes(zf, tf, mod_fn)
            patched, rep, n_rel = patch_module(raw, mod_fn, plan)
            out_path = os.path.join(OUT_DIR, mod_fn)
            with open(out_path, "wb") as f:
                f.write(patched)
            sha_orig = hashlib.sha256(raw).hexdigest()
            sha_new = hashlib.sha256(patched).hexdigest()
            vm = extract_vermagic(patched)
            manifest_drivers[mod_fn] = {
                "module": mod_fn[:-3],
                "size": len(patched),
                "sha256": sha_new,
                "stock_sha256": sha_orig,
                "vermagic": vm,
                "kernel_release": vm.split()[0] if vm else "",
                "arch": vm.split()[-1] if vm else "",
                "patched_functions": len(rep),
                "neutralized_relas": n_rel,
            }
            print(f"[OK] {mod_fn:34s} | {len(rep):2d} funcs | relas_noped={n_rel:2d} | hollow={sha_new[:12]}")

    manifest_path = os.path.join(OUT_DIR, "manifest.json")
    manifest = {
        "schema_version": 4,
        "architecture": "26_hollow_preempt",
        "target_kernel": "6.6.118-android15-8-o-g15bab650beb0-4k",
        "target_arch": "aarch64",
        "drivers": manifest_drivers,
    }
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"[OK] {len(manifest_drivers)}-module manifest written -> {manifest_path}")


if __name__ == "__main__":
    main()
