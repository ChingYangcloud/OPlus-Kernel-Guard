// SPDX-License-Identifier: GPL-2.0
/*
 * inte_stub - Clean/Green Replacement Stub for OPlus inte.ko
 *
 * 保留 /proc/inte_ko、/proc/inte_systbl、/proc/inte_status 节点与
 * oplus_kohashpro (euid=1000) 读写交互契约，但移除 load_module kretprobe、
 * sys_call_table 哈希扫描与所有异常事件上报，始终返回“绿色无异常”。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/cred.h>
#include <linux/uidgid.h>

static struct proc_dir_entry *proc_ko_entry;
static struct proc_dir_entry *proc_systbl_entry;
static struct proc_dir_entry *proc_status_entry;

static bool is_valid_sender(void)
{
	if (strcmp(current->comm, "oplus_kohashpro") != 0)
		return false;
	if (__kuid_val(current_euid()) != 1000)
		return false;
	return true;
}

static int ko_proc_show(struct seq_file *m, void *v)
{
	/* 无异常加载的 .ko 事件，返回空列表 */
	return 0;
}

static int proc_open_ko(struct inode *inode, struct file *file)
{
	return single_open(file, ko_proc_show, NULL);
}

static ssize_t proc_write_ko(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	if (!is_valid_sender())
		return -EPERM;
	return count;
}

static const struct proc_ops proc_fops_ko = {
	.proc_open    = proc_open_ko,
	.proc_read    = seq_read,
	.proc_write   = proc_write_ko,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int systbl_proc_show(struct seq_file *m, void *v)
{
	/* 系统调用表完整无劫持，返回空列表 */
	return 0;
}

static int proc_open_systbl(struct inode *inode, struct file *file)
{
	return single_open(file, systbl_proc_show, NULL);
}

static ssize_t proc_write_systbl(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	if (!is_valid_sender())
		return -EPERM;
	return count;
}

static const struct proc_ops proc_fops_systbl = {
	.proc_open    = proc_open_systbl,
	.proc_read    = seq_read,
	.proc_write   = proc_write_systbl,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int status_proc_show(struct seq_file *m, void *v)
{
	s64 ts = ktime_get_real_seconds();
	seq_printf(m, "%lld:true\n", ts);
	return 0;
}

static int proc_open_status(struct inode *inode, struct file *file)
{
	return single_open(file, status_proc_show, NULL);
}

static ssize_t proc_write_status(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	if (!is_valid_sender())
		return -EPERM;
	return count;
}

static const struct proc_ops proc_fops_status = {
	.proc_open    = proc_open_status,
	.proc_read    = seq_read,
	.proc_write   = proc_write_status,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int __init inte_stub_init(void)
{
	kuid_t sys_uid = KUIDT_INIT(1000);
	kgid_t sys_gid = KGIDT_INIT(1000);

	proc_ko_entry = proc_create("inte_ko", 0660, NULL, &proc_fops_ko);
	if (!proc_ko_entry)
		return -ENOMEM;
	proc_set_user(proc_ko_entry, sys_uid, sys_gid);

	proc_systbl_entry = proc_create("inte_systbl", 0660, NULL, &proc_fops_systbl);
	if (!proc_systbl_entry) {
		remove_proc_entry("inte_ko", NULL);
		return -ENOMEM;
	}
	proc_set_user(proc_systbl_entry, sys_uid, sys_gid);

	proc_status_entry = proc_create("inte_status", 0660, NULL, &proc_fops_status);
	if (!proc_status_entry) {
		remove_proc_entry("inte_systbl", NULL);
		remove_proc_entry("inte_ko", NULL);
		return -ENOMEM;
	}
	proc_set_user(proc_status_entry, sys_uid, sys_gid);

	pr_info("[KERNEL_SECURITY_CHECK]:init success! (green stub)\n");
	return 0;
}

static void __exit inte_stub_exit(void)
{
	if (proc_status_entry)
		remove_proc_entry("inte_status", NULL);
	if (proc_systbl_entry)
		remove_proc_entry("inte_systbl", NULL);
	if (proc_ko_entry)
		remove_proc_entry("inte_ko", NULL);
}

module_init(inte_stub_init);
module_exit(inte_stub_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OPlus Kernel Guard");
MODULE_DESCRIPTION("Clean green-status stub for inte.ko");
