// SPDX-License-Identifier: GPL-2.0-only
/*
 * Impulse LSM: blocking program exec from /tmp and /dev/shm
 * and an event log at /sys/kernel/securityinmpulse/log
 */
#include <linux/lsm_hooks.h>
#include <linux/binfmts.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/math64.h>
#include <linux/timekeeping.h>

#define IMPULSE_LOG_SIZE	128
#define IMPULSE_PATH_LEN	128

struct impulse_event {
	u64 ms;
	pid_t pid;
	u32 uid;
	char action[16];
	char comm[TASK_COMM_LEN];
	char path[IMPULSE_PATH_LEN];
};

/* ==== Circular buffer: old events are overwritten by new ones ==== */
static struct impulse_event impulse_events[IMPULSE_LOG_SIZE];
static unsigned int impulse_log_head;
static DEFINE_SPINLOCK(impulse_log_lock);

static const struct lsm_id impulse_lsmid = {
    .name = "impulse",
    .id = LSM_ID_UNDEF,
};

/*==== Directories from which program execution is prohibited ====*/
static const char * const impulse_deny_prefixes[] = {
	"/tmp/",
	"/dev/shm/",
};

static void impulse_log_add(const char *action, const char *path)
{
	struct impulse_event *ev;
	unsigned long flags;
	
	spin_lock_irqsave(&impulse_log_lock, flags);
	ev = &impulse_events[impulse_log_head % IMPULSE_LOG_SIZE];
	ev->ms = div_u64(ktime_get_boottime_ns(), NSEC_PER_MSEC);
	ev->pid = task_pid_nr(current);
	ev->uid = from_kuid(&init_user_ns, current_uid());
	strscpy(ev->action, action, sizeof(ev->action));
	strscpy(ev->comm, current->comm, sizeof(ev->comm));
	strscpy(ev->path, path, sizeof(ev->path));
	impulse_log_head++;
	spin_unlock_irqrestore(&impulse_log_lock, flags);
}

static int impulse_bprm_check(struct linux_binprm *bprm)
{
    char *buf, *path;
    int ret = 0;
    int i;
    
    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
	    return -ENOMEM; /* it is safer to refuse than to let through */
    
    path = d_path(&bprm->file->f_path, buf, PATH_MAX);
    if (IS_ERR(path))
	    goto out;
    
    for (i = 0; i < ARRAY_SIZE(impulse_deny_prefixes); i++) {
	if (!strncmp(path, impulse_deny_prefixes[i],
		 strlen(impulse_deny_prefixes[i]))) {
	    pr_warn("Impulse LSM: BLOCKED exec %s (pid=%d comm=%s uid=%u)\n",
		path, task_pid_nr(current), current->comm,
		from_kuid(&init_user_ns, current_uid()));
			impulse_log_add("exec_blocked", path);
	    ret = -EACCES;
	    break;
	}
    }
out:
    kfree(buf);
    return ret;
}

static struct security_hook_list impulse_hooks[] __ro_after_init = {
    LSM_HOOK_INIT(bprm_check_security, impulse_bprm_check),
};

/* ==== securityfs: /sys/kernel/security/impulse/log ==== */

static int impulse_log_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	unsigned int start, i;
	
	spin_lock_irqsave(&impulse_log_lock, flags);
	start = impulse_log_head > IMPULSE_LOG_SIZE ?
	    impulse_log_head - IMPULSE_LOG_SIZE : 0;
	for (i = start; i < impulse_log_head; i++) {
		const struct impulse_event *ev =
		    &impulse_events[i % IMPULSE_LOG_SIZE];
		u32 rem;
		u64 sec = div_u64_rem(ev->ms, 1000, &rem);
		
		/* seq time.action pid uid comm path */
		seq_printf(m, "%u\t%llu.%03u\t%s\t%d\t%u\t%s\t%s\n",
		       i, sec, rem, ev->action, ev->pid, ev->uid,
		       ev->comm, ev->path);
	}
	spin_unlock_irqrestore(&impulse_log_lock, flags);
	return 0;
}

static int impulse_log_open(struct inode *inode, struct file *file)
{
	return single_open(file, impulse_log_show, NULL);
}

static const struct file_operations impulse_log_fops = {
	.open = impulse_log_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* ==== securityfs appears after LSM initialization, hence the separate initcall ==== */
static int __init impulse_fs_init(void)
{
	struct dentry *dir, *file;
	
	dir = securityfs_create_dir("impulse", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);
	
	file = securityfs_create_file("log", 0400, dir, NULL,
	&impulse_log_fops);
	if (IS_ERR(file)) {
		securityfs_remove(dir);
		return PTR_ERR(file);
	}
	return 0;
}
late_initcall(impulse_fs_init);

static int __init impulse_init(void)
{
    security_add_hooks(impulse_hooks, ARRAY_SIZE(impulse_hooks),
               &impulse_lsmid);
    pr_info("Impulse LSM: initialized\n");
    return 0;
}

DEFINE_LSM(impulse) = {
    .name = "impulse",
    .init = impulse_init,
};
