// SPDX-License-Identifier: GPL-2.0-only
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

static const struct lsm_id impulse_lsmid = {
    .name = "impulse",
    .id = LSM_ID_UNDEF,
};

/*==== Directories from which program execution is prohibited ====*/
static const char * const impulse_deny_prefixes[] = {
	"/tmp/",
	"/dev/shm/",
};

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
