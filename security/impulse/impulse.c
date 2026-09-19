// SPDX-License-Identifier: GPL-2.0-only
#include <linux/lsm_hooks.h>
#include <linux/binfmts.h>
#include <linux/init.h>

static const struct lsm_id impulse_lsmid = {
    .name = "impulse",
    .id = LSM_ID_UNDEF,
};

static int impulse_bprm_check(struct linux_binprm *bprm)
{
    return 0;
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
