#include <linux/stdarg.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/printk.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PlayingPeano");
MODULE_DESCRIPTION("nulldump");
MODULE_VERSION("0.1");

#define DEVICE_NAME  "nulldump"
#define CLASS_NAME   "nulldump_class"
#define DUMP_MAX     256

static dev_t dev;
static struct cdev nulldump_cdev;
static struct class *nulldump_class;
static struct device *sdev;

static ssize_t nulldump_read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
	pr_info("nulldump: read len=%zu by pid=%d (%s)\n",
		len, current->pid, current->comm);
	return 0;
}

static ssize_t nulldump_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	size_t to_copy;
	unsigned char kbuf[DUMP_MAX];

	pr_info("nulldump: write len=%zu by pid=%d (%s)\n",
		len, current->pid, current->comm);

	size_t offset = 0;
	while (offset < len) {
		to_copy = min(DUMP_MAX, len - offset);
		if (copy_from_user(kbuf, buf + offset, to_copy)) {
			pr_warn("nulldump: copy_from_user failed, ...");
			return -EFAULT;
		}
		print_hex_dump(KERN_INFO, "nulldump: ", DUMP_PREFIX_OFFSET, 16, 1, kbuf, to_copy, true);
		offset += to_copy;
	}
	return len;
}

static const struct file_operations nulldump_fops = {
	.owner = THIS_MODULE,
	.read  = nulldump_read,
	.write = nulldump_write,
};

static int __init nulldump_init(void)
{
	int ret;

	if ((ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME))) 
	{
		pr_err("nulldump: alloc_chrdev_region failed\n");
		return ret;
	}

	pr_info("nulldump: registered major=%d minor=%d\n", MAJOR(dev), MINOR(dev));

	cdev_init(&nulldump_cdev, &nulldump_fops);
	nulldump_cdev.owner = THIS_MODULE;

	if ((ret = cdev_add(&nulldump_cdev, dev, 1))) 
	{
		pr_err("nulldump: cdev_add failed\n");
		goto err_unregister;
	}

	if (IS_ERR(nulldump_class = class_create(CLASS_NAME))) 
	{
		pr_err("nulldump: class_create failed\n");
		ret = PTR_ERR(nulldump_class);
		goto err_cdev_del;
	}

	if (IS_ERR(sdev = device_create(nulldump_class, NULL, dev, NULL, DEVICE_NAME))) 
	{
		pr_err("nulldump: device_create failed\n");
		ret = PTR_ERR(sdev);
		goto err_class_destroy;
	}

	pr_info("nulldump: module loaded, device /dev/%s\n", DEVICE_NAME);
	return 0;

err_class_destroy:
	class_destroy(nulldump_class);
err_cdev_del:
	cdev_del(&nulldump_cdev);
err_unregister:
	unregister_chrdev_region(dev, 1);
	return ret;
}

static void __exit nulldump_exit(void)
{
	device_destroy(nulldump_class, dev);
	class_destroy(nulldump_class);
	cdev_del(&nulldump_cdev);
	unregister_chrdev_region(dev, 1);
	pr_info("nulldump: module unloaded\n");
}

module_init(nulldump_init);
module_exit(nulldump_exit);

