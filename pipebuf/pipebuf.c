#include <linux/stdarg.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kfifo.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rwsem.h>
#include <linux/moduleparam.h>

#include "pipebuf_ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PlayingPeano");
MODULE_DESCRIPTION("Pipe-like buffered character devices");
MODULE_VERSION("0.1");

#define DEVICE_NAME  "pipebuf"
#define CLASS_NAME   "pipebuf_class"
#define MAX_DEVICES  64

struct pipebuf_device {
	struct cdev cdev;
	struct device *device;
	struct kfifo fifo;
	struct mutex lock;
	wait_queue_head_t read_queue;
	wait_queue_head_t write_queue;
	int readers;
	int writers;
	size_t bufsize;
	dev_t devno;
};

static dev_t base_dev;
static struct class *pipebuf_class;
static struct pipebuf_device *devices[MAX_DEVICES];
static DECLARE_RWSEM(devices_sem);
static bool module_ready;

static int num_devices = 2;
static int default_bufsize = 4096;

static const struct file_operations pipebuf_fops;

static ssize_t bufsize_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	int minor = MINOR(dev->devt) - MINOR(base_dev);
	struct pipebuf_device *pdev;
	ssize_t ret;

	down_read(&devices_sem);
	pdev = devices[minor];
	if (!pdev) {
		up_read(&devices_sem);
		return -ENODEV;
	}
	ret = sprintf(buf, "%zu\n", pdev->bufsize);
	up_read(&devices_sem);
	return ret;
}

static ssize_t bufsize_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	int minor = MINOR(dev->devt) - MINOR(base_dev);
	struct pipebuf_device *pdev;
	unsigned long size;
	int ret;

	ret = kstrtoul(buf, 10, &size);
	if (ret)
		return ret;
	if (size == 0 || size > (1 << 20))
		return -EINVAL;

	down_read(&devices_sem);
	pdev = devices[minor];
	if (!pdev) {
		up_read(&devices_sem);
		return -ENODEV;
	}

	mutex_lock(&pdev->lock);
	if (!kfifo_is_empty(&pdev->fifo)) {
		mutex_unlock(&pdev->lock);
		up_read(&devices_sem);
		return -EBUSY;
	}
	kfifo_free(&pdev->fifo);
	ret = kfifo_alloc(&pdev->fifo, size, GFP_KERNEL);
	if (ret) {
		if (kfifo_alloc(&pdev->fifo, pdev->bufsize, GFP_KERNEL))
			pr_err("pipebuf: failed to restore fifo\n");
		mutex_unlock(&pdev->lock);
		up_read(&devices_sem);
		return ret;
	}
	pdev->bufsize = kfifo_size(&pdev->fifo);
	mutex_unlock(&pdev->lock);
	up_read(&devices_sem);

	return count;
}

static DEVICE_ATTR_RW(bufsize);

static int pipebuf_create_device(int index)
{
	struct pipebuf_device *dev;
	int ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->devno = MKDEV(MAJOR(base_dev), MINOR(base_dev) + index);
	dev->bufsize = default_bufsize;

	ret = kfifo_alloc(&dev->fifo, dev->bufsize, GFP_KERNEL);
	if (ret)
		goto err_free;
	dev->bufsize = kfifo_size(&dev->fifo);

	mutex_init(&dev->lock);
	init_waitqueue_head(&dev->read_queue);
	init_waitqueue_head(&dev->write_queue);

	cdev_init(&dev->cdev, &pipebuf_fops);
	dev->cdev.owner = THIS_MODULE;

	ret = cdev_add(&dev->cdev, dev->devno, 1);
	if (ret)
		goto err_fifo;

	dev->device = device_create(pipebuf_class, NULL, dev->devno,
				    NULL, "%s%d", DEVICE_NAME, index);
	if (IS_ERR(dev->device)) {
		ret = PTR_ERR(dev->device);
		goto err_cdev;
	}

	ret = device_create_file(dev->device, &dev_attr_bufsize);
	if (ret)
		goto err_device;

	devices[index] = dev;
	pr_info("pipebuf: created pipebuf%d (bufsize=%zu)\n",
		index, dev->bufsize);
	return 0;

err_device:
	device_destroy(pipebuf_class, dev->devno);
err_cdev:
	cdev_del(&dev->cdev);
err_fifo:
	kfifo_free(&dev->fifo);
err_free:
	kfree(dev);
	return ret;
}

static void pipebuf_destroy_device(int index)
{
	struct pipebuf_device *dev = devices[index];

	if (!dev)
		return;

	device_remove_file(dev->device, &dev_attr_bufsize);
	device_destroy(pipebuf_class, dev->devno);
	cdev_del(&dev->cdev);
	kfifo_free(&dev->fifo);
	kfree(dev);
	devices[index] = NULL;
	pr_info("pipebuf: destroyed pipebuf%d\n", index);
}

static int num_devices_set(const char *val, const struct kernel_param *kp)
{
	int new_count, old_count;
	int i, ret;

	ret = kstrtoint(val, 10, &new_count);
	if (ret)
		return ret;
	if (new_count < 0 || new_count > MAX_DEVICES)
		return -EINVAL;

	if (!module_ready) {
		num_devices = new_count;
		return 0;
	}

	down_write(&devices_sem);
	old_count = num_devices;

	if (new_count > old_count) {
		for (i = old_count; i < new_count; i++) {
			ret = pipebuf_create_device(i);
			if (ret) {
				while (--i >= old_count)
					pipebuf_destroy_device(i);
				up_write(&devices_sem);
				return ret;
			}
		}
	} else if (new_count < old_count) {
		for (i = old_count - 1; i >= new_count; i--) {
			if (devices[i] &&
			    (devices[i]->readers > 0 ||
			     devices[i]->writers > 0)) {
				up_write(&devices_sem);
				pr_warn("pipebuf: pipebuf%d in use, cannot remove\n", i);
				return -EBUSY;
			}
		}
		for (i = old_count - 1; i >= new_count; i--)
			pipebuf_destroy_device(i);
	}

	num_devices = new_count;
	up_write(&devices_sem);
	return 0;
}

static const struct kernel_param_ops num_devices_ops = {
	.set = num_devices_set,
	.get = param_get_int,
};

module_param_cb(num_devices, &num_devices_ops, &num_devices, 0644);
MODULE_PARM_DESC(num_devices, "Number of pipebuf devices (changeable)");

module_param(default_bufsize, int, 0644);
MODULE_PARM_DESC(default_bufsize, "Default buffer size for new devices");

static int pipebuf_open(struct inode *inode, struct file *filp)
{
	int minor = iminor(inode);
	struct pipebuf_device *dev;

	down_read(&devices_sem);
	if (minor < 0 || minor >= MAX_DEVICES || !devices[minor]) {
		up_read(&devices_sem);
		return -ENODEV;
	}
	dev = devices[minor];

	mutex_lock(&dev->lock);

	if (filp->f_mode & FMODE_READ) {
		if (dev->readers > 0) {
			mutex_unlock(&dev->lock);
			up_read(&devices_sem);
			return -EBUSY;
		}
		dev->readers++;
	}
	if (filp->f_mode & FMODE_WRITE)
		dev->writers++;

	filp->private_data = dev;
	mutex_unlock(&dev->lock);
	up_read(&devices_sem);
	return 0;
}

static int pipebuf_release(struct inode *inode, struct file *filp)
{
	struct pipebuf_device *dev = filp->private_data;

	mutex_lock(&dev->lock);
	if (filp->f_mode & FMODE_READ)
		dev->readers--;
	if (filp->f_mode & FMODE_WRITE) {
		dev->writers--;
		if (dev->writers == 0)
			wake_up_interruptible(&dev->read_queue);
	}
	wake_up_interruptible(&dev->write_queue);
	mutex_unlock(&dev->lock);
	return 0;
}

static ssize_t pipebuf_read(struct file *filp, char __user *buf,
			    size_t count, loff_t *off)
{
	struct pipebuf_device *dev = filp->private_data;
	unsigned int copied;
	int ret;

	mutex_lock(&dev->lock);

	while (kfifo_is_empty(&dev->fifo)) {
		if (dev->writers == 0) {
			mutex_unlock(&dev->lock);
			return 0;
		}
		mutex_unlock(&dev->lock);

		ret = wait_event_interruptible(dev->read_queue,
			!kfifo_is_empty(&dev->fifo) || dev->writers == 0);
		if (ret)
			return -ERESTARTSYS;

		mutex_lock(&dev->lock);
	}

	ret = kfifo_to_user(&dev->fifo, buf, count, &copied);
	mutex_unlock(&dev->lock);

	if (ret)
		return ret;

	wake_up_interruptible(&dev->write_queue);
	return copied;
}

static ssize_t pipebuf_write(struct file *filp, const char __user *buf,
			     size_t count, loff_t *off)
{
	struct pipebuf_device *dev = filp->private_data;
	unsigned int copied;
	int ret;

	mutex_lock(&dev->lock);

	while (kfifo_is_full(&dev->fifo)) {
		mutex_unlock(&dev->lock);

		ret = wait_event_interruptible(dev->write_queue,
			!kfifo_is_full(&dev->fifo));
		if (ret)
			return -ERESTARTSYS;

		mutex_lock(&dev->lock);
	}

	ret = kfifo_from_user(&dev->fifo, buf, count, &copied);
	mutex_unlock(&dev->lock);

	if (ret)
		return ret;

	wake_up_interruptible(&dev->read_queue);
	return copied;
}

static long pipebuf_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	struct pipebuf_device *dev = filp->private_data;
	unsigned long size;
	int ret;

	switch (cmd) {
	case PIPEBUF_IOC_GET_BUFSIZE:
		mutex_lock(&dev->lock);
		size = dev->bufsize;
		mutex_unlock(&dev->lock);
		if (copy_to_user((unsigned long __user *)arg,
				 &size, sizeof(size)))
			return -EFAULT;
		return 0;

	case PIPEBUF_IOC_SET_BUFSIZE:
		if (copy_from_user(&size, (unsigned long __user *)arg,
				   sizeof(size)))
			return -EFAULT;
		if (size == 0 || size > (1 << 20))
			return -EINVAL;

		mutex_lock(&dev->lock);
		if (!kfifo_is_empty(&dev->fifo)) {
			mutex_unlock(&dev->lock);
			return -EBUSY;
		}
		kfifo_free(&dev->fifo);
		ret = kfifo_alloc(&dev->fifo, size, GFP_KERNEL);
		if (ret) {
			if (kfifo_alloc(&dev->fifo, dev->bufsize, GFP_KERNEL))
				pr_err("pipebuf: failed to restore fifo\n");
			mutex_unlock(&dev->lock);
			return ret;
		}
		dev->bufsize = kfifo_size(&dev->fifo);
		mutex_unlock(&dev->lock);
		return 0;

	default:
		return -ENOTTY;
	}
}

static const struct file_operations pipebuf_fops = {
	.owner          = THIS_MODULE,
	.open           = pipebuf_open,
	.release        = pipebuf_release,
	.read           = pipebuf_read,
	.write          = pipebuf_write,
	.unlocked_ioctl = pipebuf_ioctl,
};

static int __init pipebuf_init(void)
{
	int ret, i;

	if (num_devices < 0 || num_devices > MAX_DEVICES)
		return -EINVAL;

	ret = alloc_chrdev_region(&base_dev, 0, MAX_DEVICES, DEVICE_NAME);
	if (ret) {
		pr_err("pipebuf: alloc_chrdev_region failed\n");
		return ret;
	}

	pipebuf_class = class_create(CLASS_NAME);
	if (IS_ERR(pipebuf_class)) {
		ret = PTR_ERR(pipebuf_class);
		goto err_unregister;
	}

	for (i = 0; i < num_devices; i++) {
		ret = pipebuf_create_device(i);
		if (ret)
			goto err_destroy;
	}

	module_ready = true;
	pr_info("pipebuf: loaded, %d devices (default_bufsize=%d)\n",
		num_devices, default_bufsize);
	return 0;

err_destroy:
	while (--i >= 0)
		pipebuf_destroy_device(i);
	class_destroy(pipebuf_class);
err_unregister:
	unregister_chrdev_region(base_dev, MAX_DEVICES);
	return ret;
}

static void __exit pipebuf_exit(void)
{
	int i;

	down_write(&devices_sem);
	for (i = 0; i < MAX_DEVICES; i++)
		if (devices[i])
			pipebuf_destroy_device(i);
	up_write(&devices_sem);

	class_destroy(pipebuf_class);
	unregister_chrdev_region(base_dev, MAX_DEVICES);
	pr_info("pipebuf: unloaded\n");
}

module_init(pipebuf_init);
module_exit(pipebuf_exit);
