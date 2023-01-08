#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/ioctl.h>

#define DEVICE_NAME "kcks"
#define CLASS_NAME "kcks"

MODULE_LICENSE("GPL");

static int device_open(struct inode *inode, struct file *filp)
{
    // printk(KERN_ALERT "Device opened.\n");
    return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
    // printk(KERN_ALERT "Device closed.\n");
    return 0;
}

static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
    return 0;
}

static ssize_t device_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
    return 0;
}

struct param
{
    unsigned long address;
};

void (*blank)(void);
static long device_ioctl(struct file *filp, unsigned int ioctl_num, unsigned long ioctl_param)
{
    struct param req;
    if (copy_from_user((void *)&req, (void *)ioctl_param, sizeof(req)))
    {
        printk(KERN_ALERT "COPYING ERROR!\n");
    }

    else
    {
        printk(KERN_ALERT "COPIED LESGO!\n");
        blank = req.address;
        blank();
    }

    return 0;
}

static struct file_operations fops = {
    .read = device_read,
    .write = device_write,
    .unlocked_ioctl = device_ioctl,
    .open = device_open,
    .release = device_release};

struct proc_dir_entry *proc_entry = NULL;

int init_module(void)
{
    proc_entry = proc_create("kcks", 0666, NULL, &fops);
    return 0;
}

void cleanup_module(void)
{
    if (proc_entry)
        proc_remove(proc_entry);
}
