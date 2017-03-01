#include <linux/kernel.h>
#include <linux/tty.h>
#include <linux/sched.h>
#include <linux/head.h>
#include <asm/system.h>
#include <asm/io.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <linux/fs.h>
void do_reboot()
{
    outb(0xfe,0x64);
}
void do_shutdown()
{
    outb(0xf8,0x20);
}
int sys_reboot(int time,int type)
{
    if(type)
        add_timer(time*50,do_reboot,"reboot");
    else
        add_timer(time*50,do_shutdown,"shutdown");
    return 0;
}

