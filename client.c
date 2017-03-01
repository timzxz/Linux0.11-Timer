#define __LIBRARY__
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
_syscall1(int,gettime,int,time);
_syscall2(int,reboot,int,time,int,type);
_syscall3(int,myexecve,char *,name,char **,argv,char **,envp);
_syscall1(int,addname,char *,name);
_syscall0(int,sync);
static char * argv_rc[]={"","","","","","","",NULL};
static char * envp_rc[]={"HOME=/",NULL};
void mycpy(char* dst,char* src);
int main(int argc,char* argv[])
{
    int pid,i,j,num,time;
    for(i=1;i<argc-1;i++)
    {
	argv_rc[i-1]=strdup(argv[i]);
    }
    num=i;
    for(i=1;i<=8;i++)
    {
        if (i<argc-1)
            NULL;
        else
            argv_rc[i-1]=NULL;
    }
    time=atoi(argv[num]);
    gettime(time);
    if(!(pid=fork()))
    {
        if((strcmp(argv[1],"reboot")!=0)&&(strcmp(argv[1],"shutdown")!=0))
        {
            addname(argv[1]);
            myexecve(strcat("/usr/bin/",argv[1]),argv_rc,envp_rc);
            printf("JUMP\n");
            myexecve(strcat("/usr/local/bin/",argv[1]),argv_rc,envp_rc);
            printf("JUMP\n");
            myexecve(strcat("/usr/root/",argv[1]),argv_rc,envp_rc);
            printf("JUMP\n");
            myexecve(strcat("/bin/",argv[1]),argv_rc,envp_rc);
            printf("JUMP\n");
            myexecve(strcat("/mnt/bin/",argv[1]),argv_rc,envp_rc);
            printf("JUMP\n");
        }
        else
        {
            sync();
            if(strcmp(argv[1],"reboot")==0)
                reboot(time,1);
            else
                reboot(time,0);
        }
    }
    return 0;
}
