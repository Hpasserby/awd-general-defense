// gcc defense.c -o defense -pthread -std=c99
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>  
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <strings.h>

/**********config************/
#define BIN_PATH "/tmp/pwn"	// 原题目文件移动到此处
#define BIN_NAME "pwn"		// 题目命名 用于log文件
#define BUF_SIZE 0x2000

int enable_send_filter	= 0;	// 开启转发过滤，简单敏感字段匹配，可以不用开启
int enable_recv_filter	= 0;	// 开启转发过滤，简单敏感字段匹配，可以不用开启
int enable_shell_filter = 1;	// 若发现getshell，将过滤shell_list列表内容，推荐开启
char* recv_filter_list[] = {"\x7f", "\x55", "\x80"};	//过滤词
char* send_filter_list[] = {"\x7f", "\x55", "\x80"};	//过滤词
char* shell_list[]	= {"whoami", "ls", "cat ", "cd ", "curl ", "vim", "echo "};
// normal_list 需要尽可能包含程序运行中所能够打印的单词（白名单），用于判定当前程序是否正常运行，检测getshell
char* normal_list[]	= {"name", "show", "add", "remove", "choice", "content", "done", "length", "bye"};
/****************************/

#define SEND_MODE	0	// defence将流量转发给程序
#define RECV_MODE	1	// defence从程序接收响应

#define NOT_SHELL	0
#define GET_SHELL	1
#define MAYBE_SHELL	2
int get_shell = 0;

FILE* log_fp;
char logname[256];

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void recvlog(char* buf, int nbytes)
{
    fseek(log_fp, 0, SEEK_END);
    fprintf(log_fp, "p.recvuntil('");
    for(int i = 0; i < nbytes; i++)
        fprintf(log_fp, "\\x%.2x", (int)buf[i] & 0xff);
    fprintf(log_fp, "')\n");

    fprintf(log_fp, "\'\'\'\n");
    fprintf(log_fp, "Received: \n");
    fprintf(log_fp, "%s", buf);
    fprintf(log_fp, "\n\'\'\'\n");
}

void sendlog(char* buf, int nbytes)
{
    fseek(log_fp, 0, SEEK_END);
    fprintf(log_fp, "p.send('");
    for(int i = 0; i < nbytes; i++)
        fprintf(log_fp, "\\x%.2x", (int)buf[i] & 0xff);
    fprintf(log_fp, "')\n");

    fprintf(log_fp, "\'\'\'\n");
    fprintf(log_fp, "Sent: \n");
    fprintf(log_fp, "%s", buf);
    fprintf(log_fp, "\n\'\'\'\n");
}

int recv_filter(char* buf)
{
	if(enable_recv_filter)	
	{	
		for(int i = 0; i < sizeof(recv_filter_list)/sizeof(char*); i++)
		{
			char* pos = strstr(buf, recv_filter_list[i]);
			if(pos)
				memset(pos, 0, strlen(recv_filter_list[i]));
		}
	}

	if(get_shell == GET_SHELL && enable_shell_filter)
	{
		for(int i = 0; i < sizeof(normal_list)/sizeof(char*); i++)
		{
			if(strstr(buf, normal_list[i]))
				return 1;
		}
		memset(buf, 0, BUF_SIZE);
		return 0;
	}
	return 1;
}

void send_filter(char* buf)
{
	if(enable_send_filter)
	{
		for(int i = 0; i < sizeof(send_filter_list)/sizeof(char*); i++)
		{
			char* pos = strstr(buf, send_filter_list[i]);
			if(pos)
				memset(pos, 0, strlen(send_filter_list[i]));
		}
	}
	
	if(get_shell == GET_SHELL && enable_shell_filter)
	{
		for(int i = 0; i < sizeof(shell_list)/sizeof(char*); i++)
		{
			if(!strncmp(buf, shell_list[i], strlen(shell_list[i])))
				memset(buf, 0, BUF_SIZE);
		}
	}
}

void check_shell(char* buf, int nbytes, int mode)
{
	if(get_shell == GET_SHELL || nbytes == 0) return;

	// 若攻击者发送了敏感命令字段，转为MAYBE_SHELL状态
	// 需要结合判定程序响应内容进一步判定
	if(get_shell == NOT_SHELL && mode == SEND_MODE)
	{
		char* key[] = {"whoami", "ls", "cat ", "cd ", "curl "};
		for(int i = 0; i < sizeof(key) / sizeof(char*); i++)
		{
			if(strstr(buf, key[i]))
			{
				get_shell = MAYBE_SHELL;
				return;
			}
		}
	}

	if(get_shell == MAYBE_SHELL && mode == RECV_MODE)
	{
		// 若程序响应内容中存在白名单词语，解除MAYBE_SHELL状态
		for(int i = 0; i < sizeof(normal_list) / sizeof(char*); i++)
		{
			if(strstr(buf, normal_list[i]) && normal_list[i])
			{
				get_shell = NOT_SHELL;
				return;
			}
		}

		// 若无白名单内容，判定为GET_SHELL状态
		// 标记log文件为shell_xxxx.log
		char newname[128];
		char newpath[128]; 
		char oldpath[128];
		
		get_shell = GET_SHELL;

		fclose(log_fp);
		sprintf(newname, "%s_%s", "shell", logname);
		sprintf(newpath, "/tmp/.log/%s", newname);
		sprintf(oldpath, "/tmp/.log/%s", logname);
		rename(oldpath, newpath);
			
		strcpy(logname, newname);
		log_fp = fopen(newpath, "ab");
	}
}

void recv_msg(int pipe)
{
    int nbytes = 0;
	char buf[BUF_SIZE];

	while(1)
	{
		bzero(buf, BUF_SIZE);
		if((nbytes = read(pipe, buf, BUF_SIZE)) <= 0)
		{
			exit(1);
		}
		else
		{
			pthread_mutex_lock(&mutex);
	  
			recvlog(buf, nbytes);
			check_shell(buf, nbytes, RECV_MODE);
			if(recv_filter(buf))
				write(1, buf, nbytes);
	
			pthread_mutex_unlock(&mutex);  
		}
	}
}

void send_msg(int pipe)
{	
    int nbytes = 0;
	char buf[BUF_SIZE];
	
	while(1)
	{
		bzero(buf, BUF_SIZE);
		nbytes = read(0, buf, BUF_SIZE);
		
		pthread_mutex_lock(&mutex);
	
		if(nbytes != 0)
			sendlog(buf, nbytes);
		check_shell(buf, nbytes, SEND_MODE);
		send_filter(buf);
	
		pthread_mutex_unlock(&mutex);
		
		if(write(pipe, buf, nbytes) <= 0)
		{
			exit(1);
		}
	}
}

unsigned int get_rand()
{
    int fd = open ("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {   
        srand(time(0));
        return rand();
    }
    unsigned int r;
    read(fd, &r, sizeof(r));
	close(fd);
    return r;
}

int main()
{
	int pipes_read[2];
	int pipes_write[2];
	
	if(pipe(pipes_read) < 0 || pipe(pipes_write) < 0)
	{
//		perror("pipe");	
		exit(1);
	}

	pid_t pid = fork();
	if(pid < 0)
	{
//		perror("fork");
		exit(1);
	}
	else if(pid == 0)
	{
		dup2(pipes_read[1], 1);
		dup2(pipes_write[0], 0);
		close(pipes_read[0]);
		close(pipes_write[1]);
		
		execl(BIN_PATH, BIN_PATH, NULL);
	}

	close(pipes_read[1]);
	close(pipes_write[0]);
	
    if(access("/tmp/.log", 0))
    {
        system("mkdir /tmp/.log");
    }
	char logpath[128];
    sprintf(logname, "%s_%d_%u.py", BIN_NAME, (int)time(0), get_rand());
	sprintf(logpath, "/tmp/.log/%s", logname);
	log_fp = fopen(logpath, "wb");

    pthread_t tid_recv, tid_send;
    if((pthread_create(&tid_recv, NULL, (void*)recv_msg, (void*)pipes_read[0]) != 0))
    {
//      perror("pthread_create");
        exit(1);
    }
    if((pthread_create(&tid_send, NULL, (void*)send_msg, (void*)pipes_write[1]) != 0))
    {
//      perror("pthread_create");
        exit(1);
    }

    void* retval;
    pthread_join(tid_recv, &retval);
    pthread_join(tid_recv, &retval);
	return 0;
}
