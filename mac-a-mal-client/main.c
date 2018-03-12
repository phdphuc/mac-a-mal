//
//  main.c
//  mac_a_mal
//
//  Created by phdphuc on 5/30/17.
//  Copyright © 2017 admin. All rights reserved.
//


#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#include <sys/sys_domain.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/time.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/i386/thread_status.h>
#include <mach/mach_vm.h>

#include "data.h"
#include "event2/event.h"
#include "event2/bufferevent.h"

static int g_socket[MAX_SOCKET] = {[0 ... MAX_SOCKET-1]=-1};
FILE *outfile;

void bye(){
    int i=0;
    for (i=1;i<MAX_SOCKET;i++)
        if (g_socket[i] > 0) {
            printf("closing socket %d\n", g_socket[i]);
            close (g_socket[i]);
        }
}

static void SignalHandler(int sigraised) {
    switch (sigraised) {
        case SIGINT:
            printf("\nInterrupted - %d\n", sigraised); // note - printf is unsupported function call from a signal handler
                     break;
        case SIGALRM:
            printf ("Timed out!\n");
            flockfile(outfile);
            fwrite("STOP!", sizeof("STOP!"), strlen("STOP!"), outfile);
            funlockfile(outfile);
            break;
        default:
            break;
    }
    fclose(outfile);
    bye();
    // exit(0) should not be called from a signal handler.  Use _exit(0) instead
    _exit(0);
}


void read_cb(struct bufferevent *bev, void *arg)
{

    char line[MAX_SOCKET_LEN+1];
    int n;    
    while (n = bufferevent_read(bev, line, MAX_SOCKET_LEN), n > 0) {
        if (strncmp(line, "STOP!", 5) != 0){
        flockfile(outfile);
        fwrite(line, sizeof(line[0]), strlen(line), outfile);
        funlockfile(outfile);
        }
        else {
            flockfile(outfile);
            fwrite(line, sizeof(line[0]), strlen(line), outfile);
            funlockfile(outfile);
            fclose(outfile);
            bye();
            _exit(0);
        }
    }
}

void error_cb(struct bufferevent *bev, short event, void *arg)
{
    evutil_socket_t fd = bufferevent_getfd(bev);
    printf("fd = %u, ", fd);
    if (event & BEV_EVENT_TIMEOUT) {
        printf("Timed out\n"); //if bufferevent_set_timeouts() called
    }
    else if (event & BEV_EVENT_EOF) {
        printf("connection closed\n");
    }
    else if (event & BEV_EVENT_ERROR) {
        printf("some other error\n");
    }
    bufferevent_free(bev);
}
void do_recv(int listener, short event, void *arg)
{
    struct event_base *base = (struct event_base *)arg;
    
    struct bufferevent *bev = bufferevent_socket_new(base, listener, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, read_cb, NULL, error_cb, arg);
    
    bufferevent_enable(bev, EV_READ|EV_PERSIST);
//
//
//    evutil_socket_t fd;
//    char p[256];
//    
//    fd = recv(listener, p, 256,0);
    
//    n = recv(g_socket, p, 256, 0);
//
//    if (recv(g_socket, &data, sizeof(struct userland_event), 0) != sizeof(struct userland_event)) {
//    if (recv(g_socket, p, 256, 0) != 256) {
//        printf("malformed recv packet, leaving!\n");
//        break;
//    }
//
//    printf("Binary %s with PID %d and UID %d. Parent %s with PID %d and UID %d.\n",
//           data.path, data.pid, data.uid, data.parent_name, data.ppid, data.puid);
//          printf("%s", p);
    
    

}



int
connect_to_kernel(char *procname)
{
    struct sockaddr_ctl sc[MAX_SOCKET];
    struct ctl_info ctl_info[MAX_SOCKET];
    int ret = 0;
    sig_t oldHandler;
    char BUNDLE[20];
    
//     set up a signal handler so we can clean up when we're interrupted from the command line
//     otherwise we stay in our run loop forever
//     Or we'd like to stay in loop forever?
    
    oldHandler = signal(SIGINT, SignalHandler);
    if (oldHandler == SIG_ERR)
        printf("Could not establish new signal handler");
    int i=0;
    /* Init */
    struct event_base *base ;
    struct event *listen_event[MAX_SOCKET];
    for (i=0; i<MAX_SOCKET; i++){
        g_socket[i] = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        
        if (g_socket[i] < 0)
        {
            printf("[ERROR] Failed to create socket!\n");
            exit(1);
        }
        // the control ID is dynamically generated so we must obtain sc_id using ioctl
        memset(&ctl_info[i], 0, sizeof(ctl_info[i]));
        sprintf(BUNDLE, "%s%d", BUNDLE_ID, i);
        strncpy(ctl_info[i].ctl_name, BUNDLE, MAX_KCTL_NAME);
        ctl_info[i].ctl_name[MAX_KCTL_NAME-1] = '\0';
        if (ioctl(g_socket[i], CTLIOCGINFO, &ctl_info[i]) == -1)
        {
            printf("[ERROR] ioctl CTLIOCGINFO failed!\n");
            exit(1);
        }

        printf("[DEBUG] ctl_id: 0x%x for ctl_name: %s\n", ctl_info[i].ctl_id, ctl_info[i].ctl_name);

        
        bzero(&sc[i], sizeof(struct sockaddr_ctl));
        sc[i].sc_len = sizeof(struct sockaddr_ctl);
        sc[i].sc_family = AF_SYSTEM;
        sc[i].ss_sysaddr = AF_SYS_CONTROL;
        sc[i].sc_id = ctl_info[i].ctl_id;
        sc[i].sc_unit = 0;
        
        ret = connect(g_socket[i], (struct sockaddr*)&sc[i], sizeof(sc[i]));
        if (ret)
        {
            printf("[ERROR] Connect failed!\n");
            exit(1);
        }
        evutil_make_socket_nonblocking(g_socket[i]);
        }
//    while(1){
//        char s[10];
//        printf( "Enter a value :");
//        scanf("%s", s);
//        setsockopt(g_socket[0], SYSPROTO_CONTROL, 2, (void*)s, (socklen_t)strlen(s)+1);
//    }
    ret = setsockopt(g_socket[0], SYSPROTO_CONTROL, 1, (void*)procname, (socklen_t)(strlen(procname)+1));
    if (ret)
    {
        printf("[ERROR] Send trace process name failed!\n");
    }
        base =  event_base_new();
        if(base != NULL){
            printf("Created base\n");
            for(i=0;i<MAX_SOCKET;i++){
                listen_event[i] = event_new(base, g_socket[i], EV_READ|EV_PERSIST, do_recv, (void*)base);
                event_add(listen_event[i], NULL);
                
        }
            event_base_dispatch(base);
    }
    
    
    return 0;
}

/* Install timer_handler as the signal handler for SIGVTALRM. */




int main(int argc, const char * argv[])
{
    char procname[256];
    char fpath[256];
    outfile=fopen(fpath, "wb");
    struct sigaction sa;
    struct itimerval timer;
    long int timeout_in_sec = 120;
    
    /* Default timeout: 2 minutes
     * Install timer_handler as the signal handler for SIGALRM (SIGVTALRM doesnt work). 
     */
    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = &SignalHandler;
    if (sigaction (SIGALRM, &sa, NULL) == -1) {
        printf("sigaction failed!\n");
    }


    
    if (argc < 2)
    {
        printf("Usage \n");
        exit(0);
    }
    else if (argc >=3)
    {
        /*Options*/
        timeout_in_sec = strtol(argv[2], (char**) NULL, 10);
        if (argc >3){
            strcpy(fpath, argv[3]);
        }
        else strcpy(fpath, "log.txt");
    }
    outfile=fopen(fpath, "wb");
    strcpy(procname, argv[1]);
    
    timer.it_value.tv_sec = timeout_in_sec;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = timeout_in_sec;
    timer.it_interval.tv_usec = 0;
    
    /* Start a virtual timer. It counts down whenever this process is
     executing. */
    setitimer (ITIMER_REAL, &timer, NULL);
    
    if (connect_to_kernel(procname))
    {
        printf("[ERROR] Can't connect to kernel control socket!\n");
        exit(1);
    }
    return 0;
}
