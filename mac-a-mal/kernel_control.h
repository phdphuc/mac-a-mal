//
//  kernel_control.h
//  mac-a-mal
//
//  Created by admin on 5/30/17.
//  Copyright © 2017 phdphuc. All rights reserved.
//

#ifndef kernel_control_h
#define kernel_control_h

#include <mach/mach_types.h>
#include <sys/types.h>
#include <sys/param.h>
#include <stdbool.h>

kern_return_t install_kern_control(void);
kern_return_t remove_kern_control(void);


struct __attribute__ ((packed)) userland_event {
    uint32_t active;                    /* is userland connection established? */
    pid_t pid;                          /* target process PID */
    uid_t uid;                          /* target process UID */
    pid_t ppid;                         /* parent PID */
    uid_t puid;                         /* parent process UID */
    char path[MAXPATHLEN];              /* target binary path */
    char parent_name[MAXCOMLEN+1];      /* parent process name */
};


bool pid_run(int );

//kern_return_t send_message(struct userland_event *event);
kern_return_t send_message(char *p);
kern_return_t queue_inactive_userland_data(void);

/* the number of *nanosecs* to sleep between checking if userland sent response */
#define USERLAND_RESPONSE_PERIOD                        400000
/* the number of attempts before timeout waiting for userland  response */
/* total timeout = USERLAND_TIMEOUT_COUNT * USERLAND_RESPONSE_PERIOD */
#define USERLAND_TIMEOUT_COUNT                         12500

/* queues sizes */
#define TO_QUEUE_SIZE 100
#define FROM_QUEUE_SIZE 10
#endif /* kernel_control_h */
