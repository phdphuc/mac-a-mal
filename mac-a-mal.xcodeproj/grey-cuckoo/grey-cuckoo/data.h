//
//  data.h
//  grey-cuckoo
//
//  Created by admin on 5/31/17.
//  Copyright © 2017 admin. All rights reserved.
//

#ifndef data_h
#define data_h

#define BUNDLE_ID   "vi.grey-cuckoo"
#define MAGIC       "MagicHook"
// the supported commands
#define PATCH_TASK_FOR_PID     0x0
#define UNPATCH_TASK_FOR_PID   0x1
#define ANTI_PTRACE_ON         0x2
#define ANTI_PTRACE_OFF        0x3
#define ANTI_SYSCTL_ON         0x4
#define ANTI_SYSCTL_OFF        0x5
#define ANTI_KAUTH_ON          0x6
#define ANTI_KAUTH_OFF         0x7
#define PATCH_RESUME_FLAG      0x8
#define UNPATCH_RESUME_FLAG    0x9
#define PATCH_SINGLESTEP       0xa
#define UNPATCH_SINGLESTEP     0xb

struct __attribute__ ((packed)) userland_event {
    uint32_t active;                    /* is userland connection established? */
    pid_t pid;                          /* target process PID */
    uid_t uid;                          /* target process UID */
    pid_t ppid;                         /* parent PID */
    uid_t puid;                         /* parent process UID */
    char path[MAXPATHLEN];              /* target binary path */
    char parent_name[MAXCOMLEN+1];      /* parent process name */
};

#endif /* data_h */


