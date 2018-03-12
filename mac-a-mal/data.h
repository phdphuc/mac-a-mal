//
//  data.h
//  mac-a-mal
//
//  Created by admin on 5/30/17.
//  Copyright © 2017 phdphuc. All rights reserved.
//

#ifndef data_h
#define data_h

#define BUNDLE_ID   "mac-a-mal"
#define MAX_SOCKET 200

// State
#define SLEEP       0x0
#define RUN         0x1
#define TRACE       0x2
#define STOPPING    0x3
#define STOPED    0x4

#define MAX_SOCKET_LEN    512

#define NO_TRACE_OPEN_SPAWN    0x00
#define TRACE_OPEN_SPAWN    0x01

extern int open_spawn;

extern int g_connection_to_userland;
extern char set_procname[256];
extern int state;
void SEND_INFO(pid_t, const char * format, ... );
extern bool trackpid[99999];
extern bool trackglobal;
#endif /* data_h */
