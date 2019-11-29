#ifndef __policy_table_H__
#define __policy_table_H__

#define __POILCY_BASE   ((uint8_t)(0x01))
#define __POILCY_DEL    (__POILCY_BASE)
#define __POILCY_WRITE  (__POILCY_BASE << 1)
#define __POILCY_READ   (__POILCY_BASE << 2)
#define __POILCY_CREAT  (__POILCY_BASE << 3)

#define __MAX_POLICY_RULES 4

#endif


