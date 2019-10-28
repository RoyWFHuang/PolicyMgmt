#ifndef __policy_mgmt_H__
#define __policy_mgmt_H__

#include <stdint.h>
#include <stdio.h>
#ifndef POLICY_PREFIX
#define POLICY_PREFIX "._md_FILE_POLICY_"
#endif /* not POLICY_PREFIX */

#ifndef MD_DIR_PATH
#   define MD_DIR_PATH "/opt/csgfs/metadata/normal/"
#endif /* not MD_DIR_PATH */

#ifndef MD_RCM_DIR_PATH
#   define MD_RCM_DIR_PATH "/opt/csgfs/metadata/rcm/"
#endif /* not MD_DIR_PATH */

#include "policy_table.h"

typedef struct _tPolicyStruct
{
    uint8_t policy_mask;
    int num_user_list;
    char **user_list;
}tPolicyStruct;

typedef struct _tPolicyGrp
{
    int num_policy;
    tPolicyStruct *policy_data;
}tPolicyGrp;

int read_policy(const char *path, tPolicyGrp *policy_grp);
int write_policy(const char *path, const tPolicyGrp *policy_grp);
int del_policy(const char *path);
/**
  * Hint :  Input data  is no be free in this func
  *
  * Check policy, user can access this path or not
  *
  * @param path type : const char *
  *     access path policy
  * @param uname type : const char *
  *     checking user name
  * @param mask type : const uint8_t
  *     checking policy, see in policy_table.h
  *
  * @return int
  *     ERROR_CODE_SUCCESS
  *     ERROR_CODE_NOT_EXIST
  *     ERROR_CODE_NULL_POINT_EXCEPTION
  *	    ERROR_CODE_NONEXPECT_ERROR
  */
int check_policy(
    const char *path, const char *uname, const uint8_t mask);

void free_tPolicyGrp(tPolicyGrp *policy_grp);
void free_tPolicyStruct(tPolicyStruct *policy);

#define autofree_tPolicyGrp \
    __attribute__((cleanup(free_tPolicyGrp)))

#define autofree_tPolicyStruct \
    __attribute__((cleanup(free_tPolicyStruct)))

#ifdef CONSOLE_DEBUG
#   define PLM_DEBUG_PRINT(fmt, str...) \
        printf(\
        "%16.16s(%4d) - %16.16s: " fmt, \
        __FILE__, __LINE__, __func__, ##str)
#   define PLM_ERR_PRINT(fmt, str...) \
        printf(\
        "%16.16s(%4d) - %16.16s: **** " fmt, \
        __FILE__, __LINE__, __func__, ##str)
#else
#   include "define.h"
#   define PLM_DEBUG_PRINT PRINT_DBG
#   define PLM_ERR_PRINT PRINT_ERR
#endif


#endif
