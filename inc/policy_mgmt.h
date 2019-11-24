#ifndef __policy_mgmt_H__
#define __policy_mgmt_H__

/**
 * format : | 8    | 4*8   | n*8       |
 *          | mask | #user | user list |
 * mask: see in policy_table.h
 * #user: number of user in flowing
 * user list: list all user, format is: /user1/user2/.....
 **/

#include <stdint.h>
#include <stdio.h>
#ifndef POLICY_PREFIX
#   define POLICY_PREFIX "._md_FILE_POLICY_"
#endif /* not POLICY_PREFIX */

#ifndef MD_DIR_PATH
#   define MD_DIR_PATH "/opt/csgfs/metadata/normal/"
#endif /* not MD_DIR_PATH */

#ifndef MD_RCM_DIR_PATH
#   define MD_RCM_DIR_PATH "/opt/csgfs/metadata/rcm/"
#endif /* not MD_RCM_DIR_PATH */

#include "policy_table.h"

typedef struct _tPolicyStruct
{
    uint8_t mask;
    int num_user_list;
    char **user_list;
}tPolicyStruct;

typedef struct _tPolicyGrp
{
    int num_policy;
    tPolicyStruct **policy_data;
}tPolicyGrp;

/**
  * Hint :  Input data  is no be free in this func
  *
  * read the policy file into the policy group
  *
  * @param path type : const char *
  *     policy file path which want to read
  * @param policy_grp type : const tPolicyGrp *
  *     return policy rule in this group, flowing is sub data
  * * * @param policy_data type : int
  *         number of policy rule
  * * * @param policy_data type : tPolicyStruct
  *         policy rule setting
  * * * * * @param mask type : uint8_t
  *             policy mask see in policy_table.h define
  * * * * * @param num_user_list type : int
  *             number of uses in list
  * * * * * @param user_list type : char **
  *             user listing under the rule
  *
  * @return int
  *     ERROR_CODE_SUCCESS
  *     ERROR_CODE_PATH_ERROR
  *     ERROR_CODE_NULL_POINT_EXCEPTION
  */
int read_policy(const char *path, tPolicyGrp *policy_grp);

/**
  * Hint :  Input data  is no be free in this func
  *
  * Write the policy group into policy file
  *
  * @param path type : const char *
  *     policy file path
  * @param policy_grp type : const tPolicyGrp *
  *     input policy rule in this group, flowing is sub data
  * * * @param policy_data type : int
  *         number of policy rule
  * * * @param policy_data type : tPolicyStruct
  *         policy rule setting
  * * * * * @param mask type : uint8_t
  *             policy mask see in policy_table.h define
  * * * * * @param num_user_list type : int
  *             number of uses in list
  * * * * * @param user_list type : char **
  *             user listing under the rule
  *
  * @return int
  *     ERROR_CODE_SUCCESS
  *     ERROR_CODE_PATH_ERROR
  *     ERROR_CODE_NULL_POINT_EXCEPTION
  */
int write_policy(const char *path, const tPolicyGrp *policy_grp);

/**
  * Hint :  Input data  is no be free in this func
  *
  * Remove the policy file
  *
  * @param path type : const char *
  *     policy file path
  *
  * @return int
  *     ERROR_CODE_SUCCESS
  *     ERROR_CODE_NULL_POINT_EXCEPTION
  */
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

typedef enum _eModifyRule{
    eMODIFYRULE_ADD,
    eMODIFYRULE_DEL,
}eModifyRule;

/**
  * Hint :  Input data  is no be free in this func
  *
  * Change the policy rule
  *
  * @param path type : const char *
  *     policy file path
  *
  * @param rule type : const eModifyRule
  *     modify rule see in eModifyRule
  *
  * @param policy_grp type : const tPolicyGrp *
  *     modify content
  *
  * @return int
  *     ERROR_CODE_SUCCESS
  *     ERROR_CODE_NULL_POINT_EXCEPTION
  */
int modify_policy(const char *path, const eModifyRule rule,
    const tPolicyGrp *policy_grp);

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
