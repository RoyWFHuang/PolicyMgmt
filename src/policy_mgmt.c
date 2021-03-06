#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include "errorno.h"
#include "policy_mgmt.h"
#include "lib_method.h"
#include "macro.h"
#include "define.h"

#ifdef XXXX_PLATFORM
#include "XXXX_define.h"
#else
#   ifndef MD_DIR_PATH
#   define MD_DIR_PATH ""
#   endif
#endif



 /**
  * Hint : input data  is no be free in this func
  *
  * get file real path in md
  *
  * @param path type : const char *
  *             input path, e.g: /user/MySyncfolder/path_to/,
  *                              /user/Collaboration/path_to/
  * @return char*
  *     return the real path in md, if return NULL, the real path not exist
  */
static char *get_policy_file_real_path(const char *path)
{
    char *ptr = NULL;
    char *real_path = NULL;
    char resolved_path[1024];
    autofree_type_ptr char* tmp_path = NULL;
    strcpyALL(tmp_path, MD_DIR_PATH, (char *)path);
    ptr = realpath(tmp_path, resolved_path);
    if(NULL != ptr)
    {
        strcpyALL(real_path, (ptr+strlen(MD_DIR_PATH)));
    }
    return real_path;
}

static int __parserUserList(const char *user_list,
    tPolicyStruct *policy_data)
{
    RAII_VARIABLE(char *, tmp_list, NULL, free);

    check_null_input(user_list);
    check_null_input(policy_data);

    policy_data->user_list =
        calloc(policy_data->num_user_list, sizeof(char *));

    tLastNameData lnd;
    memset(&lnd, 0,sizeof(tLastNameData) );
    strcpyALL(lnd.input_path_pchar, (char *)user_list);
    for(int i = policy_data->num_user_list-1; i >= 0; i--)
    {
        get_last_folder_name(&lnd);
        strcpyALL(policy_data->user_list[i], lnd.last_name_pchar);
        RAII_VARIABLE(char *, tmp_path, NULL, free);
        strcpyALL(tmp_path, lnd.prefix_path_pchar);
        free_tLastNameData(lnd);
        strcpyALL(lnd.input_path_pchar, tmp_path);
    }
    free_tLastNameData(lnd);
    return ERROR_CODE_SUCCESS;
}

static char *__conver_to_policy_file_path(const char *path){

    char *policy_path = NULL;
    if(NULL == path) return NULL;

    tLastNameData lnd;
    memset(&lnd, 0,sizeof(tLastNameData) );
    strcpyALL(lnd.input_path_pchar, (char *)path);
    get_last_folder_name(&lnd);
    strcpyALL(policy_path, MD_DIR_PATH, lnd.prefix_path_pchar,
        POLICY_PREFIX, lnd.last_name_pchar);
    free_tLastNameData(lnd);
    return policy_path;

}

static int __check_user_exists(const char* user, const char** user_list,
    int num_user)
{
    check_null_input(user);
    check_null_input(user_list);

    for(int user_index = 0; user_index < num_user; user_index++)
    {
        if(NULL != user_list[user_index])
        {
            if(!strcmp(user_list[user_index], user))
            {
                return ERROR_CODE_SUCCESS;
            }
        }
    }
    return ERROR_CODE_NOT_EXIST;
}

static int __check_policy(const char* user,
    tPolicyGrp *polcy_grp, const uint8_t mask)
{
    check_null_input(polcy_grp);
    check_null_input(polcy_grp->policy_data);
    int ret_int = ERROR_CODE_NOT_EXIST;
    for(int policy_index = 0;
        policy_index < polcy_grp->num_policy;
        policy_index++)
    {
        tPolicyStruct *tmp_policy =
            polcy_grp->policy_data[policy_index];
        if(tmp_policy->mask & mask)
        {
            if(ERROR_CODE_SUCCESS != __check_user_exists(user,
                (const char**)tmp_policy->user_list,
                tmp_policy->num_user_list) )
            {
                return ERROR_CODE_NOT_EXIST;
            }
            ret_int = ERROR_CODE_SUCCESS;
        }
    }
    return ret_int;
}

static void __dup_policy_rule(
    tPolicyStruct *dst, tPolicyStruct *src)
{
    if(NULL == dst || NULL == src) return;
    memcpy(dst, src, sizeof(tPolicyStruct));
    dst->user_list = calloc(src->num_user_list, sizeof(char*));
    for(int i=0; i<src->num_user_list; i++)
    {
        strcpyALL(dst->user_list[i], src->user_list[i]);
    }
}

static tPolicyStruct *__merge_policy_rule(int8_t mask,
    const tPolicyGrp *dest_grp, const tPolicyGrp *src_grp)
{
    tPolicyStruct *dst = NULL, *src = NULL;
    tPolicyStruct *ret_policy = NULL;
    for(int num_pol=0; num_pol < dest_grp->num_policy; num_pol++)
    {
        if(mask & dest_grp->policy_data[num_pol]->mask)
        {
            dst = dest_grp->policy_data[num_pol];
            break;
        }
    }

    for(int num_pol=0; num_pol < src_grp->num_policy; num_pol++)
    {
        if(mask & src_grp->policy_data[num_pol]->mask)
        {
            src = src_grp->policy_data[num_pol];
            break;
        }
    }

    if(NULL != dst && NULL != src)
    {
        ret_policy = calloc(1, sizeof(tPolicyStruct));
        ret_policy->mask = mask;
        ret_policy->num_user_list = dst->num_user_list;

        for(int src_index=0; src_index<src->num_user_list; src_index++)
        {
            int8_t get_flag = 0;
            for(int dst_index=0; dst_index<dst->num_user_list; dst_index++)
            {
                if(!strcmp(src->user_list[src_index],
                    dst->user_list[dst_index]) )
                {
                    get_flag = 1;
                    break;
                }
            }
            if(!get_flag) ret_policy->num_user_list++;
        }

        ret_policy->user_list = calloc(ret_policy->num_user_list,
            sizeof(char*));

        for(int dst_index=0; dst_index<dst->num_user_list; dst_index++)
        {
            strcpyALL(ret_policy->user_list[dst_index],
                dst->user_list[dst_index]);
        }

        int cnt = dst->num_user_list;
        for(int src_index=0; src_index<src->num_user_list; src_index++)
        {
            int8_t get_flag = 0;
            for(int dst_index=0; dst_index<dst->num_user_list; dst_index++)
            {
                if(!strcmp(src->user_list[src_index],
                    dst->user_list[dst_index]) )
                {
                    get_flag = 1;
                    break;
                }
            }
            if(!get_flag)
            {
                strcpyALL(ret_policy->user_list[cnt],
                    src->user_list[src_index]);
                cnt++;
            }
        }
    }
    else if(NULL == dst && NULL != src)
    {
        ret_policy = calloc(1, sizeof(tPolicyStruct));
        __dup_policy_rule(ret_policy, src);
    }
    else if(NULL == src && NULL != dst)
    {
        ret_policy = calloc(1, sizeof(tPolicyStruct));
        __dup_policy_rule(ret_policy, dst);
    }

    return ret_policy;
}

static tPolicyGrp *__merge_policy(
    const tPolicyGrp *dest_grp, const tPolicyGrp *src_grp)
{
    tPolicyGrp *ret_data = NULL;


    if(!(dest_grp->num_policy | src_grp->num_policy))
    {
        goto __merge_policy_exit_lab_1;
    }
    int8_t mask = 0;
    for(int i=0;i<dest_grp->num_policy;i++)
    {
        mask |= dest_grp->policy_data[i]->mask;
    }

    for(int i=0;i<src_grp->num_policy;i++)
    {
        mask |= src_grp->policy_data[i]->mask;
    }

    int num;
    COUNT_1_BIT_NMBER(mask, num);
    if(num > 0)
    {
        int grp_index = 0;
        CREATE_PGRP(ret_data, num);
        if(mask & __POILCY_READ)
        {
            WRITE_PGRP(ret_data, grp_index, __POILCY_READ, dest_grp, src_grp);
            grp_index++;
        }
        if(mask & __POILCY_WRITE)
        {
            WRITE_PGRP(ret_data, grp_index, __POILCY_WRITE, dest_grp, src_grp);
            grp_index++;
        }
        if(mask & __POILCY_CREAT)
        {
            WRITE_PGRP(ret_data, grp_index, __POILCY_CREAT, dest_grp, src_grp);
            grp_index++;
        }
        if(mask & __POILCY_DEL)
        {
            WRITE_PGRP(ret_data, grp_index, __POILCY_DEL, dest_grp, src_grp);
            grp_index++;
        }
    }
/*
    switch(mask)
    {
        case __POILCY_READ:
            CREATE_PGRP(ret_data, 1);
            WRITE_PGRP(ret_data, 0, __POILCY_READ, dest_grp, src_grp);
            break;
        case __POILCY_WRITE:
            CREATE_PGRP(ret_data, 1);
            WRITE_PGRP(ret_data, 0, __POILCY_WRITE, dest_grp, src_grp);
            break;
        case (__POILCY_READ| __POILCY_WRITE):
            CREATE_PGRP(ret_data, 2);
            WRITE_PGRP(ret_data, 0, __POILCY_READ, dest_grp, src_grp);
            WRITE_PGRP(ret_data, 1, __POILCY_WRITE, dest_grp, src_grp);
            break;
        case (__POILCY_READ| __POILCY_WRITE | __POILCY_DEL):
            CREATE_PGRP(ret_data, 3);
            WRITE_PGRP(ret_data, 0, __POILCY_READ, dest_grp, src_grp);
            WRITE_PGRP(ret_data, 1, __POILCY_WRITE, dest_grp, src_grp);
            WRITE_PGRP(ret_data, 2, __POILCY_DEL, dest_grp, src_grp);
        case (__POILCY_READ| __POILCY_WRITE | __POILCY_DEL | __POILCY_CREAT):
            CREATE_PGRP(ret_data, 3);
            WRITE_PGRP(ret_data, 0, __POILCY_READ, dest_grp, src_grp);
            WRITE_PGRP(ret_data, 1, __POILCY_WRITE, dest_grp, src_grp);
            WRITE_PGRP(ret_data, 2, __POILCY_DEL, dest_grp, src_grp);
            WRITE_PGRP(ret_data, 3, __POILCY_CREAT, dest_grp, src_grp);
        default:
            PLM_ERR_PRINT("Error mask\n");
            break;
    }
*/
__merge_policy_exit_lab_1 :
    return ret_data;
}


static tPolicyStruct *__remove_part_of_policy_rule(int8_t mask,
    const tPolicyGrp *dest_grp, const tPolicyGrp *src_grp)
{
    tPolicyStruct *dst = NULL, *src = NULL;
    tPolicyStruct *ret_policy = NULL;
    for(int num_pol=0; num_pol < dest_grp->num_policy; num_pol++)
    {
        if(mask & dest_grp->policy_data[num_pol]->mask)
        {
            dst = dest_grp->policy_data[num_pol];
            break;
        }
    }

    for(int num_pol=0; num_pol < src_grp->num_policy; num_pol++)
    {
        if(mask & src_grp->policy_data[num_pol]->mask)
        {
            src = src_grp->policy_data[num_pol];
            break;
        }
    }

    if(NULL != dst && NULL != src)
    {
        ret_policy = calloc(1, sizeof(tPolicyStruct));
        ret_policy->mask = mask;
        ret_policy->num_user_list = dst->num_user_list;

        for(int src_index=0; src_index<src->num_user_list; src_index++)
        {
            int8_t get_flag = 0;
            for(int dst_index=0; dst_index<dst->num_user_list; dst_index++)
            {
                if(!strcmp(src->user_list[src_index],
                    dst->user_list[dst_index]) )
                {
                    get_flag = 1;
                    break;
                }
            }
            if(get_flag) ret_policy->num_user_list--;
        }

        ret_policy->user_list =
            calloc(ret_policy->num_user_list, sizeof(char*));
        int cnt = 0;
        for(int dst_index=0; dst_index<dst->num_user_list; dst_index++)
        {
            int8_t get_flag = 0;
            for(int src_index=0; src_index<src->num_user_list; src_index++)
            {
                if(!strcmp(src->user_list[src_index],
                    dst->user_list[dst_index]) )
                {
                    get_flag = 1;
                    break;
                }
            }
            if(!get_flag)
            {
                strcpyALL(ret_policy->user_list[cnt],
                    dst->user_list[dst_index]);
                cnt++;
            }
        }
    }
    else if(NULL == dst && NULL != src)
    {
        ret_policy = calloc(1, sizeof(tPolicyStruct));
        __dup_policy_rule(ret_policy, src);
    }
    else if(NULL == src && NULL != dst)
    {
        ret_policy = calloc(1, sizeof(tPolicyStruct));
        __dup_policy_rule(ret_policy, dst);
    }

    return ret_policy;
}

static tPolicyGrp *__remove_part_of_policy(
    tPolicyGrp *dest_grp, const tPolicyGrp *src_grp)
{
    tPolicyGrp *ret_data = NULL;

    if(!(dest_grp->num_policy | src_grp->num_policy))
    {
        goto __remove_part_of_policy_exit_lab_1;
    }
    int8_t mask_dst = 0;
    int8_t mask_src = 0;
    int8_t mask = 0;
    for(int i=0;i<dest_grp->num_policy;i++)
    {
        mask_dst |= dest_grp->policy_data[i]->mask;
    }

    for(int i=0;i<src_grp->num_policy;i++)
    {
        mask_src |= src_grp->policy_data[i]->mask;
    }
    mask = mask_dst & mask_src;

    int num;
    COUNT_1_BIT_NMBER(mask, num);
    if(num > 0)
    {
        int grp_index = 0;
        CREATE_PGRP(ret_data, num);
        if(mask & __POILCY_READ)
        {
            ret_data->policy_data[grp_index] =
                __remove_part_of_policy_rule(__POILCY_READ, dest_grp, src_grp);
            grp_index++;
        }
        if(mask & __POILCY_WRITE)
        {
            ret_data->policy_data[grp_index] =
                __remove_part_of_policy_rule(__POILCY_WRITE, dest_grp, src_grp);
            grp_index++;
        }
        if(mask & __POILCY_CREAT)
        {
            ret_data->policy_data[grp_index] =
                __remove_part_of_policy_rule(__POILCY_CREAT, dest_grp, src_grp);
            grp_index++;
        }
        if(mask & __POILCY_DEL)
        {
            ret_data->policy_data[grp_index] =
                __remove_part_of_policy_rule(__POILCY_DEL, dest_grp, src_grp);
            grp_index++;
        }
    }
/*
    switch(mask)
    {
        case 0x00:
#ifdef PLM_DEBUG_MODE
            PLM_DEBUG_PRINT("do nothing.....\n");
#endif
            break;
        case __POILCY_READ:
            CREATE_PGRP(ret_data, 1);
            ret_data->policy_data[0] =
                __remove_part_of_policy_rule(__POILCY_READ, dest_grp, src_grp);
            break;
        case __POILCY_WRITE:
            CREATE_PGRP(ret_data, 1);
            ret_data->policy_data[0] =
                __remove_part_of_policy_rule(__POILCY_WRITE, dest_grp, src_grp);
            break;
        case (__POILCY_READ | __POILCY_WRITE):
            CREATE_PGRP(ret_data, 2);
            ret_data->policy_data[0] =
                __remove_part_of_policy_rule(__POILCY_READ, dest_grp, src_grp);
            ret_data->policy_data[1] =
                __remove_part_of_policy_rule(__POILCY_WRITE, dest_grp, src_grp);
            break;
        default:
            PLM_ERR_PRINT("Error mask\n");
            break;
    }
*/
__remove_part_of_policy_exit_lab_1 :
    return ret_data;

}

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
int read_policy(const char *path, tPolicyGrp *policy_grp)
{
    FILE *stream;
    char *indata_buf = NULL;
    size_t len = 0;
    ssize_t nread;

    RAII_VARIABLE(char *, policy_path, NULL, free);

    check_null_input(path);
    check_null_input(policy_grp);

    policy_path = __conver_to_policy_file_path(path);
#ifdef PLM_DEBUG_MODE
    PLM_DEBUG_PRINT("policy_path [%s]\n", policy_path);
#endif
    stream = fopen(policy_path, "r");
    if (NULL == stream) return ERROR_CODE_PATH_ERROR;

    int line_num_int = 0;
    while ((nread = getline(&indata_buf, &len, stream)) != -1)
    {
        line_num_int ++;
    }
#ifdef PLM_DEBUG_MODE
    PLM_DEBUG_PRINT("line_num_int [%d]\n", line_num_int);
#endif
    rewind(stream);
    policy_grp->num_policy = line_num_int;
    policy_grp->policy_data =
        calloc(line_num_int, sizeof(tPolicyStruct *));

    line_num_int = 0;
    while ((nread = getline(&indata_buf, &len, stream)) != -1)
    {
        RAII_VARIABLE(char *, user_list, NULL, free);
        char *tmp_ptr = indata_buf;

        if(1 == nread) break;
        indata_buf[nread-1] = '\x0';
        user_list = calloc(nread, sizeof(char));

        policy_grp->policy_data[line_num_int] =
            calloc(1, sizeof(tPolicyStruct));

        memcpy(&policy_grp->policy_data[line_num_int]->mask, tmp_ptr,
            sizeof(uint8_t));
        tmp_ptr +=1;
        memcpy(&policy_grp->policy_data[line_num_int]->num_user_list, tmp_ptr,
            sizeof(int32_t));
        tmp_ptr +=4;
#ifdef PLM_DEBUG_MODE
        PLM_DEBUG_PRINT("[%2x][%4d][%s]\n",
            policy_grp->policy_data[line_num_int]->mask,
            policy_grp->policy_data[line_num_int]->num_user_list,
            tmp_ptr);
#endif
        strcpy(user_list, tmp_ptr);

        __parserUserList(
            user_list,
            policy_grp->policy_data[line_num_int]);

        line_num_int ++;
        free_to_NULL(indata_buf);
    }
    free_to_NULL(indata_buf);
    fclose(stream);
    return ERROR_CODE_SUCCESS;
}

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
int write_policy(const char *path, const tPolicyGrp *policy_grp)
{
    FILE *stream;
    //char *line = NULL;
    //size_t len = 0;
    //ssize_t nread;

    RAII_VARIABLE(char *, policy_path, NULL, free);
    RAII_VARIABLE(char *, user_list, NULL, free);

    check_null_input(path);
    check_null_input(policy_grp);

    policy_path = __conver_to_policy_file_path(path);
#ifdef PLM_DEBUG_MODE
    PLM_DEBUG_PRINT("policy_path [%s]\n", policy_path);
#endif
    stream = fopen(policy_path, "w+");
    if (stream == NULL) return ERROR_CODE_PATH_ERROR;

    for(int i=0; i<policy_grp->num_policy; i++)
    {
        int total_len = 0;
        char tmp_buf[1024*8];
        memset(tmp_buf, 0, sizeof(tmp_buf));
        char *ptr = tmp_buf;
        uint8_t policy_rule;

        for(int num_policy_rule = 0;
            num_policy_rule < __MAX_POLICY_RULES;
            num_policy_rule++)
        {
            policy_rule = __POILCY_BASE<<num_policy_rule;
            if(policy_grp->policy_data[i]->mask & policy_rule)
            {
                *ptr = policy_rule;
                ptr +=1;

                memcpy(ptr, &policy_grp->policy_data[i]->num_user_list,
                    sizeof(int32_t));
                ptr +=4;
                for(int num_user=0;
                    num_user < policy_grp->policy_data[i]->num_user_list;
                    num_user++)
                {
                    strcat(ptr, "/");
                    strcat(ptr,
                        policy_grp->policy_data[i]->user_list[num_user]);
                }
                strcat(ptr, "\n");
                total_len += (strlen(ptr) + 1 + 4);
                ptr+=strlen(ptr);
            }

        }

        fwrite(tmp_buf, sizeof(char), total_len, stream);
    }
    fclose(stream);
    return ERROR_CODE_SUCCESS;
}

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
int del_policy(const char *path)
{
    RAII_VARIABLE(char *, policy_path, NULL, free);

    check_null_input(path);

    policy_path = __conver_to_policy_file_path(path);
#ifdef PLM_DEBUG_MODE
    PLM_DEBUG_PRINT("policy_path [%s]\n", policy_path);
    int ret =
#endif
    remove(policy_path);
#ifdef PLM_DEBUG_MODE
    if(0 != ret)
    {
        PLM_DEBUG_PRINT("policy_path [%s] not exist\n", policy_path);
    }
#endif
    return ERROR_CODE_SUCCESS;
}

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
    const tPolicyGrp *policy_grp)
{
    RAII_VARIABLE(char *, policy_path, NULL, free);
    autofree_tPolicyGrp tPolicyGrp read_grp;
    tPolicyGrp *write_bk_grp = NULL;
    memset(&read_grp, 0, sizeof(tPolicyGrp));
    int ret = ERROR_CODE_SUCCESS;

    check_null_input(path);
    check_null_input(policy_grp);

    ret = read_policy(path, &read_grp);
    if(ERROR_CODE_SUCCESS == ret)
    {
        switch(rule)
        {
            case eMODIFYRULE_ADD:
                write_bk_grp = __merge_policy(&read_grp, policy_grp);
                break;
            case eMODIFYRULE_DEL:
                write_bk_grp = __remove_part_of_policy(&read_grp, policy_grp);
                break;
            default:
                PLM_ERR_PRINT("Error input modify type[%02x]", rule);
                ret = ERROR_CODE_NOT_EXIST;
                goto modify_policy_exit_lab_1;
                break;
        }
        ret = write_policy(path, write_bk_grp);
        free_tPolicyGrp(write_bk_grp);
        free_to_NULL(write_bk_grp);
    }
    else if(ERROR_CODE_PATH_ERROR == ret)
    {
        ret = write_policy(path, policy_grp);
    }
modify_policy_exit_lab_1:
    return ret;
}

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
int check_policy(const char *path, const uint8_t mask)
{
    int ret = ERROR_CODE_SUCCESS;
    autofree_tPolicyGrp tPolicyGrp read_policy_grp_data;
    memset(&read_policy_grp_data, 0, sizeof(tPolicyGrp));

    RAII_VARIABLE(char *, policy_path, NULL, free);
    RAII_VARIABLE(char *, policy_real_path, NULL, free);
    RAII_VARIABLE(char *, path_to, NULL, free);
    RAII_VARIABLE(char *, uname, NULL, free);

    check_null_input(path);
#ifdef XXXX_PLATFORM
    get_uname_and_path(path, uname, path_to);
    if(!strncmp(path_to, COLLABORATION_PATH_STR,
        strlen(COLLABORATION_PATH_STR)))
    {
    policy_real_path = get_policy_file_real_path(path);
    if(NULL == policy_real_path)
    {
#  ifdef PLM_DEBUG_MODE
        PLM_DEBUG_PRINT("[%s] is not a link" ,path);
#  endif
        return ERROR_CODE_NOT_EXIST;
    }
#else
    strcpyALL(policy_real_path, path);
#endif

    if(ERROR_CODE_PATH_ERROR ==
        read_policy(policy_real_path, &read_policy_grp_data))
    {
        tLastNameData lnd;
        memset(&lnd, 0,sizeof(tLastNameData) );
        strcpyALL(lnd.input_path_pchar, (char *)path);
        get_last_folder_name(&lnd);
        if(!strcmp("/", lnd.prefix_path_pchar))
        {
            free_tLastNameData(lnd);
            return ERROR_CODE_NOT_EXIST;
        }
        ret = check_policy(
            lnd.prefix_path_pchar, mask);
        free_tLastNameData(lnd);
    }
    else
    {
#ifdef PLM_DEBUG_MODE
        PLM_DEBUG_PRINT("get the policy file [%x][%s] ",
            mask, policy_real_path);
#endif
        ret = __check_policy(uname, &read_policy_grp_data, mask);
    }
#ifdef XXXX_PLATFORM
    }
#endif
    return ret;
}

/**
  * Hint :  Input data  is no be free in this func
  *
  * full copy tPolicyStruct
  *
  * @param dst type : tPolicyStruct *
  *     dest. data
  * @param src type : tPolicyStruct *
  *     source data
  *
  * @return int
  *     ERROR_CODE_SUCCESS
  *     ERROR_CODE_NULL_POINT_EXCEPTION
  */
int full_copy_tPolicyStruct(tPolicyStruct *restrict dst,
    tPolicyStruct *restrict src)
{
    check_null_input(dst);
    check_null_input(src);
    memcpy(dst, src, sizeof(tPolicyStruct));
    dst->user_list = calloc(src->num_user_list, sizeof(char *));
    for(int i = 0; i < src->num_user_list; i++)
    {
        strcpyALL(dst->user_list[i], src->user_list[i]);
    }
    return ERROR_CODE_SUCCESS;
}

void free_tPolicyGrp(tPolicyGrp *policy_grp)
{
    if(NULL == policy_grp) return;
    if(NULL == policy_grp->policy_data) return;
    for(int i = 0; i<policy_grp->num_policy; i++)
    {
        free_tPolicyStruct(policy_grp->policy_data[i]);
        free_to_NULL(policy_grp->policy_data[i]);
    }
    free_to_NULL(policy_grp->policy_data);
}

void free_tPolicyStruct(tPolicyStruct *policy)
{
    if(NULL == policy) return;
    if(NULL == policy->user_list) return;
    for(int i = 0; i<policy->num_user_list; i++)
    {
        free_to_NULL(policy->user_list[i]);
    }
    free_to_NULL(policy->user_list);
}


