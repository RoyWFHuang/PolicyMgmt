#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include "errorno.h"
#include "policy_mgmt.h"
#include "lib_method.h"
#include "macro.h"
#include "define.h"
/**
 * policy:num_of_user:user_list
 **/
static int __parserUserList(const char *user_list,
    tPolicyStruct *policy_data)
{

    //autofree_type_ptr char *tmp_list = NULL;
    RAII_VARIABLE(char *, tmp_list, NULL, free);

    check_null_input(user_list);
    check_null_input(policy_data);

    policy_data->user_list =
        calloc(policy_data->num_user_list, sizeof(char*));

    char *usr_pchar = NULL;

    tLastNameData lnd;
    memset(&lnd, 0,sizeof(tLastNameData) );
    strcpyALL(lnd.input_path_pchar, user_list);
    for(int i = policy_data->num_user_list-1; i >= 0; i--)
    {
        get_last_folder_name(&lnd);
        strcpyALL(policy_data->user_list[i], lnd.last_name_pchar);
        char *tmp_path = NULL;
        strcpyALL(tmp_path, lnd.prefix_path_pchar);
        free_tLastNameData(lnd);
        strcpyALL(lnd.input_path_pchar, tmp_path);
    }
    return ERROR_CODE_SUCCESS;
}

static char *__conver_to_policy_file_path(const char *path){
    char *policy_path = NULL;
    tLastNameData lnd;
    memset(&lnd, 0,sizeof(tLastNameData) );
    strcpyALL(lnd.input_path_pchar, path);
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

    for(int policy_index = 0;
        policy_index < polcy_grp->num_policy;
        policy_index++)
    {
        tPolicyStruct *tmp_policy =
            &polcy_grp->policy_data[policy_index];
        if(tmp_policy->policy_mask & mask)
        {
            return __check_user_exists(user, (const char**)tmp_policy->user_list,
                tmp_policy->num_user_list);
        }
    }
    return ERROR_CODE_NOT_EXIST;
}


int read_policy(const char *path, tPolicyGrp *policy_grp)
{
    FILE *stream;
    char *indata_buf = NULL;
    size_t len = 0;
    ssize_t nread;

    //autofree_type_ptr char *policy_path = NULL;
    //autofree_type_ptr char *user_list = NULL;
    RAII_VARIABLE(char *, policy_path, NULL, free);

    check_null_input(path);
    check_null_input(policy_grp);

    policy_path = __conver_to_policy_file_path(path);
    stream = fopen(policy_path, "r");
    if (NULL == stream) {
        return ERROR_CODE_PATH_ERROR;
    }

    int line_num_int = 0;
    while ((nread = getline(&indata_buf, &len, stream)) != -1) {
        line_num_int ++;
    }
    PLM_DEBUG_PRINT("line_num_int = %d\n", line_num_int);
    rewind(stream);
    policy_grp->num_policy = line_num_int;
    policy_grp->policy_data =
        calloc(line_num_int, sizeof(tPolicyStruct));

    line_num_int = 0;
    while ((nread = getline(&indata_buf, &len, stream)) != -1) {
        //printf("Retrieved line of length %zu:\n", nread);/
        if(1 == nread) break;

        RAII_VARIABLE(char *, user_list, NULL, free);
        indata_buf[nread-1] = '\x0';
        user_list = calloc(nread, sizeof(char));
        char *tmp_ptr = indata_buf;
        memcpy(&policy_grp->policy_data[line_num_int].policy_mask, tmp_ptr,
            sizeof(uint8_t));
        tmp_ptr +=1;
        memcpy(&policy_grp->policy_data[line_num_int].num_user_list, tmp_ptr,
            sizeof(int32_t));
        tmp_ptr +=4;
        PLM_DEBUG_PRINT("tmp_ptr = %s\n", tmp_ptr);
        strcpy(user_list, tmp_ptr);

        __parserUserList(
            user_list,
            &policy_grp->policy_data[line_num_int]);

        line_num_int ++;
        free(indata_buf);
    }
    //free(indata_buf);
    fclose(stream);
    return ERROR_CODE_SUCCESS;
}


int write_policy(const char *path, const tPolicyGrp *policy_grp)
{
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    //autofree_type_ptr char *policy_path = NULL;
    //autofree_type_ptr char *user_list = NULL;
    RAII_VARIABLE(char *, policy_path, NULL, free);
    RAII_VARIABLE(char *, user_list, NULL, free);

    check_null_input(path);
    check_null_input(policy_grp);

    policy_path = __conver_to_policy_file_path(path);
    PLM_DEBUG_PRINT("policy_path = %s\n", policy_path);
    stream = fopen(policy_path, "w+");
    if (stream == NULL) {
        return ERROR_CODE_PATH_ERROR;
    }
    for(int i=0; i<policy_grp->num_policy; i++)
    {
        int total_len = 0;
        char tmp_buf[1024];
        memset(tmp_buf, 0, sizeof(tmp_buf));
        char *ptr = tmp_buf;
        memcpy(ptr, &policy_grp->policy_data[i].policy_mask, sizeof(uint8_t));
        ptr +=1;
        memcpy(ptr, &policy_grp->policy_data[i].num_user_list, sizeof(int32_t));
        ptr +=4;
        for(int num_user=0;
            num_user<policy_grp->policy_data[i].num_user_list; num_user++)
        {
            strcat(ptr, "/");
            strcat(ptr, policy_grp->policy_data[i].user_list[num_user]);
        }
        strcat(ptr, "\n");
        total_len = strlen(ptr) + 1 + 4;
        fwrite(tmp_buf, sizeof(char), total_len, stream);
    }
    fclose(stream);
    return ERROR_CODE_SUCCESS;
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
int check_policy(
    const char *path, const char *uname, const uint8_t mask)
{
    int ret = ERROR_CODE_SUCCESS;
    autofree_tPolicyGrp tPolicyGrp read_policy_grp_data;
    memset(&read_policy_grp_data, 0, sizeof(tPolicyGrp));

    //autofree_type_ptr char *policy_path = NULL;
    RAII_VARIABLE(char *, policy_path, NULL, free);

    check_null_input(path);
    check_null_input(uname);

    if(ERROR_CODE_PATH_ERROR ==
        read_policy(path, &read_policy_grp_data))
    {
        tLastNameData lnd;
        memset(&lnd, 0,sizeof(tLastNameData) );
        strcpyALL(lnd.input_path_pchar, path);
        get_last_folder_name(&lnd);
        if(!strcmp("/", lnd.prefix_path_pchar))
        {
            free_tLastNameData(lnd);
            return ERROR_CODE_NOT_EXIST;
        }
        ret = check_policy(
            lnd.prefix_path_pchar, uname, mask);
        free_tLastNameData(lnd);
    }
    else
    {
        ret = __check_policy(uname, &read_policy_grp_data, mask);
    }
    return ret;
}

void free_tPolicyGrp(tPolicyGrp *policy_grp)
{
    if(NULL == policy_grp) return;
    if(NULL == policy_grp->policy_data) return;
    for(int i = 0; i<policy_grp->num_policy; i++)
    {
        free_tPolicyStruct(&policy_grp->policy_data[i]);
    }
}

void free_tPolicyStruct(tPolicyStruct *policy)
{
    if(NULL == policy) return;
    if(NULL == policy->user_list) return;
    for(int i = 0; i<policy->num_user_list; i++)
    {
        free_to_NULL(policy->user_list[i]);
    }
}


