#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include "errorno.h"
#include "policy_mgmt.h"
#include "lib_method.h"
#include "macro.h"

static int parserUserList(const char *user_list_pchar,
    tPolicyStruct *policy_pstruct)
{

    //autofree_type_ptr char *list_pchar = NULL;
    RAII_VARIABLE(char *, list_pchar, NULL, free);

    check_null_input(user_list_pchar);
    check_null_input(policy_pstruct);

    policy_pstruct->user_list_ppchar =
        calloc(policy_pstruct->num_int, sizeof(char*));

    char *usr_pchar = NULL;
    strcpyALL(list_pchar, user_list_pchar);
    for(int i = policy_pstruct->num_int-1; i >= 0; i--)
    {
        usr_pchar = basename(list_pchar);
        strcpyALL(policy_pstruct->user_list_ppchar[i], usr_pchar);
    }
    return ERROR_CODE_SUCCESS;
}

static char *conver_to_policy_file_path(const char *path_pchar){
    char *policy_path = NULL;
    tLastNameData lnd_struct;
    memset(&lnd_struct, 0,sizeof(tLastNameData) );
    strcpyALL(lnd_struct.input_path_pchar, path_pchar);
    get_last_folder_name(&lnd_struct);
    strcpyALL(policy_path, MD_DIR_PATH, lnd_struct.prefix_path_pchar,
        POLICY_PREFIX, lnd_struct.last_name_pchar);
    free_tLastNameData(lnd_struct);
    return policy_path;
}

int read_policy(const char *path_pchar, tPolicyGrp *policy_grp_pstruct)
{
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    autofree_type_ptr char *policy_path = NULL;
    autofree_type_ptr char *user_list_pchar = NULL;
    //RAII_VARIABLE(char *, policy_path, NULL, free);
    //RAII_VARIABLE(char *, user_list_pchar, NULL, free);

    check_null_input(path_pchar);
    check_null_input(policy_grp_pstruct);

    policy_path = conver_to_policy_file_path(path_pchar);

    stream = fopen(policy_path, "r");
    if (NULL == stream) {
        return ERROR_CODE_METADATA_NOT_EXIST;
    }

    int line_num_int = 0;
    while ((nread = getline(&line, &len, stream)) != -1) {
        line_num_int ++;
    }

    rewind(stream);

    policy_grp_pstruct->num_int = line_num_int;
    policy_grp_pstruct->policy_data_pstruct =
        calloc(line_num_int, sizeof(tPolicyStruct));

    line_num_int = 0;
    while ((nread = getline(&line, &len, stream)) != -1) {
        printf("Retrieved line of length %zu:\n", nread);
        user_list_pchar = calloc(nread, sizeof(char));
        sscanf(line,"%u:%d:%s",
            &policy_grp_pstruct->policy_data_pstruct[line_num_int].\
                policy_mask_uint8,
            &policy_grp_pstruct->policy_data_pstruct[line_num_int].num_int,
            user_list_pchar);

        parserUserList(
            user_list_pchar,
            &policy_grp_pstruct->policy_data_pstruct[line_num_int]);

        line_num_int ++;
    }
    free(line);
    fclose(stream);
    return ERROR_CODE_SUCCESS;
}


int write_new_policy(
    const char *path_pchar,
    const tPolicyGrp *policy_grp_pstruct)
{
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    autofree_type_ptr char *policy_path = NULL;
    autofree_type_ptr char *user_list_pchar = NULL;
    //RAII_VARIABLE(char *, policy_path, NULL, free);
    //RAII_VARIABLE(char *, user_list_pchar, NULL, free);

    check_null_input(path_pchar);
    check_null_input(policy_grp_pstruct);

    policy_path = conver_to_policy_file_path(path_pchar);

    stream = fopen(policy_path, "w+");
    if (stream == NULL) {
        return ERROR_CODE_METADATA_NOT_EXIST;
    }
}


int check_policy(
    const char *path_pchar, const char *uname_pchar, const uint8_t mask_int)
{
    int ret_int = ERROR_CODE_SUCCESS;
    tPolicyGrp read_policy_struct;

    autofree_type_ptr char *policy_path = NULL;
    //RAII_VARIABLE(char *, policy_path, NULL, free);

    check_null_input(path_pchar);
    check_null_input(uname_pchar);


    memset(&read_policy_struct, 0, sizeof(tPolicyGrp));

    if(ERROR_CODE_METADATA_NOT_EXIST ==
        read_policy(path_pchar, &read_policy_struct)
    {
        tLastNameData lnd_struct;
        memset(&lnd_struct, 0,sizeof(tLastNameData) );
        strcpyALL(lnd_struct.input_path_pchar, path_pchar);
        get_last_folder_name(&lnd_struct);
        ret_int = check_policy(
            lnd_struct.prefix_path_pchar, uname_pchar, mask_int);
        free_tLastNameData(lnd_struct);
    }
    else
    {
        if(read_policy_struct.policy_data_pstruct[i].policy_mask_uint8 & mask_int)
        {
            if(!strcmp(
                read_policy_struct.policy_data_pstruct[i].user_list_ppchar[i],
                uname_pchar))
            {
                break;
            }
        }
    }





}