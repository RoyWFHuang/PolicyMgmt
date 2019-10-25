#include <string.h>
#include "macro.h"
#include "policy_mgmt.h"


int main()
{
    autofree_tPolicyGrp tPolicyGrp wgrp;
    autofree_tPolicyGrp tPolicyGrp rgrp;
    memset(&wgrp, 0, sizeof(wgrp));
    memset(&wgrp, 0, sizeof(rgrp));
    int i =0;
    wgrp.num_policy = 2;
    wgrp.policy_data = calloc(wgrp.num_policy, sizeof(tPolicyStruct));

    wgrp.policy_data[i].policy_mask = __POILCY_READ;
    wgrp.policy_data[i].num_user_list = 1;
    wgrp.policy_data[i].user_list =
        calloc(wgrp.policy_data[i].num_user_list, sizeof(char *));
    strcpyALL(wgrp.policy_data[i].user_list[0], "roy");
    //strcpyALL(wgrp.policy_data[i].user_list[1], "roy_test1");
    //strcpyALL(wgrp.policy_data[i].user_list[2], "roy_test2");
    i++;
    wgrp.policy_data[i].policy_mask = __POILCY_WRITE;
    wgrp.policy_data[i].num_user_list = 3;
    wgrp.policy_data[i].user_list =
        calloc(wgrp.policy_data[i].num_user_list, sizeof(char *));
    strcpyALL(wgrp.policy_data[i].user_list[0], "roy");
    strcpyALL(wgrp.policy_data[i].user_list[1], "roy_test1");
    strcpyALL(wgrp.policy_data[i].user_list[2], "roy_test2");

    write_policy("test_policy_file", &wgrp);

    read_policy("test_policy_file", &rgrp);

    PLM_DEBUG_PRINT("start read data[%d]\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT("mask = %x\n", rgrp.policy_data[i].policy_mask);
        PLM_DEBUG_PRINT("num_user_list = %d\n", rgrp.policy_data[i].num_user_list);
        int cnt = rgrp.policy_data[i].num_user_list;
        //if(rgrp.policy_data[i].num_user_list > 3)
        //    cnt = 3;
        //else cnt =rgrp.policy_data[i].num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT("user = %s\n", rgrp.policy_data[i].user_list[j]);
        }

    }


    return 0;
}