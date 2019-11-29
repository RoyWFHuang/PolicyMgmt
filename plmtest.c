#include <string.h>
#include "macro.h"
#include "policy_mgmt.h"

void full_case()
{
    int ret_int = 0;
    autofree_tPolicyGrp tPolicyGrp wgrp;
    autofree_tPolicyGrp tPolicyGrp rgrp;
    autofree_tPolicyGrp tPolicyGrp addgrp;

    memset(&wgrp, 0, sizeof(tPolicyGrp));
    memset(&rgrp, 0, sizeof(tPolicyGrp));
    memset(&addgrp, 0, sizeof(tPolicyGrp));


    int i =0;
    wgrp.num_policy = 2;
    wgrp.policy_data = calloc(wgrp.num_policy, sizeof(tPolicyStruct *));
    wgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    wgrp.policy_data[i]->mask = __POILCY_READ;
    wgrp.policy_data[i]->num_user_list = 1;
    wgrp.policy_data[i]->user_list =
        calloc(wgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(wgrp.policy_data[i]->user_list[0], "roy");
    //strcpyALL(wgrp.policy_data[i]->user_list[1], "roy_test1");
    //strcpyALL(wgrp.policy_data[i]->user_list[2], "roy_test2");
    i++;
    wgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    wgrp.policy_data[i]->mask = __POILCY_WRITE;
    wgrp.policy_data[i]->num_user_list = 3;
    wgrp.policy_data[i]->user_list =
        calloc(wgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(wgrp.policy_data[i]->user_list[0], "roy");
    strcpyALL(wgrp.policy_data[i]->user_list[1], "roy_test1");
    strcpyALL(wgrp.policy_data[i]->user_list[2], "roy_test2");

    write_policy("/test_policy_file", &wgrp);

    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * start read data[%d]\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        //if(rgrp.policy_data[i]->num_user_list > 3)
        //    cnt = 3;
        //else cnt =rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }


    addgrp.num_policy = 2;
    addgrp.policy_data = calloc(addgrp.num_policy, sizeof(tPolicyStruct *));
    i = 0;
    addgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    addgrp.policy_data[i]->mask = __POILCY_READ;
    addgrp.policy_data[i]->num_user_list = 1;
    addgrp.policy_data[i]->user_list =
        calloc(addgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(addgrp.policy_data[i]->user_list[0], "roy_add_read");

    i++;
    addgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    addgrp.policy_data[i]->mask = __POILCY_WRITE;
    addgrp.policy_data[i]->num_user_list = 2;
    addgrp.policy_data[i]->user_list =
        calloc(addgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(addgrp.policy_data[i]->user_list[0], "roy_add_write");
    strcpyALL(addgrp.policy_data[i]->user_list[1], "roy_add_write2");

    PLM_DEBUG_PRINT(" * start modify\n");
    modify_policy("/test_policy_file", eMODIFYRULE_ADD, &addgrp);

    free_tPolicyGrp(&rgrp);
    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * ------- after modify data[%d] --------\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }

    ret_int = check_policy("roy/md/test_policy_file", __POILCY_READ);
    PLM_DEBUG_PRINT(" * [%s][%2x][%d]\n",
        "roy/md/test_policy_file", __POILCY_READ, ret_int);

    ret_int = check_policy("roy/test_policy_file", __POILCY_READ);
    PLM_DEBUG_PRINT(" * [%s][%2x][%d]\n",
        "roy/test_policy_file", __POILCY_READ, ret_int);

    ret_int = check_policy("roy1/test_policy_file", __POILCY_READ);
    PLM_DEBUG_PRINT(" * [%s][%2x][%d]\n",
        "roy1/test_policy_file", __POILCY_READ, ret_int);

    ret_int = check_policy("roy1/test_policy_file", __POILCY_WRITE);
    PLM_DEBUG_PRINT(" * [%s][%2x][%d]\n",
        "roy1/test_policy_file", __POILCY_WRITE, ret_int);

    del_policy("/test_policy_file");
    del_policy("/md/test_policy_file");
}

void read_case()
{
    int ret_int = 0;
    autofree_tPolicyGrp tPolicyGrp wgrp;
    autofree_tPolicyGrp tPolicyGrp rgrp;
    autofree_tPolicyGrp tPolicyGrp addgrp;

    memset(&wgrp, 0, sizeof(tPolicyGrp));
    memset(&rgrp, 0, sizeof(tPolicyGrp));
    memset(&addgrp, 0, sizeof(tPolicyGrp));
    int i =0;
    wgrp.num_policy = 1;
    wgrp.policy_data = calloc(wgrp.num_policy, sizeof(tPolicyStruct *));

    wgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    wgrp.policy_data[i]->mask = __POILCY_READ;
    wgrp.policy_data[i]->num_user_list = 3;
    wgrp.policy_data[i]->user_list =
        calloc(wgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(wgrp.policy_data[i]->user_list[0], "roy");
    strcpyALL(wgrp.policy_data[i]->user_list[1], "roy_test1");
    strcpyALL(wgrp.policy_data[i]->user_list[2], "roy_test2");

    write_policy("/test_policy_file", &wgrp);

    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * start read data[%d]\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }


    addgrp.num_policy = 2;
    addgrp.policy_data = calloc(addgrp.num_policy, sizeof(tPolicyStruct ));
    i = 0;
    addgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    addgrp.policy_data[i]->mask = __POILCY_READ;
    addgrp.policy_data[i]->num_user_list = 1;
    addgrp.policy_data[i]->user_list =
        calloc(addgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(addgrp.policy_data[i]->user_list[0], "roy_add_read");

    i++;
    addgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    addgrp.policy_data[i]->mask = __POILCY_WRITE;
    addgrp.policy_data[i]->num_user_list = 2;
    addgrp.policy_data[i]->user_list =
        calloc(addgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(addgrp.policy_data[i]->user_list[0], "roy_add_write");
    strcpyALL(addgrp.policy_data[i]->user_list[1], "roy_add_write2");

    PLM_DEBUG_PRINT(" * --------- start modify -------- \n");
    modify_policy("/test_policy_file", eMODIFYRULE_ADD, &addgrp);

    free_tPolicyGrp(&rgrp);
    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * ------- after modify data[%d] --------\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }

    del_policy("/test_policy_file");
    del_policy("/md/test_policy_file");

}

void write_case()
{
    int ret_int = 0;
    autofree_tPolicyGrp tPolicyGrp wgrp;
    autofree_tPolicyGrp tPolicyGrp rgrp;
    autofree_tPolicyGrp tPolicyGrp addgrp;

    memset(&wgrp, 0, sizeof(tPolicyGrp));
    memset(&rgrp, 0, sizeof(tPolicyGrp));
    memset(&addgrp, 0, sizeof(tPolicyGrp));
    int i =0;
    wgrp.num_policy = 1;
    wgrp.policy_data = calloc(wgrp.num_policy, sizeof(tPolicyStruct ));

    wgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    wgrp.policy_data[i]->mask = __POILCY_WRITE;
    wgrp.policy_data[i]->num_user_list = 1;
    wgrp.policy_data[i]->user_list =
        calloc(wgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(wgrp.policy_data[i]->user_list[0], "roy");
    //strcpyALL(wgrp.policy_data[i]->user_list[1], "roy_test1");
    //strcpyALL(wgrp.policy_data[i]->user_list[2], "roy_test2");

    write_policy("/test_policy_file", &wgrp);

    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * start read data[%d]\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }


    addgrp.num_policy = 2;
    addgrp.policy_data = calloc(addgrp.num_policy, sizeof(tPolicyStruct ));

    i = 0;
    addgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    addgrp.policy_data[i]->mask = __POILCY_READ;
    addgrp.policy_data[i]->num_user_list = 1;
    addgrp.policy_data[i]->user_list =
        calloc(addgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(addgrp.policy_data[i]->user_list[0], "roy_add_read");

    i++;
    addgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    addgrp.policy_data[i]->mask = __POILCY_WRITE;
    addgrp.policy_data[i]->num_user_list = 2;
    addgrp.policy_data[i]->user_list =
        calloc(addgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(addgrp.policy_data[i]->user_list[0], "roy_add_write");
    strcpyALL(addgrp.policy_data[i]->user_list[1], "roy_add_write2");

    PLM_DEBUG_PRINT(" * ------- start modify --------\n");
    modify_policy("/test_policy_file", eMODIFYRULE_ADD, &addgrp);

    free_tPolicyGrp(&rgrp);
    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * ------- after modify data[%d] --------\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }

    del_policy("/test_policy_file");
    del_policy("/md/test_policy_file");

}


void mix_case()
{
    int ret_int = 0;

    autofree_tPolicyGrp tPolicyGrp wgrp;
    autofree_tPolicyGrp tPolicyGrp rgrp;
    autofree_tPolicyGrp tPolicyGrp addgrp;

    memset(&wgrp, 0, sizeof(tPolicyGrp));
    memset(&rgrp, 0, sizeof(tPolicyGrp));
    memset(&addgrp, 0, sizeof(tPolicyGrp));

    int i =0;
    wgrp.num_policy = 1;
    wgrp.policy_data = calloc(wgrp.num_policy, sizeof(tPolicyStruct ));

    wgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    wgrp.policy_data[i]->mask = __POILCY_WRITE;
    wgrp.policy_data[i]->num_user_list = 1;
    wgrp.policy_data[i]->user_list =
        calloc(wgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(wgrp.policy_data[i]->user_list[0], "roy");
    //strcpyALL(wgrp.policy_data[i]->user_list[1], "roy_test1");
    //strcpyALL(wgrp.policy_data[i]->user_list[2], "roy_test2");

    write_policy("/test_policy_file", &wgrp);

    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * start read data[%d]\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }


    addgrp.num_policy = 1;
    addgrp.policy_data = calloc(addgrp.num_policy, sizeof(tPolicyStruct ));

    i = 0;
    addgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    addgrp.policy_data[i]->mask = __POILCY_READ;
    addgrp.policy_data[i]->num_user_list = 1;
    addgrp.policy_data[i]->user_list =
        calloc(addgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(addgrp.policy_data[i]->user_list[0], "roy_add_read");


    PLM_DEBUG_PRINT(" * start modify\n");
    modify_policy("/test_policy_file", eMODIFYRULE_ADD, &addgrp);

    free_tPolicyGrp(&rgrp);
    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * ------- after modify data[%d] --------\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }

    del_policy("/test_policy_file");
    del_policy("/md/test_policy_file");

}



void add_the_same_case()
{
    int ret_int = 0;
    autofree_tPolicyGrp tPolicyGrp wgrp;
    autofree_tPolicyGrp tPolicyGrp rgrp;
    autofree_tPolicyGrp tPolicyGrp addgrp;

    memset(&addgrp, 0, sizeof(tPolicyGrp));
    memset(&wgrp, 0, sizeof(tPolicyGrp));
    memset(&rgrp, 0, sizeof(tPolicyGrp));

    int i =0;
    wgrp.num_policy = 1;
    wgrp.policy_data = calloc(wgrp.num_policy, sizeof(tPolicyStruct ));

    wgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    wgrp.policy_data[i]->mask = __POILCY_WRITE;
    wgrp.policy_data[i]->num_user_list = 3;
    wgrp.policy_data[i]->user_list =
        calloc(wgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(wgrp.policy_data[i]->user_list[0], "roy");
    strcpyALL(wgrp.policy_data[i]->user_list[1], "roy_test1");
    strcpyALL(wgrp.policy_data[i]->user_list[2], "roy_test2");

    write_policy("/test_policy_file", &wgrp);

    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * start read data[%d]\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }


    addgrp.num_policy = 1;
    addgrp.policy_data = calloc(addgrp.num_policy, sizeof(tPolicyStruct ));

    i = 0;
    addgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    addgrp.policy_data[i]->mask = __POILCY_WRITE;
    addgrp.policy_data[i]->num_user_list = 2;
    addgrp.policy_data[i]->user_list =
        calloc(addgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(addgrp.policy_data[i]->user_list[0], "roy_add_write");
    strcpyALL(addgrp.policy_data[i]->user_list[1], "roy_test1");

    PLM_DEBUG_PRINT(" * start modify\n");
    modify_policy("/test_policy_file", eMODIFYRULE_ADD, &addgrp);

    free_tPolicyGrp(&rgrp);
    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * ------- after modify data[%d] --------\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }
    del_policy("/test_policy_file");
    del_policy("/md/test_policy_file");

}


void non_case()
{
    int ret_int = 0;
    autofree_tPolicyGrp tPolicyGrp wgrp;
    autofree_tPolicyGrp tPolicyGrp rgrp;
    autofree_tPolicyGrp tPolicyGrp addgrp;

    memset(&addgrp, 0, sizeof(tPolicyGrp));
    memset(&wgrp, 0, sizeof(tPolicyGrp));
    memset(&rgrp, 0, sizeof(tPolicyGrp));

    int i =0;
    wgrp.num_policy = 0;

    write_policy("/test_policy_file", &wgrp);

    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * start read data[%d]\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }
    addgrp.num_policy = 0;

    PLM_DEBUG_PRINT(" * start modify\n");
    modify_policy("/test_policy_file", eMODIFYRULE_ADD, &addgrp);

    free_tPolicyGrp(&rgrp);
    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * ------- after modify data[%d] --------\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }
    del_policy("/test_policy_file");
    del_policy("/md/test_policy_file");

}


void remove_case()
{
    int ret_int = 0;
    autofree_tPolicyGrp tPolicyGrp wgrp;
    autofree_tPolicyGrp tPolicyGrp rgrp;
    autofree_tPolicyGrp tPolicyGrp addgrp;

    memset(&wgrp, 0, sizeof(tPolicyGrp));
    memset(&rgrp, 0, sizeof(tPolicyGrp));
    memset(&addgrp, 0, sizeof(tPolicyGrp));


    int i =0;
    wgrp.num_policy = 2;
    wgrp.policy_data = calloc(wgrp.num_policy, sizeof(tPolicyStruct *));
    wgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    wgrp.policy_data[i]->mask = __POILCY_READ;
    wgrp.policy_data[i]->num_user_list = 3;
    wgrp.policy_data[i]->user_list =
        calloc(wgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(wgrp.policy_data[i]->user_list[0], "roy");
    strcpyALL(wgrp.policy_data[i]->user_list[1], "roy_test1_read");
    strcpyALL(wgrp.policy_data[i]->user_list[2], "roy_test2_read");
    i++;
    wgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    wgrp.policy_data[i]->mask = __POILCY_WRITE;
    wgrp.policy_data[i]->num_user_list = 3;
    wgrp.policy_data[i]->user_list =
        calloc(wgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(wgrp.policy_data[i]->user_list[0], "roy");
    strcpyALL(wgrp.policy_data[i]->user_list[1], "roy_test1_write");
    strcpyALL(wgrp.policy_data[i]->user_list[2], "roy_test2_write");

    write_policy("/test_policy_file", &wgrp);

    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * start read data[%d]\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }


    addgrp.num_policy = 2;
    addgrp.policy_data = calloc(addgrp.num_policy, sizeof(tPolicyStruct *));
    i = 0;
    addgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    addgrp.policy_data[i]->mask = __POILCY_READ;
    addgrp.policy_data[i]->num_user_list = 1;
    addgrp.policy_data[i]->user_list =
        calloc(addgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(addgrp.policy_data[i]->user_list[0], "roy_test1_read");

    i++;
    addgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    addgrp.policy_data[i]->mask = __POILCY_WRITE;
    addgrp.policy_data[i]->num_user_list = 2;
    addgrp.policy_data[i]->user_list =
        calloc(addgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(addgrp.policy_data[i]->user_list[0], "roy_test2_write");
    strcpyALL(addgrp.policy_data[i]->user_list[1], "roy_remove_write2");

    PLM_DEBUG_PRINT(" * start modify\n");
    modify_policy("/test_policy_file", eMODIFYRULE_DEL, &addgrp);

    free_tPolicyGrp(&rgrp);
    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * ------- after modify data[%d] --------\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }

    del_policy("/test_policy_file");
    del_policy("/md/test_policy_file");
}


void remvoe_mix_case()
{
    int ret_int = 0;

    autofree_tPolicyGrp tPolicyGrp wgrp;
    autofree_tPolicyGrp tPolicyGrp rgrp;
    autofree_tPolicyGrp tPolicyGrp addgrp;

    memset(&wgrp, 0, sizeof(tPolicyGrp));
    memset(&rgrp, 0, sizeof(tPolicyGrp));
    memset(&addgrp, 0, sizeof(tPolicyGrp));

    int i =0;
    wgrp.num_policy = 1;
    wgrp.policy_data = calloc(wgrp.num_policy, sizeof(tPolicyStruct ));

    wgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    wgrp.policy_data[i]->mask = __POILCY_WRITE;
    wgrp.policy_data[i]->num_user_list = 1;
    wgrp.policy_data[i]->user_list =
        calloc(wgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(wgrp.policy_data[i]->user_list[0], "roy");
    //strcpyALL(wgrp.policy_data[i]->user_list[1], "roy_test1");
    //strcpyALL(wgrp.policy_data[i]->user_list[2], "roy_test2");

    write_policy("/test_policy_file", &wgrp);

    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * start read data[%d]\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }


    addgrp.num_policy = 1;
    addgrp.policy_data = calloc(addgrp.num_policy, sizeof(tPolicyStruct ));

    i = 0;
    addgrp.policy_data[i] = calloc(1, sizeof(tPolicyStruct));
    addgrp.policy_data[i]->mask = __POILCY_READ;
    addgrp.policy_data[i]->num_user_list = 1;
    addgrp.policy_data[i]->user_list =
        calloc(addgrp.policy_data[i]->num_user_list, sizeof(char *));
    strcpyALL(addgrp.policy_data[i]->user_list[0], "roy_add_read");


    PLM_DEBUG_PRINT(" * start modify\n");
    modify_policy("/test_policy_file", eMODIFYRULE_DEL, &addgrp);

    free_tPolicyGrp(&rgrp);
    read_policy("/test_policy_file", &rgrp);

    PLM_DEBUG_PRINT(" * ------- after modify data[%d] --------\n", rgrp.num_policy);
    for(int i=0; i<rgrp.num_policy; i++)
    {

        PLM_DEBUG_PRINT(" * mask = %x\n", rgrp.policy_data[i]->mask);
        PLM_DEBUG_PRINT(" * num_user_list = %d\n", rgrp.policy_data[i]->num_user_list);
        int cnt = rgrp.policy_data[i]->num_user_list;
        for(int j=0; j<cnt; j++)
        {
            PLM_DEBUG_PRINT(" * user = %s\n", rgrp.policy_data[i]->user_list[j]);
        }

    }

    del_policy("/test_policy_file");
    del_policy("/md/test_policy_file");

}


int main()
{
    PLM_DEBUG_PRINT("/** all *******************************\n");
    full_case();
    PLM_DEBUG_PRINT("/***************************************\n");

    PLM_DEBUG_PRINT("/** read *******************************\n");
    read_case();
    PLM_DEBUG_PRINT("/***************************************\n");

    PLM_DEBUG_PRINT("/** write *******************************\n");
    write_case();
    PLM_DEBUG_PRINT("/***************************************\n");

    PLM_DEBUG_PRINT("/** mix_case *******************************\n");
    mix_case();
    PLM_DEBUG_PRINT("/***************************************\n");

    PLM_DEBUG_PRINT("/** add_the_same_case *******************************\n");
    add_the_same_case();
    PLM_DEBUG_PRINT("/***************************************\n");

    PLM_DEBUG_PRINT("/** non_case *******************************\n");
    non_case();
    PLM_DEBUG_PRINT("/***************************************\n");

    PLM_DEBUG_PRINT("/** remove_case *******************************\n");
    remove_case();
    PLM_DEBUG_PRINT("/***************************************\n");

    PLM_DEBUG_PRINT("/** remvoe_mix_case *******************************\n");
    remvoe_mix_case();
    PLM_DEBUG_PRINT("/***************************************\n");

    return 0;
}