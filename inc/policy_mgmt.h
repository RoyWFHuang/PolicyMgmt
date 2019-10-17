#ifndef __policy_mgmt_H__
#define __policy_mgmt_H__

#include <stdint.h>

#ifndef POLICY_PREFIX
#define POLICY_PREFIX "._md_FILE_POLICY_"
#endif /* not POLICY_PREFIX */

#ifndef MD_DIR_PATH
#   define MD_DIR_PATH "/opt/csgfs/metadata/normal/"
#endif /* not MD_DIR_PATH */

#ifndef MD_RCM_DIR_PATH
#   define MD_RCM_DIR_PATH "/opt/csgfs/metadata/rcm/"
#endif /* not MD_DIR_PATH */


#define ePOILCY_READ (uint8_t)(0x01)
#define ePOILCY_WRITE ePOILCY_READ < 1


typedef struct _tPolicyStruct
{
    uint8_t policy_mask_uint8;
    int num_int;
    char **user_list_ppchar;
}tPolicyStruct;

typedef struct _tPolicyGrp
{
    int num_int;
    tPolicyStruct *policy_data_pstruct;
}tPolicyGrp;

#endif
