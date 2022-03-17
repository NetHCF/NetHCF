/* Width setting */
#define HOP_COUNT_WIDTH 8
#define IP2HC_INDEX_WIDTH 23
#define IP2HC_COUNTER_WIDTH 8
#define TEMPORARY_BITMAP_WIDTH 32
#define TEMPORARY_BITMAP_INDEX_WIDTH 4
#define SESSION_INDEX_WIDTH 8
#define SESSION_TABLE_SIZE 256 // 2^8
#define SESSION_STATE_WIDTH 2
#define SESSION_MONITOR_RESULT_WIDTH 3
#define PACKET_TAG_WIDTH 2

/* Size setting */
#define NETHCF_ENABLE_TABLE_SIZE 1
#define NETHCF_PREPARE_TABLE_SIZE 1
#define HC_INSPECT_TABLE_SIZE 8
/* #define IP2HC_TABLE_SIZE 65536 // 2^16 */
#define IP2HC_TABLE_SIZE 13
#define TEMPORARY_BITMAP_SIZE 16
#define FORWARD_TABLE_SIZE 10
#define ONE_ACTION_TABLE_SIZE 0

/* Specific value setting */
#define CLONE_SPEC_VALUE 250
#define CONTROLLER_IP_ADDRESS 0xC0A83865 //192.168.56.101
#define CONTROLLER_PORT 3 // Maybe this parameter can be stored in a register
#define PACKET_TRUNCATE_LENGTH 54
#define IP2HC_HOT_THRESHOLD 10

/* States of NetHCF */
#define LEARNING_STATE 0
#define FILTERING_STATE 1

/* Flag of packets */
#define NORMAL_FLAG 0
#define ABNORMAL_FLAG 1
#define SYN_COOKIE_FLAG 2

/* States of TCP session monitor */
#define SESSION_INITIAL 0
#define HANDSHAKE_START 1
#define SYN_COOKIE_START 2
#define SYN_COOKIE_FINISH 3

/* Results of TCP session monitor */
#define PASS_AND_NOP 0
#define FIRST_SYN 1
#define SYNACK_WITHOUT_PROXY 2
#define ACK_WITHOUT_PROXY 3
#define ACK_WITH_PROXY 4
#define SYN_AFTER_PROXY 5
#define MONITOR_ABNORMAL 6
