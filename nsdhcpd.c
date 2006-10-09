/*
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1(the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis,WITHOUT WARRANTY OF ANY KIND,either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Alternatively,the contents of this file may be used under the terms
 * of the GNU General Public License(the "GPL"),in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License,indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above,a recipient may use your
 * version of this file under either the License or the GPL.
 *
 * Author Vlad Seryakov vlad@crystalballinc.com
 *
 */

/*
 * nsdhcpd.c -- DHCP server module
 *
 *
 * Authors
 *
 *     Vlad Seryakov vlad@crystalballinc.com
 */

#include "ns.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define DHCP_PADDING                     0
#define DHCP_SUBNET_MASK                 1
#define DHCP_TIME_OFFSET                 2
#define DHCP_ROUTERS                     3
#define DHCP_TIME_SERVERS                4
#define DHCP_NAME_SERVERS                5
#define DHCP_DOMAIN_NAME_SERVERS         6
#define DHCP_LOG_SERVERS                 7
#define DHCP_COOKIE_SERVERS              8
#define DHCP_LPR_SERVERS                 9
#define DHCP_IMPRESS_SERVERS             10
#define DHCP_RESOURCE_LOCATION_SERVERS   11
#define DHCP_HOST_NAME                   12
#define DHCP_BOOT_SIZE                   13
#define DHCP_MERIT_DUMP                  14
#define DHCP_DOMAIN_NAME                 15
#define DHCP_SWAP_SERVER                 16
#define DHCP_ROOT_PATH                   17
#define DHCP_EXTENSIONS_PATH             18
#define DHCP_IP_FORWARDING               19
#define DHCP_NON_LOCAL_SOURCE_ROUTING    20
#define DHCP_POLICY_FILTER               21
#define DHCP_MAX_DGRAM_REASSEMBLY        22
#define DHCP_DEFAULT_IP_TTL              23
#define DHCP_PATH_MTU_AGING_TIMEOUT      24
#define DHCP_PATH_MTU_PLATEAU_TABLE      25
#define DHCP_INTERFACE_MTU               26
#define DHCP_ALL_SUBNETS_LOCAL           27
#define DHCP_BROADCAST_ADDRESS           28
#define DHCP_PERFORM_MASK_DISCOVERY      29
#define DHCP_MASK_SUPPLIER               30
#define DHCP_ROUTER_DISCOVERY            31
#define DHCP_ROUTER_SOLICITATION_ADDRESS 32
#define DHCP_STATIC_ROUTES               33
#define DHCP_TRAILER_ENCAPSULATION       34
#define DHCP_ARP_CACHE_TIMEOUT           35
#define DHCP_IEEE802_3_ENCAPSULATION     36
#define DHCP_DEFAULT_TCP_TTL             37
#define DHCP_TCP_KEEPALIVE_INTERVAL      38
#define DHCP_TCP_KEEPALIVE_GARBAGE       39
#define DHCP_NIS_DOMAIN                  40
#define DHCP_NIS_SERVERS                 41
#define DHCP_NTP_SERVERS                 42
#define DHCP_VENDOR_ENCAPSULATED_OPTIONS 43
#define DHCP_NETBIOS_NAME_SERVERS        44
#define DHCP_NETBIOS_DD_SERVER           45
#define DHCP_NETBIOS_NODE_TYPE           46
#define DHCP_NETBIOS_SCOPE               47
#define DHCP_FONT_SERVERS                48
#define DHCP_X_DISPLAY_MANAGER           49
#define DHCP_REQUESTED_ADDRESS           50
#define DHCP_LEASE_TIME                  51
#define DHCP_OPTION_OVERLOAD             52
#define DHCP_MESSAGE_TYPE                53
#define DHCP_SERVER_IDENTIFIER           54
#define DHCP_PARAMETER_REQUEST_LIST      55
#define DHCP_MESSAGE                     56
#define DHCP_MAX_MESSAGE_SIZE            57
#define DHCP_RENEWAL_TIME                58
#define DHCP_REBINDING_TIME              59
#define DHCP_VENDOR_CLASS_IDENTIFIER     60
#define DHCP_CLIENT_IDENTIFIER           61
#define DHCP_NWIP_DOMAIN_NAME            62
#define DHCP_NWIP_SUBOPTIONS             63
#define DHCP_TFTP_SERVER                 66
#define DHCP_BOOT_FILE                   67
#define DHCP_STREATALK_SERVERS           75
#define DHCP_STREATALK_ASSIST_SERVERS    76
#define DHCP_USER_CLASS                  77
#define DHCP_FQDN                        81
#define DHCP_AGENT_OPTIONS               82
#define DHCP_SUBNET_SELECTION            118
#define DHCP_END                         255

#define DHCP_MAGIC                       0x63825363

#define BOOTREQUEST		         1
#define BOOTREPLY		         2

#define ETH_10MB		         1
#define ETH_10MB_LEN		         6

#define BROADCAST_FLAG                   0x8000
#define MAC_BCAST_ADDR                   "\xff\xff\xff\xff\xff\xff"

#define DHCP_DISCOVER		         1
#define DHCP_OFFER		         2
#define DHCP_REQUEST		         3
#define DHCP_DECLINE		         4
#define DHCP_ACK		         5
#define DHCP_NAK		         6
#define DHCP_RELEASE		         7
#define DHCP_INFORM		         8

#define OPTION_FIELD                     0
#define FILE_FIELD                       1
#define SNAME_FIELD                      2

#define OFFSET_CODE                      0
#define OFFSET_LEN                       1
#define OFFSET_DATA                      2

#define OPTION_SIZE                      512

#define OPTION_LIST                      0x1000
#define OPTION_BOOLEAN                   1
#define OPTION_U8                        2
#define OPTION_U16                       3
#define OPTION_S16                       4
#define OPTION_U32                       5
#define OPTION_S32                       6
#define OPTION_IPADDR                    7
#define OPTION_STRING                    8

typedef struct _dhcpDict {
    char *name;
    int flags;
    int code;
    int parent;
    struct _dhcpDict *next;
} DHCPDict;

typedef struct _dhcpOption {
    struct _dhcpOption *next;
    DHCPDict *dict;
    u_int8_t size;
    union {
      u_int8_t u8;
      u_int16_t u16;
      u_int32_t u32;
      u_int8_t *str;
    } value;
} DHCPOption;

typedef struct _dhcpRange {
    struct _dhcpRange *next;
    DHCPOption *check;
    DHCPOption *reply;
    u_int32_t gateway;
    u_int32_t netmask;
    u_int32_t start;
    u_int32_t end;
    u_int32_t lease_time;
    char macaddr[13];
} DHCPRange;

typedef struct _dhcpLease {
    u_int32_t lease_time;
    u_int32_t expires;
    u_int32_t ipaddr;
    char macaddr[13];
} DHCPLease;

typedef struct _dhcpServer {
    int port;
    char *name;
    char *proc;
    char *address;
    char *interface;
    int sock;
    int debug;
    int drivermode;
    struct sockaddr_in ipaddr;
    struct {
      int sock;
      int port;
    } client;
    Ns_Mutex lock;
    DHCPRange *ranges;
    struct {
      Tcl_HashTable ipaddr;
      Tcl_HashTable macaddr;
    } leases;
} DHCPServer;

typedef struct _dhcpPacket {
    u_int8_t op;
    u_int8_t htype;
    u_int8_t hlen;
    u_int8_t hops;
    u_int32_t xid;
    u_int16_t secs;
    u_int16_t flags;
    u_int32_t ciaddr;
    u_int32_t yiaddr;
    u_int32_t siaddr;
    u_int32_t giaddr;
    u_int8_t macaddr[16];
    u_int8_t sname[64];
    u_int8_t file[128];
    u_int32_t cookie;
    u_int8_t options[OPTION_SIZE];
} DHCPPacket;

typedef struct _dhcpRequest {
    DHCPPacket in;
    DHCPPacket out;
    DHCPServer *srvPtr;
    struct sockaddr_in sa;
    int sock;
    int size;
    char *buffer;
    u_int8_t msgtype;
    struct {
      u_int8_t msgtype;
      u_int32_t yiaddr;
      u_int32_t siaddr;
      u_int32_t netmask;
      u_int32_t gateway;
      u_int32_t broadcast;
      u_int32_t lease_time;
      DHCPRange *range;
    } reply;
    struct {
      u_int8_t *ptr;
      u_int8_t *end;
    } parser;
} DHCPRequest;

static Ns_SockProc DHCPSockProc;
static Ns_DriverProc DHCPDriverProc;
static int DHCPInterpInit(Tcl_Interp * interp, void *arg);
static int DHCPCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);
static DHCPRequest *DHCPRequestCreate(DHCPServer *srvPtr, SOCKET sock, char *buffer, int size, struct sockaddr_in *sa);
static int DHCPRequestProc(void *arg, Ns_Conn *conn);
static int DHCPRequestProcess(DHCPRequest *req);
static void DHCPRequestFree(DHCPRequest *req);
static int DHCPRequestRead(DHCPServer *srvPtr, SOCKET sock, char *buffer, int size, struct sockaddr_in *sa);
static int DHCPRequestReply(DHCPRequest *req);
static void DHCPPrintRequest(Ns_DString *ds, DHCPRequest *req, int reply);
static void DHCPPrintOptions(Ns_DString *ds, DHCPPacket *pkt, u_int8_t *ptr, int length, DHCPDict *info);
static void DHCPPrintValue(Ns_DString *ds, char *name, u_int8_t type, u_int8_t size, u_int8_t *data);
static int DHCPRequestSend(DHCPRequest *req, u_int32_t ipaddr, int port);
static void DHCPProcessDiscover(DHCPRequest *req);
static void DHCPProcessRequest(DHCPRequest *req);
static void DHCPProcessInform(DHCPRequest *req);
static void DHCPProcessRelease(DHCPRequest *req);
static void DHCPSend(DHCPRequest *req, u_int8_t type);
static void DHCPSendNAK(DHCPRequest *req);
static void DHCPRangeFree(DHCPRange *range);
static DHCPLease *DHCPLeaseAdd(DHCPServer *srvPtr, char *macaddr, u_int32_t ipaddr, u_int32_t lease_time, u_int32_t expires);
static void DHCPLeaseDel(DHCPServer *srvPtr, char *macaddr);
static char *addr2str(u_int32_t addr);
static char *str2mac(char *macaddr, char *str);
static char *bin2hex(char *buf, u_int8_t *macaddr, int numbytes);
static u_int8_t *hex2bin(u_int8_t *buf, char *hex, int size);
static u_int8_t *getOption(DHCPPacket *pkt, u_int8_t code, u_int8_t subcode, DHCPOption *val);
static void addOption(DHCPRequest *req, u_int8_t code, u_int8_t size, void *data);
static void addOption8(DHCPRequest *req, u_int8_t code, u_int8_t data);
static void addOption16(DHCPRequest *req, u_int8_t code, u_int16_t data);
static void addOption32(DHCPRequest *req, u_int8_t code, u_int32_t data);
static void addOptionIP(DHCPRequest *req, u_int8_t code, u_int32_t ipaddr);
static DHCPDict *getDict(const char *name);
static u_int8_t getType(const char *type);
static const char *getTypeName(u_int8_t type);
static u_int8_t getTypeSize(u_int8_t type);
static u_int8_t getMessage(const char *name);
static const char *getMessageName(u_int8_t type);

static Ns_Tls reqTls;

static DHCPDict agent_dict[256] = {
    { "agent.circuit-id",             OPTION_STRING,				 1,          82,  0 },
    { "agent.remote-id",              OPTION_STRING,				 2,          82,  0 },
    { "agent.agent-id",               OPTION_IPADDR,				 3,          82,  0 },
    { "agent.docsis-device-class",    OPTION_U32,     			         4,          82,  0 },
};

static DHCPDict main_dict[256] = {
    { "pad",                           0,					 0,          0,   0 },
    { "subnet-mask",                   OPTION_IPADDR,				 1,          0,   0 },
    { "time-offset",                   OPTION_S32,				 2,          0,   0 },
    { "routers",                       OPTION_IPADDR | OPTION_LIST,		 3,          0,   0 },
    { "time-servers",                  OPTION_IPADDR | OPTION_LIST,		 4,          0,   0 },
    { "ien116-name-servers",           OPTION_IPADDR | OPTION_LIST,		 5,          0,   0 },
    { "domain-name-servers",           OPTION_IPADDR | OPTION_LIST,		 6,          0,   0 },
    { "log-servers",                   OPTION_IPADDR | OPTION_LIST,		 7,          0,   0 },
    { "cookie-servers",                OPTION_IPADDR | OPTION_LIST,		 8,          0,   0 },
    { "lpr-servers",                   OPTION_IPADDR | OPTION_LIST,		 9,          0,   0 },
    { "impress-servers",               OPTION_IPADDR | OPTION_LIST,		 10,         0,   0 },
    { "resource-location-servers",     OPTION_IPADDR | OPTION_LIST,		 11,         0,   0 },
    { "host-name",                     OPTION_STRING,				 12,         0,   0 },
    { "boot-size",                     OPTION_U16,				 13,         0,   0 },
    { "merit-dump",                    OPTION_STRING,				 14,         0,   0 },
    { "domain-name",                   OPTION_STRING,				 15,         0,   0 },
    { "swap-server",                   OPTION_IPADDR,				 16,         0,   0 },
    { "root-path",                     OPTION_STRING,				 17,         0,   0 },
    { "extensions-path",               OPTION_STRING,			         18,         0,   0 },
    { "ip-forwarding",                 OPTION_BOOLEAN,				 19,         0,   0 },
    { "non-local-source-routing",      OPTION_BOOLEAN,		                 20,         0,   0 },
    { "policy-filter",                 OPTION_IPADDR | OPTION_LIST,		 21,         0,   0 },
    { "max-dgram-reassembly",          OPTION_U16,			         22,         0,   0 },
    { "default-ip-ttl",                OPTION_U8,			         23,         0,   0 },
    { "path-mtu-aging-timeout",        OPTION_U32,		                 24,         0,   0 },
    { "path-mtu-plateau-table",        OPTION_U16 | OPTION_LIST,		 25,         0,   0 },
    { "interface-mtu",                 OPTION_U16,				 26,         0,   0 },
    { "all-subnets-local",             OPTION_BOOLEAN,			         27,         0,   0 },
    { "broadcast-address",             OPTION_IPADDR,			         28,         0,   0 },
    { "perform-mask-discovery",        OPTION_BOOLEAN,		                 29,         0,   0 },
    { "mask-supplier",                 OPTION_BOOLEAN,				 30,         0,   0 },
    { "router-discovery",              OPTION_BOOLEAN,			         31,         0,   0 },
    { "router-solicitation-address",   OPTION_IPADDR,		                 32,         0,   0 },
    { "static-routes",                 OPTION_IPADDR | OPTION_LIST,		 33,         0,   0 },
    { "trailer-encapsulation",         OPTION_BOOLEAN,			         34,         0,   0 },
    { "arp-cache-timeout",             OPTION_U32,			         35,         0,   0 },
    { "ieee802-3-encapsulation",       OPTION_BOOLEAN,		                 36,         0,   0 },
    { "default-tcp-ttl",               OPTION_U8,			         37,         0,   0 },
    { "tcp-keepalive-interval",        OPTION_U32,		                 38,         0,   0 },
    { "tcp-keepalive-garbage",         OPTION_BOOLEAN,			         39,         0,   0 },
    { "nis-domain",                    OPTION_STRING,				 40,         0,   0 },
    { "nis-servers",                   OPTION_IPADDR | OPTION_LIST,		 41,         0,   0 },
    { "ntp-servers",                   OPTION_IPADDR | OPTION_LIST,		 42,         0,   0 },
    { "vendor",                        OPTION_STRING,		                 43,         0,   0 },
    { "netbios-name-servers",          OPTION_IPADDR | OPTION_LIST,		 44,         0,   0 },
    { "netbios-dd-server",             OPTION_IPADDR | OPTION_LIST,		 45,         0,   0 },
    { "netbios-node-type",             OPTION_U8,			         46,         0,   0 },
    { "netbios-scope",                 OPTION_STRING,				 47,         0,   0 },
    { "font-servers",                  OPTION_IPADDR | OPTION_LIST,		 48,         0,   0 },
    { "x-display-manager",             OPTION_IPADDR | OPTION_LIST,		 49,         0,   0 },
    { "requested-address",             OPTION_IPADDR,		                 50,         0,   0 },
    { "lease-time",                    OPTION_U32,			         51,         0,   0 },
    { "option-overload",               OPTION_U8,			         52,         0,   0 },
    { "message-type",                  OPTION_U8,			         53,         0,   0 },
    { "server-identifier",             OPTION_IPADDR,		                 54,         0,   0 },
    { "parameter-request-list",        OPTION_U8 | OPTION_LIST,		         55,         0,   0 },
    { "message",                       OPTION_STRING,				 56,         0,   0 },
    { "max-message-size",              OPTION_U16,			         57,         0,   0 },
    { "renewal-time",                  OPTION_U32,			         58,         0,   0 },
    { "rebinding-time",                OPTION_U32,			         59,         0,   0 },
    { "vendor-class-identifier",       OPTION_STRING,		                 60,         0,   0 },
    { "client-identifier",             OPTION_STRING,		                 61,         0,   0 },
    { "nwip-domain",                   OPTION_STRING,				 62,         0,   0 },
    { "nwip",                          OPTION_STRING,			         63,         0,   0 },
    { "nisplus-domain",                OPTION_STRING,			         64,         0,   0 },
    { "nisplus-servers",               OPTION_IPADDR | OPTION_LIST,		 65,         0,   0 },
    { "tftp-server-name",              OPTION_STRING,			         66,         0,   0 },
    { "bootfile-name",                 OPTION_STRING,				 67,         0,   0 },
    { "mobile-ip-home-agent",          OPTION_IPADDR | OPTION_LIST,		 68,         0,   0 },
    { "smtp-server",                   OPTION_IPADDR | OPTION_LIST,		 69,         0,   0 },
    { "pop-server",                    OPTION_IPADDR | OPTION_LIST,		 70,         0,   0 },
    { "nntp-server",                   OPTION_IPADDR | OPTION_LIST,		 71,         0,   0 },
    { "www-server",                    OPTION_IPADDR | OPTION_LIST,		 72,         0,   0 },
    { "finger-server",                 OPTION_IPADDR | OPTION_LIST,		 73,         0,   0 },
    { "irc-server",                    OPTION_IPADDR | OPTION_LIST,		 74,         0,   0 },
    { "streettalk-server",             OPTION_IPADDR | OPTION_LIST,		 75,         0,   0 },
    { "streettalk-assist-servers",     OPTION_IPADDR | OPTION_LIST,              76,         0,   0 },
    { "user-class",                    OPTION_STRING,				 77,         0,   0 },
    { "slp-directory-agent",           OPTION_STRING,			         78,         0,   0 },
    { "slp-service-scope",             OPTION_STRING,			         79,         0,   0 },
    { "option-80",                     OPTION_STRING,				 80,         0,   0 },
    { "fqdn",                          OPTION_STRING,				 81,         0,   0 },
    { "agent",                         OPTION_STRING,		                 82,         0,   agent_dict },
    { "option-83",                     OPTION_STRING,				 83,         0,   0 },
    { "option-84",                     OPTION_STRING,				 84,         0,   0 },
    { "nds-servers",                   OPTION_IPADDR | OPTION_LIST,		 85,         0,   0 },
    { "nds-tree-name",                 OPTION_STRING,				 86,         0,   0 },
    { "nds-context",                   OPTION_STRING,				 87,         0,   0 },
    { "option-88",                     OPTION_STRING,				 88,         0,   0 },
    { "option-89",                     OPTION_STRING,				 89,         0,   0 },
    { "option-90",                     OPTION_STRING,				 90,         0,   0 },
    { "option-91",                     OPTION_STRING,				 91,         0,   0 },
    { "option-92",                     OPTION_STRING,				 92,         0,   0 },
    { "option-93",                     OPTION_STRING,				 93,         0,   0 },
    { "option-94",                     OPTION_STRING,				 94,         0,   0 },
    { "option-95",                     OPTION_STRING,				 95,         0,   0 },
    { "option-96",                     OPTION_STRING,				 96,         0,   0 },
    { "option-97",                     OPTION_STRING,				 97,         0,   0 },
    { "uap-servers",                   OPTION_STRING,				 98,         0,   0 },
    { "option-99",                     OPTION_STRING,				 99,         0,   0 },
    { "option-100",                    OPTION_STRING,				 100,        0,   0 },
    { "option-101",                    OPTION_STRING,				 101,        0,   0 },
    { "option-102",                    OPTION_STRING,				 102,        0,   0 },
    { "option-103",                    OPTION_STRING,				 103,        0,   0 },
    { "option-104",                    OPTION_STRING,				 104,        0,   0 },
    { "option-105",                    OPTION_STRING,				 105,        0,   0 },
    { "option-106",                    OPTION_STRING,				 106,        0,   0 },
    { "option-107",                    OPTION_STRING,				 107,        0,   0 },
    { "option-108",                    OPTION_STRING,				 108,        0,   0 },
    { "option-109",                    OPTION_STRING,				 109,        0,   0 },
    { "option-110",                    OPTION_STRING,				 110,        0,   0 },
    { "option-111",                    OPTION_STRING,				 111,        0,   0 },
    { "option-112",                    OPTION_STRING,				 112,        0,   0 },
    { "option-113",                    OPTION_STRING,				 113,        0,   0 },
    { "option-114",                    OPTION_STRING,				 114,        0,   0 },
    { "option-115",                    OPTION_STRING,				 115,        0,   0 },
    { "option-116",                    OPTION_STRING,				 116,        0,   0 },
    { "option-117",                    OPTION_STRING,				 117,        0,   0 },
    { "subnet-selection",              OPTION_IPADDR,			         118,        0,   0 },
    { "option-119",                    OPTION_STRING,				 119,        0,   0 },
    { "option-120",                    OPTION_STRING,				 120,        0,   0 },
    { "option-121",                    OPTION_STRING,				 121,        0,   0 },
    { "option-122",                    OPTION_STRING,				 122,        0,   0 },
    { "option-123",                    OPTION_STRING,				 123,        0,   0 },
    { "option-124",                    OPTION_STRING,				 124,        0,   0 },
    { "option-125",                    OPTION_STRING,				 125,        0,   0 },
    { "option-126",                    OPTION_STRING,				 126,        0,   0 },
    { "option-127",                    OPTION_STRING,				 127,        0,   0 },
    { "option-128",                    OPTION_STRING,				 128,        0,   0 },
    { "option-129",                    OPTION_STRING,				 129,        0,   0 },
    { "option-130",                    OPTION_STRING,				 130,        0,   0 },
    { "option-131",                    OPTION_STRING,				 131,        0,   0 },
    { "option-132",                    OPTION_STRING,				 132,        0,   0 },
    { "option-133",                    OPTION_STRING,				 133,        0,   0 },
    { "option-134",                    OPTION_STRING,				 134,        0,   0 },
    { "option-135",                    OPTION_STRING,				 135,        0,   0 },
    { "option-136",                    OPTION_STRING,				 136,        0,   0 },
    { "option-137",                    OPTION_STRING,				 137,        0,   0 },
    { "option-138",                    OPTION_STRING,				 138,        0,   0 },
    { "option-139",                    OPTION_STRING,				 139,        0,   0 },
    { "option-140",                    OPTION_STRING,				 140,        0,   0 },
    { "option-141",                    OPTION_STRING,				 141,        0,   0 },
    { "option-142",                    OPTION_STRING,				 142,        0,   0 },
    { "option-143",                    OPTION_STRING,				 143,        0,   0 },
    { "option-144",                    OPTION_STRING,				 144,        0,   0 },
    { "option-145",                    OPTION_STRING,				 145,        0,   0 },
    { "option-146",                    OPTION_STRING,				 146,        0,   0 },
    { "option-147",                    OPTION_STRING,				 147,        0,   0 },
    { "option-148",                    OPTION_STRING,				 148,        0,   0 },
    { "option-149",                    OPTION_STRING,				 149,        0,   0 },
    { "option-150",                    OPTION_STRING,				 150,        0,   0 },
    { "option-151",                    OPTION_STRING,				 151,        0,   0 },
    { "option-152",                    OPTION_STRING,				 152,        0,   0 },
    { "option-153",                    OPTION_STRING,				 153,        0,   0 },
    { "option-154",                    OPTION_STRING,				 154,        0,   0 },
    { "option-155",                    OPTION_STRING,				 155,        0,   0 },
    { "option-156",                    OPTION_STRING,				 156,        0,   0 },
    { "option-157",                    OPTION_STRING,				 157,        0,   0 },
    { "option-158",                    OPTION_STRING,				 158,        0,   0 },
    { "option-159",                    OPTION_STRING,				 159,        0,   0 },
    { "option-160",                    OPTION_STRING,				 160,        0,   0 },
    { "option-161",                    OPTION_STRING,				 161,        0,   0 },
    { "option-162",                    OPTION_STRING,				 162,        0,   0 },
    { "option-163",                    OPTION_STRING,				 163,        0,   0 },
    { "option-164",                    OPTION_STRING,				 164,        0,   0 },
    { "option-165",                    OPTION_STRING,				 165,        0,   0 },
    { "option-166",                    OPTION_STRING,				 166,        0,   0 },
    { "option-167",                    OPTION_STRING,				 167,        0,   0 },
    { "option-168",                    OPTION_STRING,				 168,        0,   0 },
    { "option-169",                    OPTION_STRING,				 169,        0,   0 },
    { "option-170",                    OPTION_STRING,				 170,        0,   0 },
    { "option-171",                    OPTION_STRING,				 171,        0,   0 },
    { "option-172",                    OPTION_STRING,				 172,        0,   0 },
    { "option-173",                    OPTION_STRING,				 173,        0,   0 },
    { "option-174",                    OPTION_STRING,				 174,        0,   0 },
    { "option-175",                    OPTION_STRING,				 175,        0,   0 },
    { "option-176",                    OPTION_STRING,				 176,        0,   0 },
    { "option-177",                    OPTION_STRING,				 177,        0,   0 },
    { "option-178",                    OPTION_STRING,				 178,        0,   0 },
    { "option-179",                    OPTION_STRING,				 179,        0,   0 },
    { "option-180",                    OPTION_STRING,				 180,        0,   0 },
    { "option-181",                    OPTION_STRING,				 181,        0,   0 },
    { "option-182",                    OPTION_STRING,				 182,        0,   0 },
    { "option-183",                    OPTION_STRING,				 183,        0,   0 },
    { "option-184",                    OPTION_STRING,				 184,        0,   0 },
    { "option-185",                    OPTION_STRING,				 185,        0,   0 },
    { "option-186",                    OPTION_STRING,				 186,        0,   0 },
    { "option-187",                    OPTION_STRING,				 187,        0,   0 },
    { "option-188",                    OPTION_STRING,				 188,        0,   0 },
    { "option-189",                    OPTION_STRING,				 189,        0,   0 },
    { "option-190",                    OPTION_STRING,				 190,        0,   0 },
    { "option-191",                    OPTION_STRING,				 191,        0,   0 },
    { "option-192",                    OPTION_STRING,				 192,        0,   0 },
    { "option-193",                    OPTION_STRING,				 193,        0,   0 },
    { "option-194",                    OPTION_STRING,				 194,        0,   0 },
    { "option-195",                    OPTION_STRING,				 195,        0,   0 },
    { "option-196",                    OPTION_STRING,				 196,        0,   0 },
    { "option-197",                    OPTION_STRING,				 197,        0,   0 },
    { "option-198",                    OPTION_STRING,				 198,        0,   0 },
    { "option-199",                    OPTION_STRING,				 199,        0,   0 },
    { "option-200",                    OPTION_STRING,				 200,        0,   0 },
    { "option-201",                    OPTION_STRING,				 201,        0,   0 },
    { "option-202",                    OPTION_STRING,				 202,        0,   0 },
    { "option-203",                    OPTION_STRING,				 203,        0,   0 },
    { "option-204",                    OPTION_STRING,				 204,        0,   0 },
    { "option-205",                    OPTION_STRING,				 205,        0,   0 },
    { "option-206",                    OPTION_STRING,				 206,        0,   0 },
    { "option-207",                    OPTION_STRING,				 207,        0,   0 },
    { "option-208",                    OPTION_STRING,				 208,        0,   0 },
    { "option-209",                    OPTION_STRING,				 209,        0,   0 },
    { "authenticate",                  OPTION_STRING,				 210,        0,   0 },
    { "option-211",                    OPTION_STRING,				 211,        0,   0 },
    { "option-212",                    OPTION_STRING,				 212,        0,   0 },
    { "option-213",                    OPTION_STRING,				 213,        0,   0 },
    { "option-214",                    OPTION_STRING,				 214,        0,   0 },
    { "option-215",                    OPTION_STRING,				 215,        0,   0 },
    { "option-216",                    OPTION_STRING,				 216,        0,   0 },
    { "option-217",                    OPTION_STRING,				 217,        0,   0 },
    { "option-218",                    OPTION_STRING,				 218,        0,   0 },
    { "option-219",                    OPTION_STRING,				 219,        0,   0 },
    { "option-220",                    OPTION_STRING,				 220,        0,   0 },
    { "option-221",                    OPTION_STRING,				 221,        0,   0 },
    { "option-222",                    OPTION_STRING,				 222,        0,   0 },
    { "option-223",                    OPTION_STRING,				 223,        0,   0 },
    { "option-224",                    OPTION_STRING,				 224,        0,   0 },
    { "option-225",                    OPTION_STRING,				 225,        0,   0 },
    { "option-226",                    OPTION_STRING,				 226,        0,   0 },
    { "option-227",                    OPTION_STRING,				 227,        0,   0 },
    { "option-228",                    OPTION_STRING,				 228,        0,   0 },
    { "option-229",                    OPTION_STRING,				 229,        0,   0 },
    { "option-230",                    OPTION_STRING,				 230,        0,   0 },
    { "option-231",                    OPTION_STRING,				 231,        0,   0 },
    { "option-232",                    OPTION_STRING,				 232,        0,   0 },
    { "option-233",                    OPTION_STRING,				 233,        0,   0 },
    { "option-234",                    OPTION_STRING,				 234,        0,   0 },
    { "option-235",                    OPTION_STRING,				 235,        0,   0 },
    { "option-236",                    OPTION_STRING,				 236,        0,   0 },
    { "option-237",                    OPTION_STRING,				 237,        0,   0 },
    { "option-238",                    OPTION_STRING,				 238,        0,   0 },
    { "option-239",                    OPTION_STRING,				 239,        0,   0 },
    { "option-240",                    OPTION_STRING,				 240,        0,   0 },
    { "option-241",                    OPTION_STRING,				 241,        0,   0 },
    { "option-242",                    OPTION_STRING,				 242,        0,   0 },
    { "option-243",                    OPTION_STRING,				 243,        0,   0 },
    { "option-244",                    OPTION_STRING,				 244,        0,   0 },
    { "option-245",                    OPTION_STRING,				 245,        0,   0 },
    { "option-246",                    OPTION_STRING,				 246,        0,   0 },
    { "option-247",                    OPTION_STRING,				 247,        0,   0 },
    { "option-248",                    OPTION_STRING,				 248,        0,   0 },
    { "option-249",                    OPTION_STRING,				 249,        0,   0 },
    { "option-250",                    OPTION_STRING,				 250,        0,   0 },
    { "option-251",                    OPTION_STRING,				 251,        0,   0 },
    { "option-252",                    OPTION_STRING,				 252,        0,   0 },
    { "option-253",                    OPTION_STRING,				 253,        0,   0 },
    { "option-254",                    OPTION_STRING,				 254,        0,   0 },
    { "end",                           0,				         255,        0,   0 },
};

static Ns_ObjvTable msgtypes[] = {
    { "DISCOVER", DHCP_DISCOVER },
    { "OFFER",    DHCP_OFFER },
    { "INFORM",   DHCP_INFORM },
    { "REQUEST",  DHCP_REQUEST },
    { "DECLINE",  DHCP_DECLINE },
    { "NAK",      DHCP_NAK },
    { "ACK",      DHCP_ACK },
    { "RELEASE",  DHCP_RELEASE },
    { NULL,       0 }
};

NS_EXPORT int Ns_ModuleVersion = 1;

/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit --
 *
 *	Load the config parameters, setup the structures, and
 *	listen on the trap port.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Server will listen for SNMP traps on specified address and port.
 *
 *----------------------------------------------------------------------
 */

NS_EXPORT int Ns_ModuleInit(char *server, char *module)
{
    char *path;
    DHCPServer *srvPtr;
    Ns_DriverInitData init;
    static int first = 0;

    if (!first) {
        Ns_TlsAlloc(&reqTls, NULL);
        first = 1;
    }

    path = Ns_ConfigGetPath(server, module, NULL);
    srvPtr = (DHCPServer *) ns_calloc(1, sizeof(DHCPServer));
    srvPtr->name = server;
    srvPtr->debug = Ns_ConfigIntRange(path, "debug", 0, 0, 65535);
    srvPtr->port = Ns_ConfigIntRange(path, "port", 67, 1, 65535);
    srvPtr->proc = Ns_ConfigGetValue(path, "proc");
    srvPtr->address = Ns_ConfigGetValue(path, "address");
    srvPtr->drivermode = Ns_ConfigBool(path, "drivermode", 1);
    srvPtr->client.port = Ns_ConfigIntRange(path, "client_port", 68, 1, 65535);

    if ((Ns_GetSockAddr(&srvPtr->ipaddr, srvPtr->address, srvPtr->port) == NS_ERROR ||
         !strcmp(ns_inet_ntoa(srvPtr->ipaddr.sin_addr), "0.0.0.0")) &&
        Ns_GetSockAddr(&srvPtr->ipaddr, Ns_InfoHostname(), srvPtr->port) == NS_ERROR) {
        Ns_Log(Error, "Unable to resolve my host name");
        return NS_ERROR;
    }
    Ns_Log(Notice, "%s: server address is %s", module, ns_inet_ntoa(srvPtr->ipaddr.sin_addr));

    /* Configure DHCP listener */
    if (srvPtr->drivermode) {
        init.version = NS_DRIVER_VERSION_1;
        init.name = "nsdhcpd";
        init.proc = DHCPDriverProc;
        init.opts = NS_DRIVER_UDP|NS_DRIVER_QUEUE_ONREAD|NS_DRIVER_ASYNC;
        init.arg = srvPtr;
        init.path = NULL;
        if (Ns_DriverInit(server, module, &init) != NS_OK) {
            Ns_Log(Error, "%s: driver init failed", module);
            ns_free(srvPtr);
            return NS_ERROR;
        }
        Ns_RegisterRequest(server, "DHCP",  "/", DHCPRequestProc, NULL, srvPtr, 0);

    } else {
        srvPtr->sock = Ns_SockListenUdp(srvPtr->address, srvPtr->port);
        if (srvPtr->sock == -1) {
            Ns_Log(Error, "nsdhcpd: couldn't create socket: %s:%d: %s", srvPtr->address, srvPtr->port, strerror(errno));
            ns_free(srvPtr);
            return NS_ERROR;
        }
        Ns_SockCallback(srvPtr->sock, DHCPSockProc, srvPtr, NS_SOCK_READ | NS_SOCK_EXIT | NS_SOCK_EXCEPTION);
        Ns_Log(Notice, "%s: listening on %s:%d with proc <%s>", module, srvPtr->address, srvPtr->port,
                   srvPtr->proc ? srvPtr->proc : "");
    }

    Tcl_InitHashTable(&srvPtr->leases.macaddr, TCL_STRING_KEYS);
    Tcl_InitHashTable(&srvPtr->leases.ipaddr, TCL_ONE_WORD_KEYS);

    /*
     * Client socket if we will need to receive DHCP replies in send command
     */

    if (srvPtr->client.port > 0) {
        srvPtr->client.sock = Ns_SockListenUdp(srvPtr->address, srvPtr->client.port);
    }
    Ns_TclRegisterTrace(server, DHCPInterpInit, srvPtr, NS_TCL_TRACE_CREATE);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * DHCPInterpInit --
 *
 *      Add ns_snmp commands to interp.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
static int DHCPInterpInit(Tcl_Interp * interp, void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_dhcpd", DHCPCmd, arg, NULL);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * DHCPObjCmd --
 *
 *      Implement the ns_dhcp command.
 *
 * Results:
 *      Standard Tcl result.
 *
 * Side effects:
 *      Depends on command.
 *
 *----------------------------------------------------------------------
 */

static int DHCPCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
    DHCPServer *srvPtr = (DHCPServer *) arg;
    char macaddr[13];
    int i, status, cmd;
    Tcl_HashEntry *entry;
    Tcl_HashSearch search;
    DHCPDict *dict;
    DHCPRange *range;
    DHCPOption *opt, option;
    DHCPRequest *req;
    DHCPLease *lease;
    Ns_DString ds;

    enum {
        cmdDebug, cmdDictGet, cmdSend, cmdReqGet, cmdReqSet, cmdReqList,
        cmdRangeAdd, cmdRangeList, cmdLeaseList, cmdLeaseAdd, cmdLeaseDel
    };
    static CONST char *subcmd[] = {
        "debug", "dictget", "send", "reqget", "reqset", "reqlist",
        "rangeadd", "rangelist", "leaselist", "leaseadd", "leasedel",
        NULL
    };

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "option ?arg ...?");
        return TCL_ERROR;
    }
    status = Tcl_GetIndexFromObj(interp, objv[1], subcmd, "option", 0, &cmd);
    if (status != TCL_OK) {
        return TCL_ERROR;
    }

    switch (cmd) {
    case cmdSend: {
        int n = 1, listen = 0, timeout = 5, port = 67, type = DHCP_DISCOVER, mac[6];
        char *ipaddr = NULL, *macaddr = NULL;

        Ns_ObjvSpec sOpts[] = {
            {"-listen",    Ns_ObjvBool,   &listen,   (void *) NS_TRUE },
            {"-port",      Ns_ObjvInt,    &port,     NULL },
            {"-timeout",   Ns_ObjvInt,    &timeout,  NULL },
            {"-ipaddr",    Ns_ObjvString, &ipaddr,   NULL },
            {"-macaddr",   Ns_ObjvString, &macaddr,  NULL },
            {"-type",      Ns_ObjvFlags,  &type,     msgtypes },
            {"--",         Ns_ObjvBreak,  NULL,      NULL },
            {NULL, NULL, NULL, NULL}
        };
        Ns_ObjvSpec sArgs[] = {
            {NULL, NULL, NULL, NULL}
        };

        if (Ns_ParseObjv(sOpts, sArgs, interp, 2, objc, objv) != NS_OK) {
            Tcl_AppendResult(interp, "invalid arguments", NULL);
            return TCL_ERROR;
        }

        req = (DHCPRequest*)ns_calloc(1, sizeof(DHCPRequest));
        req->srvPtr = srvPtr;
        req->parser.ptr = req->out.options;
        req->parser.end = req->out.options;
        req->parser.end += OPTION_SIZE;
        req->sock = srvPtr->client.sock;

        if (ipaddr == NULL || !strcmp(ipaddr, "255.255.255.255")) {
            req->sa.sin_addr.s_addr = INADDR_BROADCAST;
        } else
        if (Ns_GetSockAddr(&req->sa, ipaddr, port) == NS_ERROR) {
            close(req->sock);
            DHCPRequestFree(req);
            Tcl_AppendResult(interp, "invalid address ", ipaddr, NULL);
            return TCL_ERROR;
        }
        if (macaddr != NULL) {
            memset(mac, 0, sizeof(mac));
            sscanf(macaddr, "%x%x%x%x%x%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
            for (n = 0; n < 6; n++) {
                req->out.macaddr[n] = mac[n];
            }
        }
        switch (type) {
        case DHCP_DISCOVER:
        case DHCP_REQUEST:
        case DHCP_RELEASE:
        case DHCP_INFORM:
            req->out.op = BOOTREQUEST;
            break;
        default:
            req->out.op = BOOTREPLY;
        }
        req->out.xid = (u_int32_t)Ns_DRand();
        req->out.htype = ETH_10MB;
        req->out.hlen = ETH_10MB_LEN;
        req->out.cookie = htonl(DHCP_MAGIC);
        addOption8(req, DHCP_MESSAGE_TYPE, type);
        addOption(req, DHCP_END, 0, NULL);
        DHCPRequestSend(req, req->sa.sin_addr.s_addr, port);
        DHCPRequestFree(req);

        if (listen) {
            int size;
            Ns_DString ds;
            char buffer[2048];
            struct sockaddr_in sa;

            if (Ns_SockWait(srvPtr->client.sock, NS_SOCK_READ, timeout) != NS_OK) {
                Tcl_AppendResult(interp, "timeout", NULL);
                return TCL_ERROR;
            }
            size = DHCPRequestRead(srvPtr, srvPtr->client.sock, buffer, sizeof(buffer), &sa);
            req = DHCPRequestCreate(srvPtr, srvPtr->client.sock, buffer, size, &sa);
            if (req != NULL) {
                Ns_DStringInit(&ds);
                DHCPPrintRequest(&ds, req, 0);
                Tcl_AppendResult(interp, ds.string, NULL);
                Ns_DStringFree(&ds);
            }
            DHCPRequestFree(req);
        }
        break;
    }

    case cmdLeaseAdd:
        if (objc < 6) {
            Tcl_WrongNumArgs(interp, 2, objv, "macaddr ipaddr leasetime expires");
            return TCL_ERROR;
        }
        str2mac(macaddr, Tcl_GetString(objv[2]));
        DHCPLeaseAdd(srvPtr, macaddr, inet_addr(Tcl_GetString(objv[3])), atoi(Tcl_GetString(objv[4])), atoi(Tcl_GetString(objv[5])));
        break;

    case cmdLeaseDel:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "macaddr");
            return TCL_ERROR;
        }
        str2mac(macaddr, Tcl_GetString(objv[2]));
        DHCPLeaseDel(srvPtr, macaddr);
        break;

    case cmdLeaseList:
        Ns_DStringInit(&ds);
        Ns_MutexLock(&srvPtr->lock);
        entry = Tcl_FirstHashEntry(&srvPtr->leases.macaddr, &search);
        while (entry) {
            lease = (DHCPLease*)Tcl_GetHashValue(entry);
            Ns_DStringPrintf(&ds, "%s %s %u %u ", lease->macaddr, addr2str(lease->ipaddr), lease->lease_time, lease->expires);
            entry = Tcl_NextHashEntry(&search);
        }
        Ns_MutexUnlock(&srvPtr->lock);
        Tcl_AppendResult(interp, ds.string, NULL);
        Ns_DStringFree(&ds);
        break;

    case cmdRangeList: {
        DHCPOption *options[2];

        Ns_DStringInit(&ds);
        Ns_MutexLock(&srvPtr->lock);
        for (range = srvPtr->ranges; range; range = range->next) {
            Ns_DStringPrintf(&ds, "%s ", addr2str(range->start));
            Ns_DStringPrintf(&ds, "%s ", addr2str(range->end));
            Ns_DStringPrintf(&ds, "%s ", addr2str(range->netmask));
            Ns_DStringPrintf(&ds, "%s ", addr2str(range->gateway));
            Ns_DStringPrintf(&ds, "%s ", range->macaddr);
            options[0] = range->check;
            options[1] = range->reply;
            for (i = 0; i < 2; i++) {
                Ns_DStringAppend(&ds, "{");
                for (opt = options[i]; opt; opt = opt->next) {
                    Ns_DStringPrintf(&ds, "%s ", opt->dict->name);
                    switch (opt->dict->flags & 0x00ff) {
                    case OPTION_IPADDR:
                        Ns_DStringPrintf(&ds, "%s ", addr2str(opt->value.u32));
                        break;

                    case OPTION_BOOLEAN:
                    case OPTION_U8:
                        Ns_DStringPrintf(&ds, "%d ", (int)opt->value.u8);
                        break;

                    case OPTION_U32:
                    case OPTION_S32:
                        Ns_DStringPrintf(&ds, "%u ", opt->value.u32);
                        break;

                    case OPTION_S16:
                    case OPTION_U16:
                        Ns_DStringPrintf(&ds, "%d ", (int)opt->value.u16);
                        break;

                    default:
                        Ns_DStringPrintf(&ds, "{%s} ", opt->value.str);
                    }
                }
                Ns_DStringAppend(&ds, "} ");
            }
        }
        Ns_MutexUnlock(&srvPtr->lock);
        Tcl_AppendResult(interp, ds.string, NULL);
        Ns_DStringFree(&ds);
        break;
    }

    case cmdRangeAdd: {
        int j, argc;
        CONST char **argv;
        char *options[2] = { NULL, NULL };
        char *macaddr = NULL, *start, *end, *netmask, *gateway;

        Ns_ObjvSpec raOpts[] = {
            {"-check",  Ns_ObjvString, &options[0], NULL },
            {"-reply",  Ns_ObjvString, &options[1], NULL },
            {"-macaddr",Ns_ObjvString, &macaddr,    NULL },
            {"--",      Ns_ObjvBreak,  NULL,        NULL },
            {NULL, NULL, NULL, NULL}
        };
        Ns_ObjvSpec raArgs[] = {
            {"start",   Ns_ObjvString, &start,   NULL },
            {"end",     Ns_ObjvString, &end,     NULL },
            {"netmask", Ns_ObjvString, &netmask, NULL },
            {"gateway", Ns_ObjvString, &gateway, NULL },
            {NULL, NULL, NULL, NULL}
        };

        if (Ns_ParseObjv(raOpts, raArgs, interp, 2, objc, objv) != NS_OK) {
            Tcl_AppendResult(interp, "invalid arguments", NULL);
            return TCL_ERROR;
        }
        range = (DHCPRange*)ns_calloc(1, sizeof(DHCPRange));
        range->start = inet_addr(start);
        range->end = inet_addr(end);
        range->netmask = inet_addr(netmask);
        range->gateway = inet_addr(gateway);
        if (macaddr != NULL) {
           str2mac(range->macaddr, macaddr);
        }
        for (j = 0; j < 2; j++) {
            if (options[j] == NULL) {
                continue;
            }
            if (Tcl_SplitList(interp, options[j], &argc, &argv) != TCL_OK) {
                DHCPRangeFree(range);
                Tcl_AppendResult(interp, "invalid list: ", options[j], NULL);
                return TCL_ERROR;
            }
            for (i = 0; i < argc - 1; i += 2) {
                dict = getDict(argv[i]);
                if (dict == NULL) {
                    DHCPRangeFree(range);
                    Tcl_Free((char *) argv);
                    Tcl_AppendResult(interp, "unknown option: ", argv[i], NULL);
                    return TCL_ERROR;
                }
                opt = (DHCPOption*)ns_malloc(sizeof(DHCPOption));
                if (j == 0) {
                    opt->next = range->check;
                    range->check = opt;
                } else {
                    opt->next = range->reply;
                    range->reply = opt;
                }
                opt->dict = dict;
                switch (dict->flags & 0x00ff) {
                case OPTION_BOOLEAN:
                case OPTION_U8:
                    opt->size = 1;
                    opt->value.u8 = argv[i+1][0];
                    break;

                case OPTION_IPADDR:
                    opt->size = 4;
                    opt->value.u32 = inet_addr(argv[i+1]);
                    break;

                case OPTION_U32:
                case OPTION_S32:
                    opt->size = 4;
                    opt->value.u32 = atoi(argv[i+1]);
                    break;

                case OPTION_S16:
                case OPTION_U16:
                    opt->size = 2;
                    opt->value.u16 = atoi(argv[i+1]);
                    break;

                default:
                    opt->value.str = (u_int8_t*)ns_strdup(argv[i+1]);
                    opt->size = strlen(argv[i+1]);
                }
            }
            Tcl_Free((char *) argv);
        }
        if (range) {
            Ns_MutexLock(&srvPtr->lock);
            range->next = srvPtr->ranges;
            srvPtr->ranges = range;
            Ns_MutexUnlock(&srvPtr->lock);
        }
        break;
    }

    case cmdDictGet:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name");
            return TCL_ERROR;
        }
        dict = getDict(Tcl_GetString(objv[2]));
        if (dict != NULL) {
            Tcl_Obj *obj = Tcl_NewListObj(0, 0);
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(dict->code));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(getTypeName(dict->flags), -1));
            Tcl_SetObjResult(interp, obj);
        }
        break;

    case cmdReqGet:
        req = (DHCPRequest*)Ns_TlsGet(&reqTls);
        if (!req) {
            break;
        }
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name");
            return TCL_ERROR;
        }
        Ns_DStringInit(&ds);
        if (!strcmp(Tcl_GetString(objv[2]), "type")) {
            Ns_DStringPrintf(&ds, "%s", getMessageName(req->msgtype));
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "xid")) {
            Ns_DStringPrintf(&ds, "%d", req->in.xid);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "ipaddr")) {
            Ns_DStringAppend(&ds, ns_inet_ntoa(req->sa.sin_addr));
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "yiaddr")) {
            Ns_DStringAppend(&ds, addr2str(req->in.yiaddr));
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "siaddr")) {
            Ns_DStringAppend(&ds, addr2str(req->in.siaddr));
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "giaddr")) {
            Ns_DStringAppend(&ds, addr2str(req->in.giaddr));
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "ciaddr")) {
            Ns_DStringAppend(&ds, addr2str(req->in.ciaddr));
        } else {
            dict = getDict(Tcl_GetString(objv[2]));
            if (dict != NULL && getOption(&req->in, dict->parent ? dict->parent : dict->code,
                                                    dict->parent ? dict->code : 0, &option) != NULL) {
                DHCPPrintValue(&ds, option.dict->name, option.dict->flags & 0x00ff, option.size, option.value.str);
            }
        }
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

    case cmdReqSet:
        req = (DHCPRequest*)Ns_TlsGet(&reqTls);
        if (!req) {
            break;
        }
        for (i = 2; i < objc - 1; i += 2) {
            if (!strcasecmp(Tcl_GetString(objv[i]), "type")) {
                req->reply.msgtype = getMessage(Tcl_GetString(objv[i+1]));
            } else
            if (!strcmp(Tcl_GetString(objv[i]), "yiaddr")) {
                req->in.yiaddr = inet_addr(Tcl_GetString(objv[i+1]));
            } else
            if (!strcmp(Tcl_GetString(objv[i]), "siaddr")) {
                req->in.siaddr = inet_addr(Tcl_GetString(objv[i+1]));
            } else
            if (!strcmp(Tcl_GetString(objv[i]), "giaddr")) {
                req->in.giaddr = inet_addr(Tcl_GetString(objv[i+1]));
            } else
            if (!strcmp(Tcl_GetString(objv[i]), "ciaddr")) {
                req->in.ciaddr = inet_addr(Tcl_GetString(objv[i+1]));
            } else
            if (!strcmp(Tcl_GetString(objv[i]), "network")) {
                req->reply.netmask = inet_addr(Tcl_GetString(objv[i+1]));
            } else
            if (!strcmp(Tcl_GetString(objv[i]), "broadcast")) {
                req->reply.broadcast = inet_addr(Tcl_GetString(objv[i+1]));
            } else
            if (!strcmp(Tcl_GetString(objv[i]), "gateway")) {
                req->reply.gateway = inet_addr(Tcl_GetString(objv[i+1]));
            } else
            if (!strcmp(Tcl_GetString(objv[i]), "lease_time")) {
                req->reply.lease_time = atol(Tcl_GetString(objv[i+1]));
            }
        }
        break;

    case cmdReqList:
        req = (DHCPRequest*)Ns_TlsGet(&reqTls);
        if (!req) {
            break;
        }
        Ns_DStringInit(&ds);
        DHCPPrintRequest(&ds, req, 0);
        Tcl_AppendResult(interp, ds.string, 0);
        Ns_DStringFree(&ds);
        break;

    case cmdDebug:
        if (objc > 2) {
            srvPtr->debug = atoi(Tcl_GetString(objv[2]));
        }
        Tcl_SetObjResult(interp, Tcl_NewIntObj(srvPtr->debug));
        break;
    }
    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * DHCPSockProc --
 *
 *	Socket callback to receive DHCP events
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */

static int DHCPSockProc(SOCKET sock, void *arg, int why)
{
    DHCPServer *srvPtr = (DHCPServer*)arg;
    struct sockaddr_in sa;
    DHCPRequest *req;
    char buffer[2048];
    int size;

    if (why != NS_SOCK_READ) {
        close(sock);
        return NS_FALSE;
    }
    size = DHCPRequestRead(srvPtr, sock, buffer, sizeof(buffer), &sa);
    req = DHCPRequestCreate(srvPtr, sock, buffer, size, &sa);
    if (req != NULL) {
        DHCPRequestProcess(req);
        DHCPRequestFree(req);
    }
    return NS_TRUE;
}

/*
 *----------------------------------------------------------------------
 *
 * DHCPDriverProc --
 *
 *	Driver callback to receive DHCP events
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */

static int DHCPDriverProc(Ns_DriverCmd cmd, Ns_Sock *sock, struct iovec *bufs, int nbufs)
{
    DHCPServer *srvPtr = (DHCPServer*)sock->driver->arg;

    switch (cmd) {
     case DriverQueue:

         /*
          *  Assign request line so our registered proc will be called
          */

         return Ns_DriverSetRequest(sock, "DHCP / DHCP/1.0");
         break;

     case DriverRecv:
         return DHCPRequestRead(srvPtr, sock->sock, bufs->iov_base, bufs->iov_len, &sock->sa);
         break;

     case DriverSend:
     case DriverKeep:
     case DriverClose:
         break;
    }
    return NS_ERROR;
}

/*
 *----------------------------------------------------------------------
 *
 * DHCPRequestProc --
 *
 *	Request callback for processing DHCP connections
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */

static int DHCPRequestProc(void *arg, Ns_Conn *conn)
{
    Ns_DString *ds;
    Ns_Sock *sockPtr;
    DHCPRequest *req;
    struct sockaddr_in sa;
    DHCPServer *srvPtr = (DHCPServer*)arg;

    ds = Ns_ConnSockContent(conn);
    sockPtr = Ns_ConnSockPtr(conn);
    sa = sockPtr->sa;

    req = DHCPRequestCreate(srvPtr, sockPtr->sock, ds->string, ds->length, &sa);
    if (req != NULL) {
        DHCPRequestProcess(req);
        DHCPRequestFree(req);
    }
    return NS_FILTER_BREAK;
}

/*
 *----------------------------------------------------------------------
 *
 * DHCPRequestCreate --
 *
 *	Create request structure
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */

static DHCPRequest *DHCPRequestCreate(DHCPServer *srvPtr, SOCKET sock, char *buffer, int size, struct sockaddr_in *sa)
{
    u_int8_t *type;
    DHCPRequest *req = NULL;

    if (buffer != NULL && size > 0) {
        req = (DHCPRequest*)buffer;
        if (size > sizeof(DHCPPacket)) {
	    Ns_Log(Debug, "nsdhcpd: packet received is too big %d > %d", size, sizeof(DHCPPacket));
	    return NULL;
	}
	if (ntohl(req->in.cookie) != DHCP_MAGIC) {
	    Ns_Log(Debug, "nsdhcpd: client sent bogus req %x, should be %x", req->in.cookie, DHCP_MAGIC);
	    return NULL;
	}

	if (req->in.hlen != 6 && req->in.hlen != 0) {
	    Ns_Log(Debug, "nsdhcpd: MAC length is %d bytes", req->in.hlen);
	    return NULL;
	}
        req = ns_calloc(1, sizeof(DHCPRequest));
        memcpy(&req->in, buffer, size);
        req->sock = dup(sock);
        req->srvPtr = srvPtr;
        req->buffer = buffer;
        req->size = size;
        req->sa = *sa;
        req->parser.ptr = req->out.options;
        req->parser.end = req->out.options;
        req->parser.end += OPTION_SIZE;
        type = getOption(&req->in, DHCP_MESSAGE_TYPE, 0, 0);
        if (type != NULL) {
            req->msgtype = *type;
        }
        return req;
    }
    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * DHCPRequestRead --
 *
 *	Read DHCP data from the socket
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */

static int DHCPRequestRead(DHCPServer *srvPtr, SOCKET sock, char *buffer, int size, struct sockaddr_in *sa)
{
    int len;
    socklen_t salen = sizeof(struct sockaddr_in);

    len = recvfrom(sock, buffer, size - 1, 0, (struct sockaddr*)sa, (socklen_t*)&salen);
    if (len <= 0) {
        if (errno) {
            Ns_Log(Debug, "DHCPRequestRead: %d: recv error: %d bytes, %s", sock, len, strerror(errno));
        }
        return NS_ERROR;
    }
    buffer[len] = 0;
    if (srvPtr->debug > 2) {
        Ns_Log(Debug, "nsdhcpd: received %d bytes from %s:%d", len, ns_inet_ntoa(sa->sin_addr), ntohs(sa->sin_port));
    }
    return len;
}

/*
 *----------------------------------------------------------------------
 *
 * DHCPRequestProcess --
 *
 *	Perform actual DHCP processing
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */

static int DHCPRequestProcess(DHCPRequest *req)
{
    if (req->srvPtr->debug > 3) {
        Ns_DString ds;
        Ns_DStringInit(&ds);
        DHCPPrintRequest(&ds, req, 0);
        Ns_Log(Debug, "nsdhcpd: request %d bytes from %s:%d: %s", req->size,
               ns_inet_ntoa(req->sa.sin_addr), ntohs(req->sa.sin_port), ds.string);
        Ns_DStringFree(&ds);
    }

    if (req->srvPtr->proc != NULL) {
        Tcl_Interp *interp = Ns_TclAllocateInterp(req->srvPtr->name);

        Ns_TlsSet(&reqTls, req);
        if (Tcl_EvalEx(interp, req->srvPtr->proc, -1, 0) != TCL_OK) {
            Ns_TclLogError(interp);
        }
        Ns_TclDeAllocateInterp(interp);
        Ns_TlsSet(&reqTls, 0);

        /* Script set reply code, we assume we are ready to return reply packet */
        switch (req->reply.msgtype) {
         case DHCP_ACK:
         case DHCP_OFFER:
             DHCPSend(req, DHCP_ACK);
             return NS_TRUE;

         case DHCP_NAK:
             DHCPSendNAK(req);
             return NS_TRUE;
        }
    }

    switch (req->msgtype) {
    case DHCP_DISCOVER:
    	DHCPProcessDiscover(req);
    	break;

    case DHCP_REQUEST:
    	DHCPProcessRequest(req);
    	break;

    case DHCP_INFORM:
    	DHCPProcessInform(req);
    	break;

    case DHCP_RELEASE:
    	DHCPProcessRelease(req);
        break;

    case DHCP_ACK:
    case DHCP_NAK:
    case DHCP_OFFER:
        break;

    default:
    	Ns_Log(Debug, "nsdhcpd: unsupported msg type (%d) %s -- ignoring", req->msgtype, bin2hex(req->buffer, req->in.macaddr, 6));
    }
    return NS_TRUE;
}

static void DHCPRequestFree(DHCPRequest *req)
{
    ns_free(req);
}

static int DHCPRequestSend(DHCPRequest *req, u_int32_t ipaddr, int port)
{
    int len;
    u_int8_t *ptr;
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ipaddr;
    sa.sin_port = htons(port);
    len = sizeof(DHCPPacket);
    ptr = (u_int8_t *) &req->out;
    while (*(ptr + len - 1) == 0 && *(ptr + len - 2) == 0 && *(ptr + len - 3) == 0) {
          len--;
    }
    return sendto(req->sock, (char *) &req->out, len, 0, (struct sockaddr *) &sa, sizeof(sa));
}

static int DHCPRequestReply(DHCPRequest *req)
{
    u_int8_t *ptr;
    u_int32_t ipaddr;
    struct sockaddr_in sa;
    int	size, port = 68;

    if (req->out.giaddr) {
        port = 67;
        ipaddr = req->out.giaddr;
    } else {
        if (req->out.ciaddr) {
            ipaddr = req->out.ciaddr;
        } else
        if (ntohs(req->in.flags) & BROADCAST_FLAG) {
            ipaddr = INADDR_BROADCAST;
        } else
        if (req->out.yiaddr) {
            ipaddr = req->out.yiaddr;
        } else {
            ipaddr = req->sa.sin_addr.s_addr;
        }
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ipaddr;
    sa.sin_port = htons(port);
    size = sizeof(DHCPPacket);
    ptr = (unsigned char *) &req->out;
    while (*(ptr + size - 1) == 0 && *(ptr + size - 2) == 0 && *(ptr + size - 3) == 0) {
          size--;
    }
    size = sendto(req->sock, (char *) &req->out, size, 0, (struct sockaddr *) &sa, sizeof(sa));
    if (req->srvPtr->debug > 3) {
        Ns_DString ds;
        Ns_DStringInit(&ds);
        DHCPPrintRequest(&ds, req, 1);
        Ns_Log(Debug, "nsdhcpd: reply %d bytes to %s:%d: %s", size, addr2str(ipaddr), port, ds.string);
        Ns_DStringFree(&ds);
    }
    return size;
}

static void DHCPPrintRequest(Ns_DString *ds, DHCPRequest *req, int reply)
{
    u_int8_t *type;
    DHCPPacket *pkt = reply ? &req->out : &req->in;

    type = getOption(pkt, DHCP_MESSAGE_TYPE, 0, 0);

    Ns_DStringPrintf(ds, "type %s from %s:%d hops %d flags %x xid %u ", getMessageName(type ? *type : 0),
                          ns_inet_ntoa(req->sa.sin_addr), ntohs(req->sa.sin_port), pkt->hops, pkt->flags, pkt->xid);
    Ns_DStringPrintf(ds, "yiaddr %s ", addr2str(pkt->yiaddr));
    Ns_DStringPrintf(ds, "ciaddr %s ", addr2str(pkt->ciaddr));
    Ns_DStringPrintf(ds, "giaddr %s ", addr2str(pkt->giaddr));
    Ns_DStringPrintf(ds, "siaddr %s ", addr2str(pkt->siaddr));
    Ns_DStringPrintf(ds, "macaddr %02x:%02x:%02x:%02x:%02x:%02x ",
                          pkt->macaddr[0], pkt->macaddr[1], pkt->macaddr[2],
                          pkt->macaddr[3], pkt->macaddr[4], pkt->macaddr[5]);
    DHCPPrintOptions(ds, pkt, pkt->options, OPTION_SIZE, main_dict);
}

static void DHCPPrintOptions(Ns_DString *ds, DHCPPacket *pkt, u_int8_t *ptr, int length, DHCPDict *info)
{
    int i = 0, size, code, over = 0, mode = OPTION_FIELD;

    while (i < length) {
          code = ptr[i + OFFSET_CODE];
          size = ptr[i + OFFSET_LEN];
          switch (code) {
          case DHCP_PADDING:
               i++;
               break;

          case DHCP_OPTION_OVERLOAD:
               if (i + 1 + size >= length) {
                   Ns_Log(Debug, "nsdhcpd: option field too long: code=%d, len=%d, %d > %d", code, size, i, length);
                   return;
               }
               over = ptr[i + 3];
               i += ptr[OFFSET_LEN] + 2;
               break;

          case DHCP_END:
               if (mode == OPTION_FIELD && over & FILE_FIELD) {
                   Ns_DStringPrintf(ds, "file %s ", pkt->file);
               } else
               if (mode == FILE_FIELD && over & SNAME_FIELD) {
                   Ns_DStringPrintf(ds, "sname %s ", pkt->sname);
               }
               return;

          default:
               if (i + 1 + size >= length) {
                   Ns_Log(Debug, "nsdhcpd: option field too long: code=%d, len=%d, %d > %d", code, size, i + 1 + size, length);
                   return;
               }
               if (info[code].next != NULL) {
                   DHCPPrintOptions(ds, pkt, ptr + i + OFFSET_DATA, size, info[code].next);
               }
               DHCPPrintValue(ds, info[code].name, info[code].flags & 0x00FF, size, ptr + i + OFFSET_DATA);
               i += size + 2;
          }
    }
}

static void DHCPPrintValue(Ns_DString *ds, char *name, u_int8_t type, u_int8_t size, u_int8_t *data)
{
    char buf[256];

    switch (type) {
    case OPTION_IPADDR:
        Ns_DStringPrintf(ds, "%s %s ", name, addr2str(*((u_int32_t*)(data))));
        break;
    case OPTION_BOOLEAN:
        Ns_DStringPrintf(ds, "%s %d ", name, *data);
        break;
    case OPTION_U8:
        Ns_DStringPrintf(ds, "%s %d ", name, *data);
        break;
    case OPTION_S16:
        Ns_DStringPrintf(ds, "%s %d ", name, ntohs(*((int16_t*)(data))));
        break;
    case OPTION_U16:
        Ns_DStringPrintf(ds, "%s %d ", name, ntohs(*((u_int16_t*)(data))));
        break;
    case OPTION_U32:
        Ns_DStringPrintf(ds, "%s %d ", name, ntohl(*((u_int32_t*)(data))));
        break;
    case OPTION_S32:
        Ns_DStringPrintf(ds, "%s %u ", name, ntohl(*((int32_t*)(data))));
        break;
    default:
        Ns_DStringPrintf(ds, "%s {%s} ", name, bin2hex(buf, data, size));
        break;
    }
}

static void DHCPSend(DHCPRequest *req, u_int8_t type)
{
    DHCPOption *opt, agent;

    switch (type) {
    case DHCP_DISCOVER:
    case DHCP_REQUEST:
    case DHCP_RELEASE:
    case DHCP_INFORM:
        req->out.op = BOOTREQUEST;
        break;
    default:
        req->out.op = BOOTREPLY;
    }
    req->out.htype = ETH_10MB;
    req->out.hlen = ETH_10MB_LEN;
    req->out.xid = req->in.xid;
    req->out.hops = req->in.hops;
    req->out.flags = req->in.flags;
    req->out.ciaddr = req->in.ciaddr;
    req->out.giaddr = req->in.giaddr;
    req->out.yiaddr = req->reply.yiaddr;
    req->out.siaddr = req->reply.siaddr;
    req->out.cookie = htonl(DHCP_MAGIC);
    memcpy(req->out.macaddr, req->in.macaddr, 6);

    addOption8(req, DHCP_MESSAGE_TYPE, type);
    addOption(req, DHCP_VENDOR_CLASS_IDENTIFIER, 7, "nsdhcpd");
    addOptionIP(req, DHCP_SERVER_IDENTIFIER, req->srvPtr->ipaddr.sin_addr.s_addr);

    if (req->reply.gateway) {
        addOption32(req, DHCP_ROUTERS, req->reply.gateway);
    }
    if (req->reply.netmask) {
        addOption32(req, DHCP_SUBNET_MASK, req->reply.netmask);
    }
    if (req->reply.broadcast) {
        addOption32(req, DHCP_BROADCAST_ADDRESS, req->reply.broadcast);
    }
    if (req->reply.lease_time) {
        int lease_time;
        addOption32(req, DHCP_LEASE_TIME, req->reply.lease_time);
        lease_time = req->reply.lease_time - 15;
        if (lease_time < 0) {
            lease_time = 5;
        }
        addOption32(req, DHCP_RENEWAL_TIME, lease_time);
        addOption32(req, DHCP_REBINDING_TIME, lease_time);
    }
    // Options from the range found
    if (req->reply.range) {
        for (opt = req->reply.range->reply; opt; opt = opt->next) {

            /*
             * Each complex option will be placed with one suboption,
             * this is not optimized but simple. Later we will merge them all into one
             * option with all suboptions
             */

            if (opt->dict->parent) {
                addOption(req, opt->dict->parent, opt->size + 2, NULL);
            }
            addOption(req, opt->dict->code, opt->size, opt->value.str);
        }
    }
    // We must return agent option back
    if (getOption(&req->in, DHCP_AGENT_OPTIONS, 0, &agent) != NULL) {
        addOption(req, DHCP_AGENT_OPTIONS, agent.size, agent.value.str);
    }
    addOption(req, DHCP_END, 0, NULL);
    DHCPRequestReply(req);
}

static void DHCPProcessDiscover(DHCPRequest *req)
{
    DHCPSend(req, DHCP_OFFER);
}

static void DHCPProcessRequest(DHCPRequest *req)
{
    req->reply.yiaddr = req->in.yiaddr;
    req->reply.siaddr = req->in.siaddr;
    DHCPSend(req, DHCP_ACK);
}

static void DHCPProcessInform(DHCPRequest *req)
{
    req->reply.yiaddr = req->in.yiaddr;
    req->reply.siaddr = req->in.siaddr;
    DHCPSend(req, DHCP_ACK);
}

static void DHCPProcessRelease(DHCPRequest *req)
{
}

static void DHCPSendNAK(DHCPRequest *req)
{
    req->out.op = BOOTREPLY;
    req->out.htype = ETH_10MB;
    req->out.hlen = ETH_10MB_LEN;
    req->out.xid = req->in.xid;
    req->out.hops = req->in.hops;
    req->out.flags = req->in.flags;
    req->out.ciaddr = req->in.ciaddr;
    req->out.giaddr = req->in.giaddr;
    req->out.cookie = htonl(DHCP_MAGIC);
    memcpy(req->out.macaddr, req->in.macaddr, 6);

    addOption8(req, DHCP_MESSAGE_TYPE, DHCP_NAK);
    addOption(req, DHCP_VENDOR_CLASS_IDENTIFIER, 7, "nsdhcpd");
    addOptionIP(req, DHCP_SERVER_IDENTIFIER, req->srvPtr->ipaddr.sin_addr.s_addr);
    addOption(req, DHCP_END, 0, NULL);

    DHCPRequestReply(req);
}

static void DHCPRangeFree(DHCPRange *range)
{
    DHCPOption *opt, *next;

    if (range == NULL) {
        return;
    }
    opt = range->check;
    while (opt != NULL) {
        next = opt->next;
        if ((opt->dict->flags & 0x00FF) == OPTION_STRING) {
            ns_free(opt->value.str);
        }
        ns_free(opt);
        opt = next;
    }
    opt = range->reply;
    while (opt != NULL) {
        next = opt->next;
        if ((opt->dict->flags & 0x00FF) == OPTION_STRING) {
            ns_free(opt->value.str);
        }
        ns_free(opt);
        opt = next;
    }
    ns_free(range);
}

static DHCPLease *DHCPLeaseAdd(DHCPServer *srvPtr, char *macaddr, u_int32_t ipaddr, u_int32_t lease_time, u_int32_t expires)
{
    int n;
    Tcl_HashEntry *entry;
    DHCPLease *lease = NULL;

    Ns_MutexLock(&srvPtr->lock);
    entry = Tcl_CreateHashEntry(&srvPtr->leases.macaddr, macaddr, &n);
    if (n) {
        lease = (DHCPLease*)ns_calloc(1, sizeof(DHCPLease));
        memcpy(lease->macaddr, macaddr, 12);
        lease->ipaddr = ipaddr;
        lease->lease_time = lease_time;
        lease->expires = expires;
        Tcl_SetHashValue(entry, (ClientData)lease);
        entry = Tcl_CreateHashEntry(&srvPtr->leases.ipaddr, (char*)lease->ipaddr, &n);
        Tcl_SetHashValue(entry, (ClientData)lease);
    }
    Ns_MutexUnlock(&srvPtr->lock);
    return lease;
}

static void DHCPLeaseDel(DHCPServer *srvPtr, char *macaddr)
{
    DHCPLease *lease;
    Tcl_HashEntry *entry;

    Ns_MutexLock(&srvPtr->lock);
    entry = Tcl_FindHashEntry(&srvPtr->leases.macaddr, macaddr);
    if (entry == NULL) {
        return;
    }
    lease = (DHCPLease*)Tcl_GetHashValue(entry);
    Tcl_DeleteHashEntry(entry);
    entry = Tcl_FindHashEntry(&srvPtr->leases.ipaddr, (char*)lease->ipaddr);
    if (entry) {
        Tcl_DeleteHashEntry(entry);
    }
    ns_free(lease);
    Ns_MutexUnlock(&srvPtr->lock);
}

static char *addr2str(u_int32_t addr)
{
    struct in_addr in;
    in.s_addr = addr;
    return ns_inet_ntoa(in);
}

static char *str2mac(char *macaddr, char *str)
{
    int i, j;
    for (i = j = 0; j < 12 && str[i]; i++) {
        if (isdigit(str[i])) {
            macaddr[j++] = str[i];
        }
    }
    macaddr[j] = 0;
    return macaddr;
}

static u_int8_t *hex2bin(u_int8_t *buf, char *hex, int size)
{
    char code[] = "00";
    u_int8_t *p = buf;

    while (*hex && size > 0) {
        if (isxdigit(*hex) && isxdigit(*(hex+1))) {
            code[0] = *hex++;
            code[1] = *hex++;
            *p++ = (char)strtol(code, NULL, 16);
            size--;
         } else {
            hex++;
         }
    }
    return buf;
}

static char *bin2hex(char *buf, u_int8_t *bin, int size)
{
    int i, n1, n2;
    char *p = buf;

    for (i = 0; i < size; i++) {
        if(!isprint(bin[i])) {
           break;
        }
    }
    /* No unprintable characters, return as is */
    if (i >= size) {
        memcpy(buf, bin, size);
        buf[size] = 0;
        return buf;
    }

    for (i = 0; i < size; i++) {
        n1 = (*(bin + i) & 0xf0) >> 4;
        n2 = *(bin + i) & 0x0f;
        if (n1 >= 10) {
            *p = n1 + 'a' - 10;
        } else {
            *p = n1 + '0';
        }
        p++;
        if (n2 >= 10) {
            *p = n2 + 'a' - 10;
        } else {
            *p = n2 + '0';
        }
        p++;
    }
    *p = 0;
    return buf;
}

static void addOption8(DHCPRequest *req, u_int8_t code, u_int8_t data)
{
    addOption(req, code, 1, &data);
}

static void addOption16(DHCPRequest *req, u_int8_t code, u_int16_t data)
{
    data = htons(data);
    addOption(req, code, 2, &data);
}

static void addOption32(DHCPRequest *req, u_int8_t code, u_int32_t data)
{
    data = htonl(data);
    addOption(req, code, 4, &data);
}

static void addOptionIP(DHCPRequest *req, u_int8_t code, u_int32_t ipaddr)
{
    addOption(req, code, 4, &ipaddr);
}

static void addOption(DHCPRequest *req, u_int8_t code, u_int8_t size, void *data)
{
    int i;
    u_int8_t *ptr = data;

    if ((size + 2) > (req->parser.end - req->parser.ptr)) {
    	Ns_Log(Debug, "nsdhcpd: Option Too Big - type %d len %d", code, size);
    	return;
    }

    *req->parser.ptr++ = code;
    *req->parser.ptr++ = size;
    for (i = 0; ptr && i < size; i++) {
        *req->parser.ptr++ = *ptr++;
    }
}

static const char *getMessageName(u_int8_t type)
{
    int i;

    for (i = 0; msgtypes[i].key; i++) {
         if (msgtypes[i].value == type) {
             return msgtypes[i].key;
         }
    }
    return "unknown";
}

static u_int8_t getMessage(const char *name)
{
    int i;

    for (i = 0; msgtypes[i].key; i++) {
         if (!strcasecmp(msgtypes[i].key, name)) {
             return msgtypes[i].value;
         }
    }
    return 0;
}

static const char *getTypeName(u_int8_t type)
{
    switch (type & 0x00FF) {
     case OPTION_IPADDR:
         return "ipaddr";

     case OPTION_BOOLEAN:
         return "boolean";

     case OPTION_U8:
         return "ubyte";

     case OPTION_S16:
         return "short";

     case OPTION_U16:
         return "ushort";

     case OPTION_U32:
         return "uint";

     case OPTION_S32:
         return "int";
    }
    return "string";
}

static u_int8_t getTypeSize(u_int8_t type)
{
    switch (type & 0x00FF) {
     case OPTION_IPADDR:
         return 4;

     case OPTION_BOOLEAN:
         return 1;

     case OPTION_U8:
         return 1;

     case OPTION_S16:
         return 2;

     case OPTION_U16:
         return 2;

     case OPTION_U32:
         return 4;

     case OPTION_S32:
         return 4;
    }
    return 0;
}

static u_int8_t getType(const char *type)
{
    if (!strcasecmp(type, "ipaddr")) {
        return OPTION_IPADDR;
    }
    if (!strcasecmp(type, "boolean")) {
        return OPTION_BOOLEAN;
    }
    if (!strcasecmp(type, "byte")) {
        return OPTION_U8;
    }
    if (!strcasecmp(type, "ushort")) {
        return OPTION_U16;
    }
    if (!strcasecmp(type, "short")) {
        return OPTION_S16;
    }
    if (!strcasecmp(type, "uint")) {
        return OPTION_U32;
    }
    if (!strcasecmp(type, "int")) {
        return OPTION_S32;
    }
    return OPTION_STRING;
}

/* get an option with bounds checking (warning, not aligned). */
static u_int8_t *getOption(DHCPPacket *pkt, u_int8_t code, u_int8_t subcode, DHCPOption *opt)
{
    u_int8_t *ptr;
    DHCPDict *dict = main_dict;
    int i = 0, size, length, over = 0, done = 0, mode = OPTION_FIELD;

    length = OPTION_SIZE;
    ptr = pkt->options;

    while (!done) {
          if (i >= length) {
              Ns_Log(Debug, "nsdhcpd: option field too long: %d: %d > %d", code, i, length);
              return NULL;
          }
          size = ptr[i + OFFSET_LEN];
          if (ptr[i + OFFSET_CODE] == code) {
              if (i + 1 + size >= length) {
                  Ns_Log(Debug, "nsdhcpd: option field too long: code=%d, len=%d, %d > %d", code, size, i, length);
                  return NULL;
              }
              if (subcode && dict[code].next != NULL) {
                  dict = dict[code].next;
                  length = size;
                  code = subcode;
                  subcode = 0;
                  i = 0;
                  continue;
              }
              if (opt) {
                  opt->size = size;
                  opt->value.str = ptr + i + OFFSET_DATA;
                  opt->dict = &dict[code];
              }
              return ptr + i + OFFSET_DATA;
              break;
          }
          switch (ptr[i + OFFSET_CODE]) {
          case DHCP_PADDING:
               i++;
               break;

          case DHCP_OPTION_OVERLOAD:
               if (i + 1 + size >= length) {
                   Ns_Log(Debug, "nsdhcpd: option field too long: code=%d, len=%d, %d > %d", DHCP_OPTION_OVERLOAD, size, i, length);
                   return NULL;
               }
               over = ptr[i + 3];
               i += ptr[OFFSET_LEN] + 2;
               break;

          case DHCP_END:
               if (mode == OPTION_FIELD && over & FILE_FIELD) {
                   ptr = pkt->file;
                   mode = FILE_FIELD;
                   length = 128;
                   i = 0;
               } else
               if (mode == FILE_FIELD && over & SNAME_FIELD) {
                   ptr = pkt->sname;
                   mode = SNAME_FIELD;
                   length = 64;
                   i = 0;
               } else {
                  done = 1;
               }
               break;

          default:
               i += size + 2;
          }
    }
    return NULL;
}

static DHCPDict *getDict(const char *name)
{
    int i, len = strlen(name);
    DHCPDict *dict = main_dict;
    const char *part2 = strchr(name, '.'), *part1 = name;

    if (part2 != NULL) {
        len = part2 - part1;
        part2++;
    }

    for (i = 0; i < 255; i++) {
        if (!strncasecmp(dict[i].name, part1, len)) {
            if (part2 != NULL && dict[i].next != NULL) {
                dict = dict[i].next;
                len = strlen(name);
                part1 = name;
                part2 = NULL;
                i = -1;
                continue;
            }
            return &dict[i];
        }
    }
    return NULL;
}
