/*
	Kernel Ircbot Framework
    (c) Tibbar 2006.  If you wish to use this code in your own project please contact me
	at tibbar@tibbar.org to obtain permission.
*/

#define PF_INET 1
#define SOCK_STREAM 1
#define IPPROTO_TCP 1

#define SOCKET_ERROR -1

#define MSG_PEEK TRUE

#define AF_INET 2;

/*
struct sockaddr {
        short   sin_family;
        USHORT sin_port;
        ULONG   sin_addr;
};
*/
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned long u_long;

struct in_addr {
        union {
                struct { u_char s_b1,s_b2,s_b3,s_b4; } S_un_b;
                struct { u_short s_w1,s_w2; } S_un_w;
                u_long S_addr;
        } S_un;
#define s_addr  S_un.S_addr
                                /* can be used for most tcp & ip code */
#define s_host  S_un.S_un_b.s_b2
                                /* host on imp */
#define s_net   S_un.S_un_b.s_b1
                                /* network */
#define s_imp   S_un.S_un_w.s_w2
                                /* imp */
#define s_impno S_un.S_un_b.s_b4
                                /* imp # */
#define s_lh    S_un.S_un_b.s_b3
                                /* logical host */
};

typedef unsigned short      			WORD;

struct sockaddr_in {
        short   sin_family;
        u_short sin_port;
        struct  in_addr sin_addr;
        char    sin_zero[8];
};



#define WSADESCRIPTION_LEN      256
#define WSASYS_STATUS_LEN       128

typedef struct WSAData {
        WORD                    wVersion;
        WORD                    wHighVersion;
#ifdef _WIN64
        unsigned short          iMaxSockets;
        unsigned short          iMaxUdpDg;
        char FAR *              lpVendorInfo;
        char                    szDescription[WSADESCRIPTION_LEN+1];
        char                    szSystemStatus[WSASYS_STATUS_LEN+1];
#else
        char                    szDescription[WSADESCRIPTION_LEN+1];
        char                    szSystemStatus[WSASYS_STATUS_LEN+1];
        unsigned short          iMaxSockets;
        unsigned short          iMaxUdpDg;
        char FAR *              lpVendorInfo;
#endif
} WSADATA;


NTSTATUS KSocketGetLastError(void);
void KSocketSetError(NTSTATUS errorCode);
PKSOCKET socket(int domain, int type, int protocol);
PKSOCKET socketbind(USHORT sin_port, ULONG  in_addr);
int connect(PKSOCKET pSocket, const struct sockaddr_in *serv_addr, int namelen);
int listen(PKSOCKET s,int backlog);
int shutdown(PKSOCKET pSocket, int how);
int send(PKSOCKET pSocket, const char* buf, int len, int flags);
int recv(PKSOCKET pSocket, char* buf, int len, int flags);