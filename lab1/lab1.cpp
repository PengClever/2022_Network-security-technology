#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>

#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

#define SERVERPORT 5555
#define BUFFERSIZE 64
char strStdinBuffer[BUFFERSIZE];
char strSocketBuffer[BUFFERSIZE];
char strEncryBuffer[BUFFERSIZE];
char strDecryBuffer[BUFFERSIZE];

typedef int INT32;
typedef char INT8;
typedef unsigned char  ULONG8;
typedef unsigned short ULONG16;
typedef unsigned long  ULONG32;

//初始置换IP
static const ULONG8 pc_first[64] = {
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17, 9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
};
//逆初始置换IP-1
static const ULONG8 pc_last[64] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
};
//按位取值或赋值
static const ULONG32 pc_by_bit[64] = {
    0x80000000L,0x40000000L,0x20000000L,0x10000000L, 0x8000000L,
    0x4000000L, 0x2000000L, 0x1000000L, 0x800000L, 0x400000L,
    0x200000L, 0x100000L,  0x80000L, 0x40000L, 0x20000L,0x10000L,
    0x8000L, 0x4000L, 0x2000L, 0x1000L, 0x800L, 0x400L, 0x200L,
    0x100L, 0x80L,0x40L,0x20L, 0x10L, 0x8L, 0x4L, 0x2L, 0x1L,
    0x80000000L,0x40000000L,0x20000000L,0x10000000L, 0x8000000L,
    0x4000000L, 0x2000000L, 0x1000000L, 0x800000L, 0x400000L,
    0x200000L, 0x100000L,  0x80000L, 0x40000L, 0x20000L, 0x10000L,
    0x8000L, 0x4000L, 0x2000L, 0x1000L, 0x800L, 0x400L, 0x200L,
    0x100L, 0x80L, 0x40L,0x20L, 0x10L, 0x8L,  0x4L, 0x2L, 0x1L
};
//置换运算P
static const ULONG8 des_P[32] = {
    16,7,20,21, 29,12,28,17, 1,15,23,26,
    5,18,31,10, 2,8,24,14, 32,27,3,9,
    19,13,30,6, 22,11,4,25
};
//数据扩展E
static const ULONG8 des_E[48] = {
    32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
    12,13,14,15,16,17,16,17,18,19,20,21,
    20,21,22,23,24,25,24,25,26,27,28,29,
    28,29,30,31,32,1 
};
//数据压缩S
static const ULONG8 des_S[8][64] = {
    {
        0xe,0x0,0x4,0xf,0xd,0x7,0x1,0x4,0x2,0xe,0xf,0x2,0xb,
        0xd,0x8,0x1,0x3,0xa,0xa,0x6,0x6,0xc,0xc,0xb,0x5,0x9,
        0x9,0x5,0x0,0x3,0x7,0x8,0x4,0xf,0x1,0xc,0xe,0x8,0x8,
        0x2,0xd,0x4,0x6,0x9,0x2,0x1,0xb,0x7,0xf,0x5,0xc,0xb,
        0x9,0x3,0x7,0xe,0x3,0xa,0xa,0x0,0x5,0x6,0x0,0xd
    },
    {
        0xf,0x3,0x1,0xd,0x8,0x4,0xe,0x7,0x6,0xf,0xb,0x2,0x3,
        0x8,0x4,0xf,0x9,0xc,0x7,0x0,0x2,0x1,0xd,0xa,0xc,0x6,
        0x0,0x9,0x5,0xb,0xa,0x5,0x0,0xd,0xe,0x8,0x7,0xa,0xb,
        0x1,0xa,0x3,0x4,0xf,0xd,0x4,0x1,0x2,0x5,0xb,0x8,0x6,
        0xc,0x7,0x6,0xc,0x9,0x0,0x3,0x5,0x2,0xe,0xf,0x9
    },
    {
        0xa,0xd,0x0,0x7,0x9,0x0,0xe,0x9,0x6,0x3,0x3,0x4,0xf,
        0x6,0x5,0xa,0x1,0x2,0xd,0x8,0xc,0x5,0x7,0xe,0xb,0xc,
        0x4,0xb,0x2,0xf,0x8,0x1,0xd,0x1,0x6,0xa,0x4,0xd,0x9,
        0x0,0x8,0x6,0xf,0x9,0x3,0x8,0x0,0x7,0xb,0x4,0x1,0xf,
        0x2,0xe,0xc,0x3,0x5,0xb,0xa,0x5,0xe,0x2,0x7,0xc
    },
    {
        0x7,0xd,0xd,0x8,0xe,0xb,0x3,0x5,0x0,0x6,0x6,0xf,0x9,
        0x0,0xa,0x3,0x1,0x4,0x2,0x7,0x8,0x2,0x5,0xc,0xb,0x1,
        0xc,0xa,0x4,0xe,0xf,0x9,0xa,0x3,0x6,0xf,0x9,0x0,0x0,
        0x6,0xc,0xa,0xb,0xa,0x7,0xd,0xd,0x8,0xf,0x9,0x1,0x4,
        0x3,0x5,0xe,0xb,0x5,0xc,0x2,0x7,0x8,0x2,0x4,0xe
    },
    {
        0x2,0xe,0xc,0xb,0x4,0x2,0x1,0xc,0x7,0x4,0xa,0x7,0xb,
        0xd,0x6,0x1,0x8,0x5,0x5,0x0,0x3,0xf,0xf,0xa,0xd,0x3,
        0x0,0x9,0xe,0x8,0x9,0x6,0x4,0xb,0x2,0x8,0x1,0xc,0xb,
        0x7,0xa,0x1,0xd,0xe,0x7,0x2,0x8,0xd,0xf,0x6,0x9,0xf,
        0xc,0x0,0x5,0x9,0x6,0xa,0x3,0x4,0x0,0x5,0xe,0x3
    },
    {
        0xc,0xa,0x1,0xf,0xa,0x4,0xf,0x2,0x9,0x7,0x2,0xc,0x6,
        0x9,0x8,0x5,0x0,0x6,0xd,0x1,0x3,0xd,0x4,0xe,0xe,0x0,
        0x7,0xb,0x5,0x3,0xb,0x8,0x9,0x4,0xe,0x3,0xf,0x2,0x5,
        0xc,0x2,0x9,0x8,0x5,0xc,0xf,0x3,0xa,0x7,0xb,0x0,0xe,
        0x4,0x1,0xa,0x7,0x1,0x6,0xd,0x0,0xb,0x8,0x6,0xd
    },
    {
        0x4,0xd,0xb,0x0,0x2,0xb,0xe,0x7,0xf,0x4,0x0,0x9,0x8,
        0x1,0xd,0xa,0x3,0xe,0xc,0x3,0x9,0x5,0x7,0xc,0x5,0x2,
        0xa,0xf,0x6,0x8,0x1,0x6,0x1,0x6,0x4,0xb,0xb,0xd,0xd,
        0x8,0xc,0x1,0x3,0x4,0x7,0xa,0xe,0x7,0xa,0x9,0xf,0x5,
        0x6,0x0,0x8,0xf,0x0,0xe,0x5,0x2,0x9,0x3,0x2,0xc
    },
    {
        0xd,0x1,0x2,0xf,0x8,0xd,0x4,0x8,0x6,0xa,0xf,0x3,0xb,
        0x7,0x1,0x4,0xa,0xc,0x9,0x5,0x3,0x6,0xe,0xb,0x5,0x0,
        0x0,0xe,0xc,0x9,0x7,0x2,0x7,0x2,0xb,0x1,0x4,0xe,0x1,
        0x7,0x9,0x4,0xc,0xa,0xe,0x8,0x2,0xd,0x0,0xf,0x6,0xc,
        0xa,0x9,0xd,0x0,0xf,0x3,0x3,0x5,0x5,0x6,0x8,0xb
    } 
};
//等分密钥
static const ULONG8 keyleft[28] = {
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,19,11,3,60,52,44,36
};
static const ULONG8 keyright[28] = {
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,21,13,5,28,20,12,4
};
//密钥移位
static const ULONG8 lefttable[16] = {
    1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};
//密钥选取
static const ULONG8 keychoose[48] ={
    14,17,11,24,1,5,3,28,15,6,21,10,
    23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
};

class CDesOperate{
private:
    //存储生成的子密钥
    ULONG32 subKey[16][2];
    //存储计算中间值
    ULONG32 firstKey[2];
    //用于完成一次独立的加密或解密过程
    bool handleData(ULONG32 *data, ULONG8 choice);
    //用于实现16轮的每一轮加解密
    bool oneStepOfMakeData(ULONG32 *left, ULONG32 *right, INT32 number);
    //用于生成初始秘钥
    bool makeFirstKey(ULONG32 *orgKey);
    //用于16轮迭代生成子秘钥的每一轮运算
    bool oneStepOfMakeSubKey(ULONG32 *left, ULONG32 *right, INT32 number);
public:
    CDesOperate(){
        for(int i=0;i<16;i++){
            for(int j=0;j<2;j++){
                subKey[i][j]=0;
            }
        }
        for(int i=0;i<2;i++){
            firstKey[i]=0;
        }
    }
    ~CDesOperate();
    //加密 参数依次为  明文  明文长度  密文 密文长度  秘钥 秘钥长度
    bool Encry(char* pPlaintext,int nPlaintextLength,char *pCipherBuffer,int &nCipherBufferLength, char *pKey,int nKeyLength);
    //解密 参数依次为 密文 密文长度 明文 明文长度   秘钥  密钥长度
    bool Decry(char* pCipher,int nCipherBufferLength,char *pPlaintextBuffer, int &nPlaintextBufferLength, char *pKey,int nKeyLength);
};


void clientMode();
void serverMode();
ssize_t totalRecv(int s,void *buf,size_t len,int flags );
void secretChat(int clientSocket, char *strIpAddr, char *key);

int main(){
    bool input = false;
    while(!input){
        printf("Client or Server?\r\n");
        char mode;
        cin >> mode;
        if (mode == 'c' || mode == 'C')
        {
            //Client mode
            input = true;
            clientMode();

        }
        else if (mode == 's' || mode == 'S')
        {
            //Server mode
            input = true;
            serverMode();
        }
        else
        {
            printf("Wrong input!\n");
        }
    }
    return 0;
}


bool CDesOperate::handleData(ULONG32 *left, ULONG8 choice){
    int j = 0;
    ULONG32 *right =& left[1];
    ULONG32 tempData[2] = {0};
    for(j = 0; j < 64; j++){
        if(j < 32){
            if(pc_first[j] > 32){
                if(*right&pc_by_bit[pc_first[j]-1]){
                    tempData[0] |= pc_by_bit[j];
                }
            }else{
                if(*left&pc_by_bit[pc_first[j]-1]){
                    tempData[0] |= pc_by_bit[j];
                }
            }
        }else{
            if(pc_first[j]>32){
                if(*right&pc_by_bit[pc_first[j]-1]){
                    tempData[1] |= pc_by_bit[j];
                }
            }else{
                if(*left&pc_by_bit[pc_first[j]-1]){
                    tempData[1] |= pc_by_bit[j];
                }
            }
        }
    }
    *left = tempData[0];
    *right = tempData[1];
    tempData[0] = 0;
    tempData[1] = 0;
    int number = 0;
    switch(choice){
    case 0:
        for(number = 0; number < 16; number++){
            oneStepOfMakeData(left, right, (ULONG32)number);
        }
        break;
    case 1:
        for(number=15;number>=0;number--){
            oneStepOfMakeData(left, right, (ULONG32)number);
        }
        break;
    default:
        break;
    }
    ULONG32 temp;
    temp = *left;
    *left = *right;
    *right = temp;
    for (j = 0; j < 64; j++)
    {
        if (j < 32)
        {
            if (pc_last[j] > 32)
            {
                if (*right&pc_by_bit[pc_last[j]-1])
                {
                    tempData[0] |= pc_by_bit[j];
                }
            }
            else
            {
                if (*left&pc_by_bit[pc_last[j]-1])
                {
                    tempData[0] |= pc_by_bit[j];
                }
            }
        }
        else
        {
            if (pc_last[j] > 32)
            {
                if (*right&pc_by_bit[pc_last[j]-1])
                {
                    tempData[1] |= pc_by_bit[j];
                }
            }
            else
            {
                if (*left&pc_by_bit[pc_last[j]-1])
                {
                    tempData[1] |= pc_by_bit[j];
                }
            }
        }
    }
    *left =  tempData[0] ;
    *right = tempData[1];
    return true;
}

bool CDesOperate::oneStepOfMakeData(ULONG32 *left, ULONG32 *right, INT32 number){
    ULONG32 oldRight =*right;
    ULONG8 useBySBox[8] = {0};
    ULONG32 exdesP[2] = {0};
    int j;
    for(j = 0; j < 48; j++){
        if (j < 24)
        {
            if ( *right&pc_by_bit[des_E[j]-1] )
            {
                exdesP[0] |= pc_by_bit[j] ;
            }
        }
        else
        {
            if ( *right&pc_by_bit[des_E[j]-1] )
            {
                exdesP[1] |= pc_by_bit[j-24] ;
            }
        }
    }
    for(j = 0; j < 2; j++){
        exdesP[j] ^= subKey[number][j];
    }
    exdesP[1] >>= 8 ;
    useBySBox[7] = (ULONG8) (exdesP[1]&0x0000003fL) ;
    exdesP[1] >>= 6 ;
    useBySBox[6] = (ULONG8) (exdesP[1]&0x0000003fL) ;
    exdesP[1] >>= 6 ;
    useBySBox[5] = (ULONG8) (exdesP[1]&0x0000003fL) ;
    exdesP[1] >>= 6 ;
    useBySBox[4] = (ULONG8) (exdesP[1]&0x0000003fL) ;
    exdesP[0] >>= 8 ;
    useBySBox[3] = (ULONG8) (exdesP[0]&0x0000003fL) ;
    exdesP[0] >>= 6 ;
    useBySBox[2] = (ULONG8) (exdesP[0]&0x0000003fL) ;
    exdesP[0] >>= 6 ;
    useBySBox[1] = (ULONG8) (exdesP[0]&0x0000003fL) ;
    exdesP[0] >>= 6 ;
    useBySBox[0] = (ULONG8) (exdesP[0]&0x0000003fL) ;
    exdesP[0] = 0 ;
    exdesP[1] = 0 ;
    *right = 0;
    for(j = 0; j < 7; j++){
        *right |= des_S[j][useBySBox[j]];
        *right <<= 4;
    }
    *right |= des_S[j][useBySBox[j]];
    ULONG32 tempData = 0;
    for (j = 0; j < 32; j++)
    {
        if (*right&pc_by_bit[des_P[j]-1] )
        {
            tempData |= pc_by_bit[j] ;
        }
    }
    *right = tempData ;
    *right ^= *left;
    *left = oldRight;
    return true;
}

bool CDesOperate::makeFirstKey(ULONG32 *orgKey){
    ULONG32 tempKey[2] = {0};
    ULONG32 *pFirstKey = (ULONG32 *)firstKey;
    ULONG32 *pTempKey = (ULONG32 *)tempKey;
    memset((ULONG8 *)firstKey, 0, sizeof(firstKey));
    memcpy((ULONG8 *)&tempKey, (ULONG8 *)orgKey, 8);
    memset((ULONG8 *)subKey, 0, sizeof(subKey));
    int j = 0;
    for(j = 0; j < 28; j++){
        if(keyleft[j] > 32){
            if(pTempKey[1] & pc_by_bit[keyleft[j] - 1]){
                pFirstKey[0] |= pc_by_bit[j];
            }
        }
        else{
            if(pTempKey[0] & pc_by_bit[keyleft[j] - 1]){
                pFirstKey[0] |= pc_by_bit[j];
            }
        }
        if(keyright[j] > 32){
            if(pTempKey[1] & pc_by_bit[keyright[j] - 1]){
                pFirstKey[1] |= pc_by_bit[j];
            }
        }
        else{
            if(pTempKey[0] & pc_by_bit[keyright[j] - 1]){
                pFirstKey[1] |= pc_by_bit[j];
            }
        }
    }
    for(j = 0; j < 16; j++){
        oneStepOfMakeSubKey(&pFirstKey[0], &pFirstKey[1], j);
    }
    return true;
}

bool CDesOperate::oneStepOfMakeSubKey(ULONG32 *left, ULONG32 *right, INT32 number){
    ULONG32 tempKey[2] = {0, 0};
    ULONG32 *pTempKey = (ULONG32 *)tempKey;
    ULONG32 *pSubKey = (ULONG32 *)subKey[number];
    ULONG32 helpData[3] = {0x0, 0x80000000, 0xc0000000};
    pTempKey[0] = *left&helpData[lefttable[number]];
    pTempKey[1] = *right&helpData[lefttable[number]];
    if(lefttable[number] == 1){
        pTempKey[0] >>= 27;
        pTempKey[1] >>= 27;
    }else{
        pTempKey[0] >>= 26;
        pTempKey[1] >>= 26;
    }
    pTempKey[0] &= 0xfffffff0;
    pTempKey[1] &= 0xfffffff0;
    *left <<= lefttable[number];
    *right <<= lefttable[number];
    *left |= pTempKey[0];
    *right |= pTempKey[1];
    pTempKey[0] = 0;
    pTempKey[1] = 0;

    int j=0;
    for(;j<48;j++){
        if(j<24){
            if(*left&pc_by_bit[keychoose[j]-1]){
                pSubKey[0]|=pc_by_bit[j];
            }
        }
        else{
            if(*right&pc_by_bit[keychoose[j]-28]){
                    pSubKey[1]|=pc_by_bit[j-24];
                }
            }
        }
    return true;
}

bool CDesOperate::Encry(char* pPlaintext, int nPlaintextLength, char *pCipherBuffer, int &nCipherBufferLength, char *pKey, int nKeyLength){
    if(nKeyLength != 8){
        return false;
    }
    makeFirstKey((ULONG32*)pKey);
    int length=((nPlaintextLength+7) / 8) * 2;
    if(nCipherBufferLength < length * 4){
        nCipherBufferLength = length * 4;
    }
    memset(pCipherBuffer,0,nCipherBufferLength);
    ULONG32 *output = (ULONG32 *)pCipherBuffer;
    ULONG32 *source;
    if(nPlaintextLength != sizeof(ULONG32)*length)
    {
        source = new ULONG32[length];
        memset(source, 0, sizeof(ULONG32)*length);
        memcpy(source, pPlaintext, nPlaintextLength);
    } 
    else
    {
        source = (ULONG32 *)pPlaintext;
    }
    ULONG32 msg[2] = {0, 0};
    for(int i = 0; i < (length/2); i++){
        msg[0] = source[2*i];
        msg[1] = source[2*i+1];
        handleData(msg,(ULONG8)0);
        output[2*i]=msg[0];
        output[2*i+1]=msg[1];
    }
    if(pPlaintext!=(char *)source)
    {
        delete []source;
    }
    return true;
}
bool CDesOperator::Decry(char* pCipher,int nCipherBufferLength,char *pPlaintextBuffer, int &nPlaintextBufferLength, char *pKey,int nKeyLength){
    if(nCipherBufferLength%8 != 0)
    {
        return false;
    }
    if(nPlaintextBufferLength<nCipherBufferLength)
    {
        nPlaintextBufferLength = nCipherBufferLength;
        return false;
    }
    if(nKeyLength != 8)
    {
        return false;
    }
    makeFirstKey((ULONG32*)pKey);
    memset(pPlaintextBuffer,0,nPlaintextBufferLength);
    ULONG32 *pSouce = (ULONG32 *)pCipher;
    ULONG32 *pDest = (ULONG32 *)pPlaintextBuffer;
    ULONG32 gp_msg[2] = {0,0};
    for (int i=0;i<(nCipherBufferLength/8);i++)
    {
        gp_msg[0] = pSouce[2*i];
        gp_msg[1] = pSouce[2*i+1];
        handleData(gp_msg,(ULONG8)1);
        pDest[2*i] = gp_msg[0];
        pDest[2*i+1] = gp_msg[1];
    }
    return true;
}

void clientMode(){
    char strIpAddr[16];
    printf("Please input the server address:\r\n");
    cin >> strIpAddr;
    int clientSocket;
    struct sockaddr_in serverAddr;
    //创建socket
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("Create socket fail");
        return;
    }
    //初始化serverAddr
    bzero(&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(strIpAddr);
    serverAddr.sin_port = htons(SERVERPORT);
    //connect服务器
    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0)
    {
        printf("Connect socket fail");
        return;
    }
    printf("Connect Success!\nBegin to chat...\n");
    secretChat(clientSocket, strIpAddr, "benbenmi");
    return;
}

void serverMode(){
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    //创建socket
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("Create socket fail");
        return;
    }
    //初始化serverAddr
    bzero(&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(SERVERPORT);
    //绑定socket
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(struct sockaddr)) == -1)
    {
        printf("Bind socket fail");
        return;
    }
    //listen socket
    if (listen(serverSocket, 5) == -1)
    {
        printf("listen socket fail");
        return;
    }
    printf("Listening...\n");
    socklen_t socklen = sizeof(struct sockaddr);
    //accept socket
    if ((clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &socklen)) == -1)
    {
        printf("accept socket fail");
        return;
    }
    close(serverSocket);
    printf("server: got connectoin from %s, port %d, socket %d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), clientSocket);
    secretChat(clientSocket, inet_ntoa(clientAddr.sin_addr), "benbenmi");
    close(clientSocket);
    return;
}

ssize_t totalRecv(int s, void *buf, size_t len, int flags){
    size_t nCurSize = 0;
    while(nCurSize < len){
        ssize_t nRes = recv(s, (char*)buf + nCurSize, len - nCurSize, flags);
        if(nRes < 0 || nRes + nCurSize > len){
            return -1;
        }
        nCurSize += nRes;
    }
    return nCurSize;
}

void secretChat(int clientSocket, char *strIpAddr, char *key){
    printf("secretChat\n");
    CDesOperate cDes;
    if(strlen(pKey)!=8)
    {
        printf("Key length error");
        return ;
    }
    pid_t nPid;
    nPid = fork();
    if(nPid != 0)
    {
        while(1)
        {
            bzero(&strSocketBuffer, BUFFERSIZE);
            int nLength = 0;
            nLength = totalRecv (nSock, strSocketBuffer, BUFFERSIZE, 0);
            if(nLength != BUFFERSIZE)
            {
                break;
            }
            else
            {
                int nLen = BUFFERSIZE;
                cDes.Decry(strSocketBuffer, BUFFERSIZE, strDecryBuffer, nLen, pKey, 8);
                strDecryBuffer[BUFFERSIZE-1]=0;
                if(strDecryBuffer[0] != 0 && strDecryBuffer[0] != '\n')
                {
                    printf("Receive message form <%s>: %s\n", pRemoteName, strDecryBuffer);
                    if(0 == memcmp("quit",strDecryBuffer,4))
                    {
                        printf("Quit!\n");
                        break;
                    }
                }
            }
        }
    }
    else
    {
        while(1)
        {
            bzero(&strStdinBuffer, BUFFERSIZE);
            while(strStdinBuffer[0]==0)
            {
                if (fgets(strStdinBuffer, BUFFERSIZE, stdin) == NULL)
                {
                    continue;
                }
            }
            int nLen = BUFFERSIZE;
            cDes.Encry(strStdinBuffer, BUFFERSIZE, strEncryBuffer, nLen, pKey, 8);
            if(send(nSock, strEncryBuffer, BUFFERSIZE,0)!=BUFFERSIZE)
            {
                perror("send");
            }
            else
            {
                if(0==memcmp("quit",strStdinBuffer,4))
                {
                    printf("Quit!\n");
                    break;
                }
            }
        }
    }
    return;
}