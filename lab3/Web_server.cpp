#include <iostream>
#include <ctime>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>


typedef unsigned char 	BYTE;
typedef unsigned short 	WORD;
typedef unsigned int 	DWORD;
typedef int 			SOCKET;
typedef char * 			LPSTR;

#define METHOD_GET 		0
#define METHOD_HEAD 	1
#define _MAX_PATH 		128
#define DATA_BUFSIZE 	2048
#define SOCKET_ERROR 	-1
#define HTTPPORT 		22222
#define IPADDR 			"127.0.0.1"
#define ROOTDIR 		"/home/pengclever/code/c++/code/NST/lab3/www"
#define DHFILE 			"dh1024.pem"
#define INVALID_SOCKET 	(SOCKET)-1
#define INVALID_METHOD 	-1
#define INVALID_HANDLE_VALUE NULL

#define HTTP_STATUS_OK				"200 OK"
#define HTTP_STATUS_CREATED			"201 Created"
#define HTTP_STATUS_ACCEPTED		"202 Accepted"
#define HTTP_STATUS_NOCONTENT		"204 No Content"
#define HTTP_STATUS_MOVEDPERM		"301 Moved Permanently"
#define HTTP_STATUS_MOVEDTEMP		"302 Moved Temporarily"
#define HTTP_STATUS_NOTMODIFIED		"304 Not Modified"
#define HTTP_STATUS_BADREQUEST		"400 Bad Request"
#define HTTP_STATUS_UNAUTHORIZED	"401 Unauthorized"
#define HTTP_STATUS_FORBIDDEN		"403 Forbidden"
#define HTTP_STATUS_NOTFOUND		"404 File can not fonund!"
#define HTTP_STATUS_SERVERERROR		"500 Internal Server Error"
#define HTTP_STATUS_NOTIMPLEMENTED	"501 Not Implemented"
#define HTTP_STATUS_BADGATEWAY		"502 Bad Gateway"
#define HTTP_STATUS_UNAVAILABLE		"503 Service Unavailable"

using namespace std;

static char *pass;
static int password_cb(char *buf, int num, int rwflag, void *userdata)
{
    if (num < strlen(pass) + 1)
        return (0);

    strcpy(buf, pass);
    return (strlen(pass));
}

class CHttpProtocol;

typedef struct REQUEST
{
	SOCKET Socket;
	int nMethod;
	DWORD dwRecv;
	DWORD dwSend;
	FILE * fp;
    CHttpProtocol *chp;
	char szFileName[_MAX_PATH];
	char postfix[10];
	char StatuCodeReason[100];
}REQUEST, *PREQUEST;

class CHttpProtocol
{
public:
    SOCKET ListenSocket;
	char strRootDir[_MAX_PATH];
	char Time[50];
    SSL *ssl;
    SSL_CTX *ctx;
    SSL_METHOD *meth;

public:
    void initialize_ctx();
    void load_dh_params(char *file);
    bool TcpListen();
    bool StartHttpSrv();
    void StopHttpSrv();
    static void *ListenThread(void *param);
    static void *ClientThread(void *param);
	void Disconnect(PREQUEST pReq);
    void Analyse(PREQUEST pReq, char* pBuf);
    bool SSLRecvRequest(PREQUEST pReq, BIO *io, char *pBuf, DWORD dwBufSize);
    bool SSLSendHeader(PREQUEST pReq, BIO *io);
    bool SSLSendFile(PREQUEST pReq, BIO *io);
    bool SSLSendBuffer(PREQUEST pReq, BIO *io, char *pBuf, DWORD dwBufSize);

	bool FileExist(PREQUEST pReq);
    int  GetFileSize(PREQUEST pReq);
	void GetCurTime(LPSTR Time);
	bool GetLastModified(PREQUEST pReq, LPSTR Time);
	bool GetContenType(PREQUEST pReq, LPSTR type);

public:
	~CHttpProtocol(void);
};

CHttpProtocol::~CHttpProtocol(void){}

void CHttpProtocol::initialize_ctx()
{
    SSL_library_init();
    SSL_load_error_strings();
    meth = (SSL_METHOD *)SSLv23_method();
    ctx = SSL_CTX_new(meth);
    if (!ctx)
    {
        printf("Error creating the context.\n");
        exit(0);
    }
    if (SSL_CTX_use_certificate_chain_file(ctx, "server.crt") <= 0)
    {
        printf("Error setting the certificate file.\n");
        exit(0);
    }
    char password[] = "peng";
    pass = password;
    SSL_CTX_set_default_passwd_cb(this->ctx, password_cb);
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0){
        printf("Error setting the key file.\n");
        exit(0);
    }
    if (SSL_CTX_check_private_key(ctx) == 0) {
        printf("Private key does not match the certificate public key\n");
        exit(0);
    }
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", 0) < 1){
        printf("Error setting the verify locations.\n");
        exit(0);
    }
	return;
}

void CHttpProtocol::load_dh_params(char *file)
{
    DH *ret = 0;
	BIO *bio;
    if ((bio = BIO_new_file(file, "r")) == NULL){
        printf("Couldn't open DH file");
		exit(0);
	}
    ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (SSL_CTX_set_tmp_dh(this->ctx, ret) < 0){
        printf("Couldn't set DH parameters");
		exit(0);
	}
	return;
}

bool CHttpProtocol::TcpListen()
{
    ListenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (ListenSocket < 0) {
        printf("Socket function failed with error\n");
        return false;
    }
    struct sockaddr_in service;
	memset(&service, 0, sizeof(service));
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr(IPADDR);
    service.sin_port = htons(HTTPPORT);
	int val = 1;
    setsockopt(ListenSocket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	sprintf(strRootDir, ROOTDIR);
    int iResult;
	iResult = bind(ListenSocket, (struct sockaddr *)&service, sizeof (service));
    if (iResult == SOCKET_ERROR) 
	{
        printf("Bind failed with error\n");
        return false;
    }
	iResult = listen(ListenSocket, SOMAXCONN);
	if(iResult == SOCKET_ERROR) 
	{
		printf("Listen failed with error\n");
		return false;
	}
    return true;
}

bool CHttpProtocol::StartHttpSrv()
{
    initialize_ctx();
    load_dh_params((char *)DHFILE);
	if (TcpListen())
	{
		printf("***********  Server Starting  ***********\n");
		pthread_t listen_tid;
		pthread_create(&listen_tid, NULL, &ListenThread, this);
		pthread_join(listen_tid, NULL);
		return true;
	}
	return false;
}

void CHttpProtocol::StopHttpSrv()
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
	return;
}

void *CHttpProtocol::ListenThread(void *param)
{
	while (true)
    {
		CHttpProtocol *pHttpProtocol = (CHttpProtocol *)param;
		PREQUEST pReq = new REQUEST;
		if (pReq == NULL)
		{
			printf("No memory for request\n");
			exit(0);
		}
		pReq->Socket = INVALID_SOCKET;
		pReq->nMethod = INVALID_METHOD;
		pReq->fp = INVALID_HANDLE_VALUE;
		pReq->dwRecv = 0;
		pReq->dwSend = 0;
		strcpy(pReq->postfix, "");
		strcpy(pReq->szFileName, "");
		strcpy(pReq->StatuCodeReason, "");
		pReq->chp = pHttpProtocol;
		struct sockaddr_in SockAddr;
		socklen_t socklen = sizeof(struct sockaddr);
        pReq->Socket = accept(pHttpProtocol->ListenSocket, (struct sockaddr *)&SockAddr, &socklen);
        if (pReq->Socket == INVALID_SOCKET)
        {
            printf("Accept failed\n");
			exit(0);
        }
	    printf("IP:%s connecting to socket:%d\n", inet_ntoa(SockAddr.sin_addr), pReq->Socket);
		pthread_t client_tid;
        pthread_create(&client_tid, NULL, &ClientThread, pReq);
		pthread_join(client_tid, NULL);
    }

    return NULL;
}

void *CHttpProtocol::ClientThread(void *param)
{
	PREQUEST pReq = (PREQUEST)param;
	CHttpProtocol *chp = pReq->chp; 
    BIO *soc_bio = BIO_new_socket(pReq->Socket, BIO_NOCLOSE);
    SSL *ssl = SSL_new(pReq->chp->ctx);
    SSL_set_bio(ssl, soc_bio, soc_bio);
    int iResult = SSL_accept(ssl);
    if (iResult <= 0){
        printf("SSL_accept with wrong.");
		exit(0);
	}
    BIO *buf_bio = BIO_new(BIO_f_buffer());
    BIO *ssl_bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
    BIO_push(buf_bio, ssl_bio);
	char buf[DATA_BUFSIZE] = "";
	if (!chp->SSLRecvRequest(pReq, buf_bio, buf, sizeof(buf)))
	{
		printf("SSLRecvRequest with wrong.");
		chp->Disconnect(pReq);
		delete pReq;
		exit(0);
    }
	chp->Analyse(pReq, buf);
	if(!strcmp(HTTP_STATUS_NOTIMPLEMENTED, pReq->StatuCodeReason))
	{
		printf("Request method not implemented\n");
		exit(0);
	}
	if(!chp->SSLSendHeader(pReq, buf_bio))
	{
		printf("SSLSendheader failed\n");
		exit(0);
	}
	if(pReq->nMethod == METHOD_GET)
		chp->SSLSendFile(pReq, buf_bio);
	//补充其它方式,eg:HEAD
	chp->Disconnect(pReq);
	delete pReq;
    return NULL;
}

void CHttpProtocol::Disconnect(PREQUEST pReq)
{
	int	iResult;
	printf("Closing socket: %d\n", pReq->Socket);
	iResult = close(pReq->Socket);
	if (iResult == SOCKET_ERROR)
	{
		printf("close() error\n");
		exit(0);
	}
	return;
}

void CHttpProtocol::Analyse(PREQUEST pReq, char* pBuf)
{
	strcpy(pReq->StatuCodeReason, HTTP_STATUS_OK);
	char szSeps[] = " \n";
	char *cpToken;
	char *p;
	if (strstr((const char *)pBuf, "..") != NULL)
	{
		strcpy(pReq->StatuCodeReason, HTTP_STATUS_BADREQUEST);
		return;
	}
	cpToken = strtok_r(pBuf, szSeps, &p);
	if (0 == strcmp(cpToken, "GET"))
		pReq->nMethod = METHOD_GET;
	else if (0 == strcmp(cpToken, "HEAD"))
		pReq->nMethod = METHOD_HEAD;
	else
    {
		strcpy(pReq->StatuCodeReason, HTTP_STATUS_NOTIMPLEMENTED);
		return;
	}
	cpToken = strtok_r(NULL, szSeps, &p);
	if (cpToken == NULL)
	{
		strcpy(pReq->StatuCodeReason, HTTP_STATUS_BADREQUEST);
		return;
	}
	strcpy(pReq->szFileName, strRootDir);
	char name[256];
	if (strlen(cpToken) > 1)
		strcpy(name, cpToken);
	else
		strcpy(name, "/index.html");
	printf("%s\n", name);
	strcat(pReq->szFileName, name);
	return;
}

bool CHttpProtocol::SSLRecvRequest(PREQUEST pReq, BIO *io, char *pBuf, DWORD dwBufSize)
{
    char buf[dwBufSize];
    int r, length = 0;
    memset(buf, 0, dwBufSize);
    while (true)
    {
        r = BIO_gets(io, (char *)buf, DATA_BUFSIZE - 1);
        switch (SSL_get_error(ssl, r))
        {
        case SSL_ERROR_NONE:
            memcpy(&pBuf[length], buf, r);
            length += r;
            break;
        default:
            break;
        }
		if(!strcmp((const char *)buf,"\r\n") || !strcmp((const char *)buf,"\n"))
			break;
    }
    pBuf[length] = '\0';
	pReq->dwRecv += length;
    return true;
}

bool CHttpProtocol::SSLSendHeader(PREQUEST pReq, BIO *io)
{
	char Header[2048];
	while(false == FileExist(pReq))
	{
		strcpy(pReq->szFileName, strRootDir);
		strcat(pReq->szFileName, "/error.html");
	}
	DWORD length;
	char last_modified[100];
	char ContenType[100];
	GetCurTime(Time);
	length = GetFileSize(pReq);
	GetLastModified(pReq, (char*)last_modified);
	GetContenType(pReq, (char*)ContenType);

	sprintf(Header, "HTTP/1.0 %s\r\nDate: %sServer: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nLast-Modified: %s\r\n", HTTP_STATUS_OK,
			Time,
			"Pengclever Web Server",
			ContenType,
			length,
			last_modified);
	int iResult;
	iResult = BIO_puts(io, Header);
	if(iResult <= 0)
	{
		printf("BIO_puts with error\n");
		return false;
    }
	if(BIO_flush(io) <= 0)
	{
		printf("BIO_flush with error\n");
		return false;
    }
	pReq->dwSend += iResult;
	return true;
}

bool CHttpProtocol::SSLSendFile(PREQUEST pReq, BIO *io)
{
	static char buf[2048]= {""};
	int iResult;
	while(!feof(pReq->fp)){
        fread(buf, sizeof(buf), 1, pReq->fp);
		if(!pReq->chp->SSLSendBuffer(pReq, io, buf, sizeof(buf))){
			printf("Send buffer with wrong.\n");
			return false;
		}
    }
	if (!fclose(pReq->fp))
		pReq->fp = INVALID_HANDLE_VALUE;
	else
	{
		printf("Error occurs when closing file\n");
		return false;
	}
	return true;
}

bool CHttpProtocol::SSLSendBuffer(PREQUEST pReq, BIO *io, char* pBuf, DWORD dwBufSize)
{
	int iResult;
	iResult = BIO_puts(io, pBuf);
	if(BIO_flush(io) <= 0)
	{
		printf("BIO_flush with error\n");
		return false;
	}
	pReq->dwSend += iResult;
	return true;
}

bool CHttpProtocol::FileExist(PREQUEST pReq)
{
	pReq->fp = fopen(pReq->szFileName, "r");
	if(pReq->fp == INVALID_HANDLE_VALUE)
	{
		strcpy(pReq->StatuCodeReason, HTTP_STATUS_NOTFOUND);
		return false;
	}
	return true;
}

int CHttpProtocol::GetFileSize(PREQUEST pReq)  
{
    int filesize = -1;  
    FILE *fp;  
    fp = fopen(pReq->szFileName, "r");  
    if(fp == NULL)  
        return filesize;  
    fseek(fp, 0L, SEEK_END);  
    filesize = ftell(fp);  
    fclose(fp);  
    return filesize;  
} 

void CHttpProtocol::GetCurTime(LPSTR Time)
{
    time_t timep;
    time (&timep);
    sprintf(Time, "%s", asctime(gmtime(&timep)));
	return;
}

bool CHttpProtocol::GetLastModified(PREQUEST pReq, LPSTR Time)
{
    struct stat buf;
    int ret = 0;;
    int size = 0;
    memset(&buf, 0x00, sizeof(buf));
    ret = stat(pReq->szFileName, &buf);
    if(ret != 0)
    {
        printf("Get file stat with wrong.\n");
        return false;
    }
    sprintf(Time, "%s", ctime(&buf.st_mtime));
	return true;
}

bool CHttpProtocol::GetContenType(PREQUEST pReq, LPSTR type)
{
    char* cpToken;
    cpToken = strstr(pReq->szFileName, ".");
    strcpy(pReq->postfix, cpToken);

	if (0 == strcmp(pReq->postfix, ".doc"))
		strcpy(type, "application/msword");
	else if (0 == strcmp(pReq->postfix, ".bin"))
		strcpy(type, "application/octet-stream");
	else if (0 == strcmp(pReq->postfix, ".dll"))
		strcpy(type, "application/octet-stream");
	else if (0 == strcmp(pReq->postfix, ".exe"))
		strcpy(type, "application/octet-stream");
	else if (0 == strcmp(pReq->postfix, ".pdf"))
		strcpy(type, "application/pdf");
	else if (0 == strcmp(pReq->postfix, ".class"))
		strcpy(type, "application/x-java-class");
	else if (0 == strcmp(pReq->postfix, ".zip"))
		strcpy(type, "application/zip");
	else if (0 == strcmp(pReq->postfix, ".aif"))
		strcpy(type, "audio/aiff");
	else if (0 == strcmp(pReq->postfix, ".au"))
		strcpy(type, "audio/basic");
	else if (0 == strcmp(pReq->postfix, ".snd"))
		strcpy(type, "audio/basic");
	else if (0 == strcmp(pReq->postfix, ".mid"))
		strcpy(type, "audio/midi");
	else if (0 == strcmp(pReq->postfix, ".rmi"))
		strcpy(type, "audio/midi");
	else if (0 == strcmp(pReq->postfix, ".mp3"))
		strcpy(type, "audio/mpeg");
	else if (0 == strcmp(pReq->postfix, ".vox"))
		strcpy(type, "audio/voxware");
	else if (0 == strcmp(pReq->postfix, ".wav"))
		strcpy(type, "audio/wav");
	else if (0 == strcmp(pReq->postfix, ".ra"))
		strcpy(type, "audio/x-pn-realaudio");
	else if (0 == strcmp(pReq->postfix, ".ram"))
		strcpy(type, "audio/x-pn-realaudio");
	else if (0 == strcmp(pReq->postfix, ".bmp"))
		strcpy(type, "image/bmp");
	else if (0 == strcmp(pReq->postfix, ".gif"))
		strcpy(type, "image/gif");
	else if (0 == strcmp(pReq->postfix, ".jpeg"))
		strcpy(type, "image/jpeg");
	else if (0 == strcmp(pReq->postfix, ".jpg"))
		strcpy(type, "image/jpeg");
	else if (0 == strcmp(pReq->postfix, ".tif"))
		strcpy(type, "image/tiff");
	else if (0 == strcmp(pReq->postfix, ".tiff"))
		strcpy(type, "image/tiff");
	else if (0 == strcmp(pReq->postfix, ".xbm"))
		strcpy(type, "image/xbm");
	else if (0 == strcmp(pReq->postfix, ".wrl"))
		strcpy(type, "model/vrml");
	else if (0 == strcmp(pReq->postfix, ".htm"))
		strcpy(type, "text/html");
	else if (0 == strcmp(pReq->postfix, ".html"))
		strcpy(type, "text/html");
	else if (0 == strcmp(pReq->postfix, ".c"))
		strcpy(type, "text/plain");
	else if (0 == strcmp(pReq->postfix, ".cpp"))
		strcpy(type, "text/plain");
	else if (0 == strcmp(pReq->postfix, ".def"))
		strcpy(type, "text/plain");
	else if (0 == strcmp(pReq->postfix, ".h"))
		strcpy(type, "text/plain");
	else if (0 == strcmp(pReq->postfix, ".txt"))
		strcpy(type, "text/plain");
	else if (0 == strcmp(pReq->postfix, ".rtx"))
		strcpy(type, "text/richtext");
	else if (0 == strcmp(pReq->postfix, ".rtf"))
		strcpy(type, "text/richtext");
	else if (0 == strcmp(pReq->postfix, ".java"))
		strcpy(type, "text/x-java-source");
	else if (0 == strcmp(pReq->postfix, ".css"))
		strcpy(type, "text/css");
	else if (0 == strcmp(pReq->postfix, ".mpeg"))
		strcpy(type, "video/mpeg");
	else if (0 == strcmp(pReq->postfix, ".mpg"))
		strcpy(type, "video/mpeg");
	else if (0 == strcmp(pReq->postfix, ".mpe"))
		strcpy(type, "video/mpeg");
	else if (0 == strcmp(pReq->postfix, ".avi"))
		strcpy(type, "video/msvideo");
	else if (0 == strcmp(pReq->postfix, ".mov"))
		strcpy(type, "video/quicktime");
	else if (0 == strcmp(pReq->postfix, ".qt"))
		strcpy(type, "video/quicktime");
	else if (0 == strcmp(pReq->postfix, ".shtml"))
		strcpy(type, "wwwserver/html-ssi");
	else if (0 == strcmp(pReq->postfix, ".asa"))
		strcpy(type, "wwwserver/isapi");
	else if (0 == strcmp(pReq->postfix, ".asp"))
		strcpy(type, "wwwserver/isapi");
	else if (0 == strcmp(pReq->postfix, ".cfm"))
		strcpy(type, "wwwserver/isapi");
	else if (0 == strcmp(pReq->postfix, ".dbm"))
		strcpy(type, "wwwserver/isapi");
	else if (0 == strcmp(pReq->postfix, ".isa"))
		strcpy(type, "wwwserver/isapi");
	else if (0 == strcmp(pReq->postfix, ".plx"))
		strcpy(type, "wwwserver/isapi");
	else if (0 == strcmp(pReq->postfix, ".url"))
		strcpy(type, "wwwserver/isapi");
	else if (0 == strcmp(pReq->postfix, ".cgi"))
		strcpy(type, "wwwserver/isapi");
	else if (0 == strcmp(pReq->postfix, ".php"))
		strcpy(type, "wwwserver/isapi");
	else if (0 == strcmp(pReq->postfix, ".wcgi"))
		strcpy(type, "wwwserver/isapi");

	if(type)
		return true;
	else
		return false;
}

int main()
{
    CHttpProtocol chp;
    chp.StartHttpSrv();
    while (true){}
    return 0;
}