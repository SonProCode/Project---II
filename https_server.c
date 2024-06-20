#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void signalHanlder(int signo)
{
    pid_t pid = wait(NULL);
}

void *client_proc(void *);

int my_fd,client_fd;
struct sockaddr_in server, client;
int client_size;
int error = 0, wrote = 0;
char buffer[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>https_server</h1>";
SSL_CTX *my_ssl_ctx;
SSL *my_ssl;

int main()
{

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    my_ssl_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(my_ssl_ctx,"server.pem",SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(my_ssl_ctx,"server.pem",SSL_FILETYPE_PEM);
    if( !SSL_CTX_check_private_key(my_ssl_ctx) )
    {
        fprintf(stderr,"Private key does not match certificate\n");
        exit(-1);
    }

    my_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    server.sin_family = AF_INET;
    server.sin_port = htons(5353);
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(my_fd, (struct sockaddr *)&server, sizeof(server));
    listen(my_fd, 5);

    while (1)
    {

        int m_client = accept(my_fd, NULL, NULL);
        printf("New Client: %d\n", m_client);

        pthread_t tid;
        pthread_create(&tid, NULL, client_proc, &m_client);
        pthread_detach(tid);
    }
    SSL_CTX_free(my_ssl_ctx);


}

void *client_proc(void *arg)
{
    int m_client = *(int *)arg;
    if((my_ssl = SSL_new(my_ssl_ctx)) == NULL)
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    SSL_set_fd(my_ssl,m_client);
    if(SSL_accept(my_ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    printf("[%s,%s]\n",SSL_get_version(my_ssl),SSL_get_cipher(my_ssl));
    char buf[2048];
    int ret = SSL_read(my_ssl, buf, sizeof(buf));
    buf[ret] = 0;

    printf("Received from %d: %s\n", m_client, buf);
    if (strncmp(buf, "GET / ", 6) == 0)
    {
        // Tra ve trang web
        strcpy(buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Hello World</h1>");
        SSL_write(my_ssl, buf, strlen(buf));
        //send(m_client, buffer, sizeof(buffer), 0);
    }
    else if (strncmp(buf, "GET /image ", 11) == 0)
    {
        // Tra ve file anh
        strcpy(buf, "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n");
        //send(m_client, buf, strlen(buf), 0);
        SSL_write(my_ssl, buf, strlen(buf));
        // Doc file anh va tra ve client
        FILE *f = fopen("./files/image.jpg", "rb");
        while (1) {
            int len = fread(buf, 1, sizeof(buf), f);
            if (len <= 0)
                break;
            //send(m_client, buf, len, 0);
            SSL_write(my_ssl, buf, len);

        }
        fclose(f);
    }
    else if (strncmp(buf, "GET /video1 ", 12) == 0)
    {
        FILE *f = fopen("./files/test.mp4", "rb");

        fseek(f, 0, SEEK_END);
        long filesize = ftell(f);
        fseek(f, 0, SEEK_SET);

        // Tra ve file video
        sprintf(buf, "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nContent-Length: %ld\r\n\r\n", filesize);
        SSL_write(my_ssl, buf, strlen(buf));

        // Doc file video va tra ve client
        while (1)
        {
            int len = fread(buf, 1, sizeof(buf), f);
            if (len <= 0)
                break;
            SSL_write(my_ssl, buf, len);
        }
        fclose(f);
    }
    else if (strncmp(buf, "GET /video2 ", 12) == 0)
    {
        FILE *f = fopen("./files/test2.mp4", "rb");

        fseek(f, 0, SEEK_END);
        long filesize = ftell(f);
        fseek(f, 0, SEEK_SET);

        // Tra ve file video
        sprintf(buf, "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nContent-Length: %ld\r\n\r\n", filesize);
        SSL_write(my_ssl, buf, strlen(buf));

        // Doc file video va tra ve client
        while (1) {
            int len = fread(buf, 1, sizeof(buf), f);
            if (len <= 0)
                break;
            SSL_write(my_ssl, buf, len);
        }
        fclose(f);
    }
    else if (strncmp(buf, "GET /index.html ", 16) == 0)
    {
        FILE *f = fopen("./index.html", "rb");


        // Tra ve file video
        sprintf(buf, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n");
        SSL_write(my_ssl, buf, strlen(buf));

        // Doc file video va tra ve client
        while (1)
        {
            int len = fread(buf, 1, sizeof(buf), f);
            if (len <= 0)
                break;
            SSL_write(my_ssl, buf, len);
        }
        fclose(f);
    }
    else if (strncmp(buf, "GET /audio ", 11) == 0)
    {
        FILE *f = fopen("./files/audio.mp3", "rb");

        fseek(f, 0, SEEK_END);
        long filesize = ftell(f);
        fseek(f, 0, SEEK_SET);

        // Tra ve file audio
        sprintf(buf, "HTTP/1.1 200 OK\r\nContent-Type: audio/mp3\r\nContent-Length: %ld\r\n\r\n", filesize);
        //SSL_write(my_ssl, buf, strlen(buf));
        SSL_write(my_ssl, buf, strlen(buf));
        // Doc file audio va tra ve client
        //char fbuf[2048];
        while (1)
        {
            int len = fread(buf, 1, sizeof(buf), f);
            if (len <= 0)
                break;
            SSL_write(my_ssl, buf, len);
        }
        fclose(f);
    }
    else if (strncmp(buf, "POST /login", 11) == 0)
    {
        /// lay ra tai khoan + mat khau
        char tmp[256];
        int i = 12;
        int tru = 12;
        for (; i < strlen(buf); i++)
        {
            if (buf[i] == '&')
            {
                tmp[i - tru] = ' ';
            }
            else if (buf[i] == ' ')
            {
                tmp[i - tru] = '\0';
                break;
            }
            else
                tmp[i - tru] = buf[i];
        }
        char username[32] = {0}, password[32] = {0};
        sscanf(tmp, "username=%s pass=%s", username, password);
        //printf("%s %s\n", username, password);
        // kiem tra tai khoan da dang ki chua
        sprintf(tmp, "%s %s\n", username, password);
        FILE *f = fopen("account.txt", "r");
        int found = 0;
        char line[65];
        while (fgets(line, sizeof(line), f) != NULL)
        {
            if (strcmp(tmp, line) == 0)
            {
                found = 1;
                break;
            }
        }
        if (found == 1)
        {
            strcpy(buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Dang nhap thanh cong!</h1>");
            SSL_write(my_ssl, buf, strlen(buf));
        }
        else
        {
            strcpy(buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Tai khoan hoac mat khau sai!</h1>");
            SSL_write(my_ssl, buf, strlen(buf));
        }

    }
    else if (strncmp(buf, "POST /regis", 11) == 0)
    {
        /// lay ra tai khoan + mat khau
        char tmp[256];
        int i = 12;
        int tru = 12;
        for (; i < strlen(buf); i++)
        {
            if (buf[i] == '&')
            {
                tmp[i - tru] = ' ';
            }
            else if (buf[i] == ' ')
            {
                tmp[i - tru] = '\0';
                break;
            }
            else
                tmp[i - tru] = buf[i];
        }
        char username[32] = {0}, password[32] = {0};
        sscanf(tmp, "username=%s pass=%s", username, password);
        //printf("%s %s\n", username, password);
        // kiem tra tai khoan da dang ki chua
        sprintf(tmp, "%s %s\n", username, password);
        FILE *fp = fopen("account.txt", "a");
        if (fp == NULL)
        {
            printf("Lỗi mở file.\n");
        }
        else
        {
            fprintf(fp, "%s", tmp);
            strcpy(buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Dang ky thanh cong</h1>");
            SSL_write(my_ssl, buf, strlen(buf));
            fclose(fp);
        }
    }
    else {
        strcpy(buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Khong tim thay tai nguyen</h1>");
        SSL_write(my_ssl, buf, strlen(buf));
    }

    SSL_shutdown(my_ssl);
    SSL_free(my_ssl);
    close(m_client);
    pthread_exit(NULL);
}

