#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PAGE_SIZE  4096
static unsigned char page[PAGE_SIZE];

void dump_memory_region(FILE* pMemFile, unsigned long start_address,
        long length, int serverSocket)
{
    int read_size = 0;

    fseeko(pMemFile, start_address, SEEK_SET);

    while (length > 0) {
        read_size = (length > PAGE_SIZE) ? PAGE_SIZE : length;
        fread(&page, 1, read_size, pMemFile);
        if (serverSocket == -1) {
            fwrite(&page, 1, read_size, stdout);
        } else {
            send(serverSocket, &page, read_size, 0);
        }
        length -= read_size;
    }
}


static char line[256];
static char mapsFilename[1024];
static char memFilename[1024];
FILE* pMapsFile = NULL;
FILE* pMemFile = NULL;

int main(int argc, char **argv)
{
    int serverSocket = -1;

    if (argc == 2 || argc == 4) {
        int pid = atoi(argv[1]);
        long ptraceResult = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        if (ptraceResult < 0) {
            printf("Unable to attach to the pid specified\n");
            return;
        }
        wait(NULL);

        sprintf(mapsFilename, "/proc/%s/maps", argv[1]);
        pMapsFile = fopen(mapsFilename, "r");
        sprintf(memFilename, "/proc/%s/mem", argv[1]);
        pMemFile = fopen(memFilename, "r");
        if (argc == 5) {
            unsigned int port;
            struct sockaddr_in serverSocketAddress;
            int count = sscanf(argv[3], "%d", &port);
            if (count == 0) {
                printf("Invalid port specified\n");
                return;
            }
            serverSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (serverSocket == -1) {
                printf("Could not create socket\n");
                return;
            }
            serverSocketAddress.sin_addr.s_addr = inet_addr(argv[2]);
            serverSocketAddress.sin_family = AF_INET;
            serverSocketAddress.sin_port = htons(port);
            if (connect(serverSocket, (struct sockaddr *) &serverSocketAddress,
                        sizeof(serverSocketAddress)) < 0) {
                printf("Could not connect to server\n");
                return;
            }
        }

        if (argc == 2) {
            while (fgets(line, 256, pMapsFile) != NULL) {
                unsigned long start_address;
                unsigned long end_address;
                sscanf(line, "%08lx-%08lx\n", &start_address, &end_address);
                dump_memory_region(pMemFile, start_address,
                        end_address - start_address, serverSocket);
            }
        } else {
            unsigned long start_address;
            long length;
            int count = sscanf(argv[2], "%x", &start_address);
            if (count == 0) {
                printf("Invalid adddress\n");
                return;
            }
            count = sscanf(argv[3], "%x", &length);
            if (count == 0) {
                printf("Invalid length\n");
                return;
            }
            dump_memory_region(pMemFile, start_address,
                    length, serverSocket);
        }

        fclose(pMapsFile);
        fclose(pMemFile);
        if (serverSocket != -1) {
            close(serverSocket);
        }

        ptrace(PTRACE_CONT, pid, NULL, NULL);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    } else {
        printf("%s <pid> <address> <size>\n", argv[0]);
        printf("%s <pid> <ip-address> <port> <socket>\n", argv[0]);
        exit(0);
    }
}

