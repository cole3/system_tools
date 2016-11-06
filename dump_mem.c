#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PAGE_SIZE  4096
static unsigned char page[PAGE_SIZE];
static char line[256];
static char mapsFilename[1024];
static char memFilename[1024];
FILE* pMapsFile = NULL;
FILE* pMemFile = NULL;


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

void write_memory_region(FILE* pMemFile, unsigned long start_address,
                         unsigned char data)
{
    int read_size = 0;

    fseeko(pMemFile, start_address, SEEK_SET);
    if (!fwrite(&data, 1, 1, pMemFile)) {
        printf("Invalid write\n");
    }
}

void dump_all_maps(FILE *pMaps, FILE* pMemFile, int serverSocket)
{
    unsigned long start_address;
    unsigned long end_address;

    while (fgets(line, 256, pMaps) != NULL) {
        sscanf(line, "%08lx-%08lx\n", &start_address, &end_address);
        dump_memory_region(pMemFile, start_address,
                           end_address - start_address, serverSocket);
    }
}

void read_mem(FILE* pMemFile, const char *addr_str, const char *size_str)
{
    unsigned long start_address;
    long length;
    int count = sscanf(addr_str, "%x", &start_address);
    if (count == 0) {
        printf("Invalid adddress\n");
        return;
    }
    count = sscanf(size_str, "%x", &length);
    if (count == 0) {
        printf("Invalid length\n");
        return;
    }
    dump_memory_region(pMemFile, start_address, length, -1);
}

void write_mem(FILE* pMemFile, const char *addr_str, const char *data_str)
{
    unsigned long start_address;
    unsigned char data;
    int count = sscanf(addr_str, "%x", &start_address);
    if (count == 0) {
        printf("Invalid adddress\n");
        return;
    }
    count = sscanf(data_str, "%x", &data);
    if (count == 0) {
        printf("Invalid data\n");
        return;
    }
    write_memory_region(pMemFile, start_address, data);
}

void dump_by_socket(FILE *pMaps, FILE* pMemFile,
                    const char *ip_str, const char *port_str)
{
    int serverSocket = -1;
    unsigned int port;
    struct sockaddr_in serverSocketAddress;
    int count = sscanf(port_str, "%d", &port);
    if (count == 0) {
        printf("Invalid port specified\n");
        return;
    }
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        printf("Could not create socket\n");
        return;
    }
    serverSocketAddress.sin_addr.s_addr = inet_addr(ip_str);
    serverSocketAddress.sin_family = AF_INET;
    serverSocketAddress.sin_port = htons(port);
    if (connect(serverSocket, (struct sockaddr *) &serverSocketAddress,
                sizeof(serverSocketAddress)) < 0) {
        printf("Could not connect to server\n");
        return;
    }

    dump_all_maps(pMaps, pMemFile, serverSocket);

    if (serverSocket != -1) {
        close(serverSocket);
    }

}

void show_usage(const char *cmd)
{
    printf("%s d(dump) <pid>\n", cmd);
    printf("%s r(read) <pid> <address> <size>\n", cmd);
    printf("%s w(write) <pid> <address> <data>\n", cmd);
    printf("%s s(socket) <pid> <ip-address> <port>\n", cmd);
}

int main(int argc, char **argv)
{
    int pid;
    long ptraceResult;

    if (argc < 3) {
        show_usage(argv[0]);
        return -1;
    }

    pid = atoi(argv[2]);
    ptraceResult = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (ptraceResult < 0) {
        printf("Unable to attach to the pid specified\n");
        return;
    }
    wait(NULL);

    sprintf(mapsFilename, "/proc/%d/maps", pid);
    pMapsFile = fopen(mapsFilename, "r");
    sprintf(memFilename, "/proc/%d/mem", pid);
    pMemFile = fopen(memFilename, "r");

    switch (*argv[1]) {
    case 'd':
        dump_all_maps(pMapsFile, pMemFile, -1);
        break;
    case 'r':
        if (argc < 5) {
            show_usage(argv[0]);
            break;
        }
        read_mem(pMemFile, argv[3], argv[4]);
        break;
    case 'w':
        if (argc < 5) {
            show_usage(argv[0]);
            break;
        }
        write_mem(pMapsFile, argv[3], argv[4]);
        break;
    case 's':
        if (argc < 5) {
            show_usage(argv[0]);
            break;
        }
        dump_by_socket(pMapsFile, pMemFile, argv[3], argv[4]);
        break;
    default:
        show_usage(argv[0]);
        break;
    }

    fclose(pMapsFile);
    fclose(pMemFile);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}

