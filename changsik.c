#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windivert.h>

#define MAXBUF  0xFFFF
char *strstr_n(const char *str1, const char *str2);

int main(void)
{
	HANDLE handle;
	PVOID payload;
	UINT payload_len;
	UINT packet_len;
	unsigned char packet[MAXBUF];
	unsigned char * s1 = "Accept-Encoding: gzip,";
	unsigned char * s2 = "Michael";
	unsigned char * t1 = "Accept-Encoding:      ";
	unsigned char * t2 = "Gilbert";
	unsigned char * tmp1;
	unsigned char * tmp2;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	WINDIVERT_ADDRESS addr;
	handle = WinDivertOpen("tcp and tcp.PayloadLength > 0",
		WINDIVERT_LAYER_NETWORK, 0, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	while (TRUE)
	{
		tmp1 = NULL;
		tmp2 = NULL;
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			printf("Recv error\n");
			continue;
		}
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, &payload, &payload_len);
		printf("packet_len :%d\n", packet_len);
		printf("payload_len :%d\n", payload_len);
		printf("1\n");
		if (addr.Direction == 0)
		{
			tmp1 = payload;
			tmp2 = strstr_n(tmp1, s1);
			printf("2\n");
			printf("%s\n", payload);
			if (tmp2 != NULL)
			{
				memcpy(tmp2, t1, strlen(t1));
				payload = tmp1;
				printf("out bound 변경\n");
				printf("%s\n", payload);
			}
		}
		if (addr.Direction == 1)
		{
			tmp1 = payload;
			tmp2 = strstr_n(tmp1, s2);
			printf("3\n");
			printf("%s\n", payload);
			if (tmp2 != NULL)
			{
				memcpy(tmp2, t2, strlen(t2));
				payload = tmp1;
				printf("in bound 변경\n");
				printf("%s\n", payload);
			}
		}
		WinDivertHelperCalcChecksums(packet, packet_len, NULL);
		if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
		{
			printf("Send error\n");
			continue;
		}
	}
	WinDivertClose(handle);
	return 0;
}

char *strstr_n(const char *str1, const char *str2)
{
	char *cp = (char *)str1;
	char *s1, *s2;

	if (!*str2) return (char *)str1;

	while (*cp || *(cp+1) || *(cp + 2) || *(cp + 3) || *(cp + 4) || *(cp + 5) || *(cp + 6) || *(cp + 7) || *(cp + 8) || *(cp + 9) || *(cp + 10))
	{
		s1 = cp;
		s2 = (char *)str2;

		while (*s1 && *s2 && !(*s1 - *s2)) s1++, s2++;
		if (!*s2) return cp;
		cp++;
	}
	return NULL;
}