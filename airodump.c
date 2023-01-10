#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

void usage() {
	printf("syntax: airodump <interface>\n");
	printf("sample: airodump wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

typedef struct {
	u_int8_t bssid[6];
	u_int32_t b_count;
	u_int16_t s_len;
	u_char* essid;
	int16_t pwr;
} Beacons;

int count = 0;
int point = 0;
int r_idx[31] = {0};

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_info(Beacons* b, int idx)
{
	// BSSID
	for (int i=0; i<6; i++) {
		printf("%02x", b[idx].bssid[i]);
		if (i != 5)
			printf(":");
	}
	printf("   ");
	
	// PWR
	printf("%4d", b[idx].pwr-256);

	// Beacons
	printf("%9d", b[idx].b_count+1);
	printf("   ");

	// ESSID
	for (int i=0; i<b[idx].s_len; i++)
		printf("%c", b[idx].essid[i]);
	printf("\n");
}

void print_beacon(Beacons* b) {
	printf("%-20s%4s%9s %7s\n", "BSSID", "PWR", "BEACONS", "SSID");
	int c = 30;
	if (count < 30)
		c = count;	
	for (int i=0; i<c; i++) {
		int cur = r_idx[i] - 1;
		print_info(b, cur);
	}
}

void check_ridx(int idx)
{
	int flag = 0;
	for (int i=0; i<30; i++) {
		if (r_idx[i] == idx) {
			flag = 1;
			break;
		}
		else if (r_idx[i] == 0) {
			r_idx[i] = idx;
			break;
		}
	}
	if (!flag) {
		r_idx[point] = idx;
		if (point == 29)
			point = 0;
		else
			point++;
	}
}

u_int32_t parse_info(const u_char* p, Beacons* b)
{
	int flag = 0;
	int current = 0;
	if((int)*(p+24) == 128) { //0x80
		// BSSID
		for (int i=0; i<count; i++) {
			for (int j=0; j<6; j++) {
				if (b[i].bssid[j] == *(p+40+j)) {
					flag = 1;
				} else {
					flag = 0;
					break;
				}
			}
			if (flag) {
				b[i].b_count++;
				current = i;
				break;
			}
		}
		if (!flag) {
			for (int i=0; i<6; i++)
				b[count].bssid[i] = *(p+40+i);
			current = count;
			count++;
		}

		// ESSID
		b[current].s_len = *(p+61);
		b[current].essid = (char*)malloc(sizeof(char) * b[current].s_len);
		for (int i=0; i<b[current].s_len; i++)
			b[current].essid[i] = *(p+62+i);

		// PWR
		b[current].pwr = *(p+22);

		check_ridx(current+1);
		sleep(0.1);
		system("clear");
		print_beacon(b);
		return current;
	}
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	
	Beacons beacon[100000];
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		int idx = parse_info(packet, beacon);
	}
	for (int i=0; i<count; i++) {
		free(beacon[i].essid);
	}
	pcap_close(pcap);
}





