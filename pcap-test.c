#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

int byte2int(u_char* p){
	int total_size_arr[1] = {};
	total_size_arr[0] = *p++;
	total_size_arr[1] = *p++;
	int total_size = 0;
	total_size += total_size_arr[0]/10*16*16*16; //Total Size 계산
	total_size += total_size_arr[0]%10*16*16;
	total_size += total_size_arr[1]/10*16;
	total_size += total_size_arr[1]%10;
	return total_size;
}


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) { //인자가 2개보다 작아서 오류 발생
		usage();
		return false;
	}
	param->dev_ = argv[1]; //구조체 param의 dev_에 인자에 1번째가 들어감
	return true;
}

int main(int argc, char* argv[]) {
	char name[] = "안두혁";
	char mobile[] = "8262";
	printf("[bob11]pcap-test[%s%s]\n\n", name, mobile);

	if (!parse(&param, argc, argv)) //인자 정보가 제대로 되었는지 확인하는 조건문
		return -1;
	// printf("%s",param.dev_); // 출력 : dum0
	char errbuf[PCAP_ERRBUF_SIZE]; //뭔지 모르겠지만 의미상 err내용을 담는 변수
	// 첫번째 인자는 PCD, 두번째 인자는 받아들이는 최대 크기를 의미한다, 세 번째 모드(1은 모든패킷 0은 나를 향하는 패킷만), 네 번째 읽기 시간 초과, 다섯 번째 함수에 오류발생시 오류 내용을 저장하기 위한 공간으로 활용.
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	// printf("출력 : %d\n",pcap_fileno(pcap));
	if (pcap == NULL) { //pcap_open_live에 오류가 발생했을때 오류를 출력하는 조건문
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		// printf("pcap_pkthdr의 크기 : %ld",sizeof(header));
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		// printf("header : %d\n",header);
		u_char* p=(u_char*)packet;
		u_char* sub_p=(u_char*)packet;
		printf("=========================================\n");
		printf("Ethernet Destination : \t");
		for (int i = 0; i<6;i++) printf("%x ",*sub_p++); //mac des 출력
		printf("\n");

		printf("Ethernet Source : \t");
		for (int i = 0; i<6;i++) printf("%x ",*sub_p++); //mac src 출력
		printf("\n");

		// printf("Ethernet Type : \t");
		int ip_type = 0;
		ip_type += (int)(*sub_p++)*10+(int)(*sub_p++); //ip_type를 계산
		if (!(ip_type == 80)) continue;
		// printf("%d\n",ip_type);

		int ip_1byte = 0;
		ip_1byte += (int)(*sub_p++);
		// printf("Ip Version : \t\t%d\n",ip_1byte/16);
		int ip_head_size = ip_1byte%16*4;
		// printf("Ip Header Size : \t%d\n",ip_head_size);
		
		*sub_p++; //바이트 날리기
		
		int total_size_arr[1] = {};
		total_size_arr[0] = *sub_p++;
		total_size_arr[1] = *sub_p++;
		int total_size = 0;
		total_size += total_size_arr[0]/10*16*16*16; //Total Size 계산
		total_size += total_size_arr[0]%10*16*16;
		total_size += total_size_arr[1]/10*16;
		total_size += total_size_arr[1]%10;
		// total_size = byte2int(sub_p);
		// printf("Total Size : \t\t%d\n",total_size);

		sub_p = (sub_p+5); //바이트 날리기
		
		int protocol = *sub_p++;
		if(protocol != 6) continue; 
		// printf("Protocol : \t\t%x\n",protocol);

		sub_p = (sub_p+2); //바이트 날리기

		printf("Source Ip : \t\t");
		for(int i=0; i<3;i++) printf("%d.",*sub_p++); 
		printf("%d\n",*sub_p++);
		
		printf("Destination Ip : \t");
		for(int i=0; i<3;i++) printf("%d.",*sub_p++); 
		printf("%d\n",*sub_p++);
		
		if(ip_head_size>20) sub_p = sub_p+(ip_head_size-20)/4;

		printf("Source Port : \t\t");
		int source_port_arr[1] = {};
		source_port_arr[0] = *sub_p++;
		source_port_arr[1] = *sub_p++;
		int source_port = 0;
		source_port += source_port_arr[0]/16*16*16*16; //source_port 계산
		source_port += source_port_arr[0]%16*16*16;
		source_port += source_port_arr[1]/16*16;
		source_port += source_port_arr[1]%16;
		printf("%d\n",source_port);

		printf("Destination Port : \t");
		int des_port_arr[1] = {};
		des_port_arr[0] = *sub_p++;
		des_port_arr[1] = *sub_p++;
		int des_port = 0;
		des_port += des_port_arr[0]/16*16*16*16; //des_port 계산
		des_port += des_port_arr[0]%16*16*16;
		des_port += des_port_arr[1]/16*16;
		des_port += des_port_arr[1]%16;
		printf("%d\n",des_port);

		sub_p = (sub_p+8); //바이트 날리기

		int tcp_1byte = 0;
		tcp_1byte += (int)(*sub_p++);
		int data_offset = tcp_1byte/16*4;
		// printf("Data Offset : \t\t%d\n",data_offset);

		sub_p = (sub_p+5); //바이트 날리기

		if(data_offset>20) sub_p = (sub_p+(data_offset-20)/4);

		printf("Payload : \t\t");
		if(header->caplen-(14+ip_head_size+data_offset) >= 10)
			for(int i=0;i<10;i++)
				printf("%x ",*sub_p++);
		else if(header->caplen-(14+ip_head_size+data_offset) == 0)
			printf("No data");
		else
			for(int i=0;i<header->caplen-(14+ip_head_size+data_offset);i++)
				printf("%x ",*sub_p++);
		printf("\n");

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {//pcap_next_ex를 읽지 못했을때 오류
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		// int res = pcap_next_ex(pcap,&header,header->caplen);
		// printf("%u bytes captured\n", header->caplen);

		
	}

	pcap_close(pcap);
}
