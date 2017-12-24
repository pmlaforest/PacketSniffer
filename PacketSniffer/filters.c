#include <stdio.h>

#define HAVE_REMOTE
#define WIN32
#include "pcap.h"  

extern pcap_if_t *alldevs;

int activate_packet_filter(pcap_t *adhandle, bpf_u_int32 netmask, char *filter_mask)
{
	struct bpf_program fcode;

	if (filter_mask == NULL) {
		fprintf(stderr, "\nUnable to get the filter mask. Check the syntax.\n");
		return -1;
	}

	//compile the filter
	if (pcap_compile(adhandle, &fcode, filter_mask, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	return 0;
}



