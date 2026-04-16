/*
 * ntlmv1scan - detect NTLMv1 authentication messages in Linux network traffic
 * Author: Gratien Dhaese and contributors
 * License: GPL v3
 *
 * Captures raw Ethernet frames from a live interface using AF_PACKET sockets,
 * filters to SMB TCP traffic (ports 139/445), and flags NTLMSSP AUTHENTICATE
 * (Type 3) messages whose LM and NT response lengths are both 24 bytes, which
 * is the hallmark of NTLMv1.
 *
 * Requires root privileges (or CAP_NET_RAW) to open a raw socket.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* NTLMSSP AUTHENTICATE (Type 3) message structure offsets. */
static const unsigned char ntlmssp_signature[] = "NTLMSSP\0";
static const size_t ntlmssp_signature_len    = 8U;   /* length of "NTLMSSP\0" */
static const size_t ntlm_auth_msgtype_offset = 8U;   /* MessageType field offset */
/* In NTLMSSP AUTHENTICATE (Type 3), LM response len is at byte offset 12
 * and NT response len is at byte offset 20.  Both are 2-byte little-endian
 * fields (SecurityBuffer.Length). */
static const size_t ntlm_auth_lm_len_offset  = 12U;
static const size_t ntlm_auth_nt_len_offset  = 20U;

static const size_t max_frame_size = 65536U;

struct scan_stats {
	unsigned long packets;
	unsigned long ntlm_auth_messages;
	unsigned long ntlmv1_hits;
};

static uint16_t read_le16(const unsigned char *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t read_le32(const unsigned char *p)
{
	return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

static void format_timestamp(const struct timeval *ts, char *buf, size_t buf_len)
{
	struct tm tm_value;

	if (localtime_r(&ts->tv_sec, &tm_value) == NULL) {
		(void)snprintf(buf, buf_len, "time-unavailable");
		return;
	}
	if (strftime(buf, buf_len, "%Y-%m-%d %H:%M:%S", &tm_value) == 0) {
		(void)snprintf(buf, buf_len, "time-unavailable");
	}
}

static void inspect_ntlm_payload(const unsigned char *payload, size_t payload_len,
				  const struct timeval *ts, struct scan_stats *stats)
{
	size_t i;
	char when[64];

	/* Walk the payload looking for NTLMSSP AUTHENTICATE messages.
	 * The loop bound ensures we can safely read the NT response length
	 * field (2 bytes at ntlm_auth_nt_len_offset), which is the furthest
	 * field we access for any candidate match. */
	for (i = 0; i + ntlm_auth_nt_len_offset + sizeof(uint16_t) <= payload_len; i++) {
		uint16_t lm_response_len;
		uint16_t nt_response_len;

		if (memcmp(payload + i, ntlmssp_signature, ntlmssp_signature_len) != 0)
			continue;
		if (read_le32(payload + i + ntlm_auth_msgtype_offset) != 3U)
			continue;

		stats->ntlm_auth_messages++;

		lm_response_len = read_le16(payload + i + ntlm_auth_lm_len_offset);
		nt_response_len = read_le16(payload + i + ntlm_auth_nt_len_offset);

		/* NTLMv1 produces exactly 24-byte LM and NT responses. */
		if (lm_response_len == 24U && nt_response_len == 24U) {
			stats->ntlmv1_hits++;
			format_timestamp(ts, when, sizeof(when));
			(void)printf(
				"[%s.%06ld] Potential NTLMv1 authentication detected "
				"(packet_index=%lu, lm_len=%u, nt_len=%u)\n",
				when, (long)ts->tv_usec,
				stats->packets,
				(unsigned int)lm_response_len,
				(unsigned int)nt_response_len);
		}

		/* Skip ahead past this authenticate header to avoid rescanning
		 * the same bytes.  The for-loop's i++ adds one more. */
		i += ntlm_auth_nt_len_offset;
	}
}

static int is_smb_port(uint16_t port)
{
	return (port == 139U || port == 445U);
}

static void process_frame(const unsigned char *frame, ssize_t frame_len,
			   const struct timeval *ts, struct scan_stats *stats)
{
	const struct ethhdr  *eth;
	const struct iphdr   *ip;
	const struct tcphdr  *tcp;
	const unsigned char  *payload;
	size_t                ip_hdr_len;
	size_t                tcp_hdr_len;
	size_t                payload_len;

	if (frame_len < (ssize_t)sizeof(struct ethhdr))
		return;

	eth = (const struct ethhdr *)frame;
	if (ntohs(eth->h_proto) != ETH_P_IP)
		return;

	if (frame_len < (ssize_t)(sizeof(struct ethhdr) + sizeof(struct iphdr)))
		return;

	ip = (const struct iphdr *)(frame + sizeof(struct ethhdr));
	if (ip->protocol != IPPROTO_TCP)
		return;

	ip_hdr_len = (size_t)ip->ihl * 4U;
	if (ip_hdr_len < sizeof(struct iphdr))
		return;
	if (frame_len < (ssize_t)(sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct tcphdr)))
		return;

	tcp = (const struct tcphdr *)(frame + sizeof(struct ethhdr) + ip_hdr_len);
	if (!is_smb_port(ntohs(tcp->source)) && !is_smb_port(ntohs(tcp->dest)))
		return;

	tcp_hdr_len = (size_t)tcp->doff * 4U;
	if (tcp_hdr_len < sizeof(struct tcphdr))
		return;
	if (frame_len < (ssize_t)(sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len))
		return;

	payload     = frame + sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len;
	payload_len = (size_t)frame_len - (sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len);
	if (payload_len == 0U)
		return;

	inspect_ntlm_payload(payload, payload_len, ts, stats);
}

static void usage(const char *prog)
{
	(void)fprintf(stderr,
		      "Usage: %s -i interface [-c packet_count]\n"
		      "\n"
		      "  -i interface     Capture live traffic from interface (root required)\n"
		      "  -c packet_count  Stop after <packet_count> total packets (0 = unlimited)\n"
		      "  -h               Show this help and exit\n"
		      "\n"
		      "Exits 0 if no NTLMv1 traffic was seen, 1 if potential NTLMv1 was detected.\n",
		      prog);
}

int main(int argc, char **argv)
{
	char          *interface_name = NULL;
	unsigned long  packet_count   = 0UL;
	int            opt;
	int            sockfd;
	unsigned char  buffer[max_frame_size];
	struct scan_stats stats = {0, 0, 0};

	while ((opt = getopt(argc, argv, "i:c:h")) != -1) {
		switch (opt) {
		case 'i':
			interface_name = optarg;
			break;
		case 'c':
		{
			char         *endptr = NULL;
			unsigned long value;

			errno = 0;
			value = strtoul(optarg, &endptr, 10);
			if (errno != 0 || endptr == optarg || *endptr != '\0') {
				(void)fprintf(stderr,
					      "Invalid packet count: %s\n", optarg);
				return EXIT_FAILURE;
			}
			packet_count = value;
			break;
		}
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (interface_name == NULL) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sockfd < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	{
		struct ifreq      ifr;
		struct sockaddr_ll sll;

		memset(&ifr, 0, sizeof(ifr));
		(void)strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
		if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
			perror("SIOCGIFINDEX");
			(void)close(sockfd);
			return EXIT_FAILURE;
		}

		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_ALL);
		sll.sll_ifindex  = ifr.ifr_ifindex;
		if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
			perror("bind");
			(void)close(sockfd);
			return EXIT_FAILURE;
		}
	}

	(void)printf("Scanning interface '%s' for NTLMv1 authentication traffic...\n",
		     interface_name);

	while (packet_count == 0UL || stats.packets < packet_count) {
		ssize_t       frame_len;
		struct timeval now;

		frame_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
		if (frame_len < 0) {
			perror("recvfrom");
			(void)close(sockfd);
			return EXIT_FAILURE;
		}
		if (frame_len == 0)
			continue;

		stats.packets++;
		if (gettimeofday(&now, NULL) != 0)
			memset(&now, 0, sizeof(now));

		process_frame(buffer, frame_len, &now, &stats);
	}

	(void)close(sockfd);

	(void)printf("\nScan summary:\n");
	(void)printf("  packets processed          : %lu\n", stats.packets);
	(void)printf("  NTLM authenticate messages : %lu\n", stats.ntlm_auth_messages);
	(void)printf("  potential NTLMv1 hits      : %lu\n", stats.ntlmv1_hits);

	return (stats.ntlmv1_hits > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
