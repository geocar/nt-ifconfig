#undef UNICODE

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <process.h>

#define INET_INTERFACE_ID	"inet"
#define GUID_NETWORK_ADAPTER	"{4D36E972-E325-11Ce-BFC1-08002BE10318}"

static int prefer_cidr = 0;
struct address_t {
	const char *ip;
	struct address_t *next, *prev;
	char *freeme;
	int num;
};
static int need_reboot = 0;

static int tryrun(char *argv[])
{

	int i, bl;
	char *buffer, *q;
	char *nargv[4] = { "cmd", "/C", NULL, NULL };

	for (i = bl = 0; argv[i]; i++) {
		bl += strlen(argv[i])+1;
		if (i > 0) bl += 2;
	}
	buffer = (char *)malloc(buffer);
	if (!buffer) {
		perror("malloc");
		exit(1);
	}

	for (i = 0, q = buffer; argv[i]; i++) {
		if (i > 0) *q++ = '"';
		strcpy(q, argv[i]);
		q += strlen(argv[i]);
		if (i > 0) *q++ = '"';
		*q++ = ' ';
	}
	q--;
	*q = 0;
	nargv[2] = buffer;
	if (spawnvp(P_WAIT, nargv[0], nargv) == 0) return 1;

	return 0; /* failed */
}

static char *l2cidr(const char *s)
{
	if (strcmp(s, "255.255.255.255") == 0) return "32";

	if (strcmp(s, "255.255.255.254") == 0) return "31";
	if (strcmp(s, "255.255.255.252") == 0) return "30";
	if (strcmp(s, "255.255.255.248") == 0) return "29";
	if (strcmp(s, "255.255.255.240") == 0) return "28";
	if (strcmp(s, "255.255.255.224") == 0) return "27";
	if (strcmp(s, "255.255.255.192") == 0) return "26";
	if (strcmp(s, "255.255.255.128") == 0) return "25";

	if (strcmp(s, "255.255.255.0") == 0) return "24";
	if (strcmp(s, "255.255.254.0") == 0) return "23";
	if (strcmp(s, "255.255.252.0") == 0) return "22";
	if (strcmp(s, "255.255.248.0") == 0) return "21";
	if (strcmp(s, "255.255.240.0") == 0) return "20";
	if (strcmp(s, "255.255.224.0") == 0) return "19";
	if (strcmp(s, "255.255.192.0") == 0) return "18";
	if (strcmp(s, "255.255.128.0") == 0) return "17";

	if (strcmp(s, "255.255.0.0") == 0) return "16";
	if (strcmp(s, "255.254.0.0") == 0) return "15";
	if (strcmp(s, "255.252.0.0") == 0) return "14";
	if (strcmp(s, "255.248.0.0") == 0) return "13";
	if (strcmp(s, "255.240.0.0") == 0) return "12";
	if (strcmp(s, "255.224.0.0") == 0) return "11";
	if (strcmp(s, "255.192.0.0") == 0) return "10";
	if (strcmp(s, "255.128.0.0") == 0) return "9";

	if (strcmp(s, "255.0.0.0") == 0) return "8";
	if (strcmp(s, "254.0.0.0") == 0) return "7";
	if (strcmp(s, "252.0.0.0") == 0) return "6";
	if (strcmp(s, "248.0.0.0") == 0) return "5";
	if (strcmp(s, "240.0.0.0") == 0) return "4";
	if (strcmp(s, "224.0.0.0") == 0) return "3";
	if (strcmp(s, "192.0.0.0") == 0) return "2";
	if (strcmp(s, "128.0.0.0") == 0) return "1";

	if (strcmp(s, "0.0.0.0") == 0) return "0";

	return (char *)s;
}
static char *cidr2l(const char *s)
{
	if (*s == '/') s++;

	if (strcmp(s, "32") == 0) return "255.255.255.255";
	if (strcmp(s, "31") == 0) return "255.255.255.254";
	if (strcmp(s, "30") == 0) return "255.255.255.252";
	if (strcmp(s, "29") == 0) return "255.255.255.248";
	if (strcmp(s, "28") == 0) return "255.255.255.240";
	if (strcmp(s, "27") == 0) return "255.255.255.224";
	if (strcmp(s, "26") == 0) return "255.255.255.192";
	if (strcmp(s, "25") == 0) return "255.255.255.128";

	if (strcmp(s, "24") == 0) return "255.255.255.0";
	if (strcmp(s, "23") == 0) return "255.255.254.0";
	if (strcmp(s, "22") == 0) return "255.255.252.0";
	if (strcmp(s, "21") == 0) return "255.255.248.0";
	if (strcmp(s, "20") == 0) return "255.255.240.0";
	if (strcmp(s, "19") == 0) return "255.255.224.0";
	if (strcmp(s, "18") == 0) return "255.255.192.0";
	if (strcmp(s, "17") == 0) return "255.255.128.0";

	if (strcmp(s, "16") == 0) return "255.255.0.0";
	if (strcmp(s, "15") == 0) return "255.254.0.0";
	if (strcmp(s, "14") == 0) return "255.252.0.0";
	if (strcmp(s, "13") == 0) return "255.248.0.0";
	if (strcmp(s, "12") == 0) return "255.240.0.0";
	if (strcmp(s, "11") == 0) return "255.224.0.0";
	if (strcmp(s, "10") == 0) return "255.192.0.0";
	if (strcmp(s, "9") == 0) return "255.128.0.0";

	if (strcmp(s, "8") == 0) return "255.0.0.0";
	if (strcmp(s, "7") == 0) return "254.0.0.0";
	if (strcmp(s, "6") == 0) return "252.0.0.0";
	if (strcmp(s, "5") == 0) return "248.0.0.0";
	if (strcmp(s, "4") == 0) return "240.0.0.0";
	if (strcmp(s, "3") == 0) return "224.0.0.0";
	if (strcmp(s, "2") == 0) return "192.0.0.0";
	if (strcmp(s, "1") == 0) return "128.0.0.0";

	return "255.255.255.255"; /* shouldn't happen */
}

void expand_addresslist(struct address_t **top, char *buf, unsigned int len, char *assoc)
{
	int i;
	struct address_t *x;
	int addrlen;

	*top = NULL;
	i = 1;
	while (len > 2) {
		x = (struct address_t *)malloc(sizeof(struct address_t));
		if (!x) {
			perror("malloc");
			exit(1);
		}

		x->ip = buf;
		x->next = *top;
		x->prev = NULL;
		if (*top)
			x->next->prev = x;
		x->freeme = assoc;
		x->num = i;

		*top = x;

		buf +=  (addrlen = strlen(buf) + 1);
		len -= addrlen;
	}
}
void compress_addresslist(struct address_t *top, char **space, unsigned int *len)
{
	struct address_t *x;
	char *ptr;
	int addrlen;

	for (*len = 1, x = top; x; x = x->next)
		if (x->ip)
			(*len) += strlen(x->ip) + 1;

	*space = ptr = (char *)malloc(*len);
	if (!*space) {
		perror("malloc");
		exit(1);
	}
	/* NOTE: this must be done in REVERSE ORDER
	 * because the "first" address is the "main address"
	 */
	for (x = top; x->next; x = x->next);
	for (; x; x = x->prev) {
		if (!x->ip)
			continue;
		memcpy(ptr, x->ip, addrlen = strlen(x->ip) + 1);
		ptr += addrlen;
	}
	*ptr = 0; /* last ZERO */
}
void free_addresslist(struct address_t *top)
{
	struct address_t *x, *y;

	for (x = top; x; x = top) {
		top = x->next;
		for (y = x->next; y ; y = y->next)
			if (y->freeme == x->freeme)
				y->freeme = NULL;
		free(x->freeme);
		free(x);
	}
}
int interface_connect(int i, PHKEY h,
		int (*shortcut)(char *, void *, void *), void *qa, void *qb)
{
	int r;
	char buffer[1024];
	char rsbuf[1024];
	DWORD rslen, rstype;
	HKEY p;

retry_start_l:
	sprintf(buffer, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%d", i + 1);
	if (RegOpenKey(HKEY_LOCAL_MACHINE, (const char *)buffer, &p) != ERROR_SUCCESS)
		return -1;

	rslen = sizeof(rsbuf);
	if (RegQueryValueEx(p, (const char *)"ServiceName", NULL, &rstype, rsbuf, &rslen) != ERROR_SUCCESS)
		return -1;
	rsbuf[rslen] = 0;
	RegCloseKey(p);

	if (strlen(rsbuf) + 69 + sizeof(GUID_NETWORK_ADAPTER) >= sizeof(buffer))
		return -1;/* out of room */

	/* Win2K has a netSH shortcut! */
	if (shortcut) {
		sprintf(buffer, "SYSTEM\\CurrentControlSet\\Control\\Network\\%s\\%s\\Connection", GUID_NETWORK_ADAPTER, rsbuf);
		if (RegOpenKey(HKEY_LOCAL_MACHINE, buffer, &p) == ERROR_SUCCESS) {
			/* woot! windows 2000 can make any option here on out VERY easy! */

			rslen = sizeof(rsbuf);
			if (RegQueryValueEx(p, (const char *)"Name",
			NULL, &rstype, rsbuf, &rslen) != ERROR_SUCCESS) {

				shortcut = NULL;
				goto retry_start_l;
			}
			rsbuf[rslen] = 0;
			RegCloseKey(p);

			r = shortcut(rsbuf, qa, qb);
			if (r == -1) {
				/* if we get here, then shortcut failed */
				shortcut = NULL;
				goto retry_start_l;
			}
			return r;
		}
	}

	/* Win2K uses this... */
	sprintf(buffer, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s", rsbuf);
	if (RegOpenKey(HKEY_LOCAL_MACHINE, buffer, h) != ERROR_SUCCESS) {
		/* ...WinNT uses this */
		sprintf(buffer, "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters\\Tcpip", rsbuf);
		if (RegOpenKey(HKEY_LOCAL_MACHINE, buffer, h) != ERROR_SUCCESS)
			return -1;
	}
/*	fprintf(stderr, "Opened %s  h = %u\n",buffer,*h); */
	return 0;
}
void interface_disconnect(HKEY h)
{
	RegCloseKey(h);
}
int interface_load_addresses(HKEY r, const char *keyn, struct address_t **top, int *type)
{
	DWORD rstype, len;
	char *buffer;
	int sp, ee;

	/* load the address list into memory */
	buffer = NULL;
	for (sp = 64;; sp += 64) {
		if (buffer)
			free(buffer);
		buffer = (char *)malloc(len = sp);
		if (!buffer) {
			perror("malloc");
			exit(1);
		}
		switch (ee=RegQueryValueEx(r, (const char *)keyn, NULL,
					&rstype, buffer, &len)) {
		case ERROR_MORE_DATA:
			/* r can be HKEY_PERFORMANCE_DATA, so don't trust len... */
			continue;
		case ERROR_SUCCESS:
			break;
		default:
			fprintf(stderr, "RegQueryValueEx: Could not locate (%s)\n", keyn);
			fprintf(stderr, "RegQueryValueEx: Unknown Error (%x // %d)\n", ee, ee);
			exit(1);
		};
		break;
	}

	/* save the seen type */
	if (type)
		*type = rstype;

	expand_addresslist(top, buffer, len, buffer);
	return 0;
}

int dump_interfaces(void)
{
	char buffer[1024];
	char rsbuf[1024];
	DWORD rslen, rstype;
	HKEY p;
	int i;

	printf("Visible Interfaces:\n");
	for (i = 0; i < 256; i++) {
		sprintf(buffer, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%d", i + 1);
		if (RegOpenKey(HKEY_LOCAL_MACHINE, (const char *)buffer, &p)
				!= ERROR_SUCCESS)
			continue;
		rslen = sizeof(rsbuf);
		if (RegQueryValueEx(p, (const char *)"Description",
				NULL, &rstype, rsbuf, &rslen) != ERROR_SUCCESS)
			continue;
		rsbuf[rslen] = 0;
		printf("        %s%d: %s\n", INET_INTERFACE_ID, i, rsbuf);
		RegCloseKey(p);
	}
	return 0;
}
char *get_default_subnet_mask(int interface_num)
{
	/* caller must free */
	HKEY h;
	struct address_t *ifnetmask, *x;
	static char default_subnet[256];
	static int last_interface_num = -1;

	if (interface_num == last_interface_num && last_interface_num != -1)
		return default_subnet;

	if (interface_connect(interface_num, &h, NULL, NULL, NULL) == -1)
		return 0;

	if (interface_load_addresses(h, "SubnetMask", &ifnetmask, NULL) == -1) {
		interface_disconnect(h);
		return 0;
	}
	for (x = ifnetmask; x->next; x = x->next);

	strcpy(default_subnet, x->ip);

	interface_disconnect(h);
	free_addresslist(ifnetmask);

	last_interface_num = interface_num;

	return default_subnet;
}
int dump_interface_info(int interface_num)
{
	HKEY h;
	struct address_t *ifip, *ifnetmask;
	struct address_t *x, *y;
	int firstaddr;

	if (interface_connect(interface_num, &h, NULL, NULL, NULL) == -1)
		return -1;

	fprintf(stderr, "Looking to dump iinterface info: %u\n", h);
	if (interface_load_addresses(h, "IPAddress", &ifip, NULL) == -1) {
		interface_disconnect(h);
		return -1;
	}

	if (interface_load_addresses(h, "SubnetMask", &ifnetmask, NULL) == -1) {
		interface_disconnect(h);
		free_addresslist(ifip);
		return -1;
	}

	printf("Addresses bound to %s%d:\n", INET_INTERFACE_ID, interface_num);
	/* NOTE: this must be done in REVERSE ORDER
	 * because the "first" address is the "main address"
	 */
	for (x = ifip, y=ifnetmask; x->next && y->next; x = x->next, y = y->next);
	for (firstaddr = 1; x && y; x = x->prev, y = y->prev) {
		printf("        %s/%s%s\n", x->ip, prefer_cidr ? l2cidr(y->ip) : y->ip,
				firstaddr ? " (primary)" : "");
		firstaddr = 0;
	}

	free_addresslist(ifip);
	free_addresslist(ifnetmask);
	interface_disconnect(h);
	return 0;
}
void display_usage_and_exit(const char *argv0)
{
	fprintf(stderr, "Usage: %s /list                - list all interfaces\n", argv0);
	fprintf(stderr, "       %s interface /list      - list all addresses bound to an interface\n", argv0);
	fprintf(stderr, "       %s interface /add X     - assign address `X' to interface\n", argv0);
	fprintf(stderr, "       %s interface /del X     - remove addres `X' from interface\n", argv0);
	fprintf(stderr, "       %s interface /enable    - enable DHCP for interface\n", argv0);
	fprintf(stderr, "       %s interface /disable   - disable DHCP for interface\n", argv0);
	exit(0);
}

static int test_valid_ipaddress(const char *ip)
{
	int a, b, c, d;

	if (sscanf(ip, "%d.%d.%d.%d", &a,&b,&c,&d) != 4)
		return -1;
	if (a == 0 || a == 255 || b == 255 || c == 255 || d == 0 || d == 255)
		return -1;
	return 0;
}
static int test_valid_subnetmask(const char *ip)
{
	int m[4], i, j;

	if (sscanf(ip, "%d.%d.%d.%d", &m[0], &m[1], &m[2], &m[3]) != 4) {
		if (sscanf(ip, "/%d", &i) != 1 && sscanf(ip, "%d", &i) != 1) return -1;
		/* CIDR form */
		if (i >= 0 && i <= 32) return 0;
		return -1;
	}
	if (m[0] == 0 && (m[1] || m[2] || m[3]))
		return -1;
	if (m[1] == 0 && (m[2] || m[3]))
		return -1;
	if (m[2] == 0 && m[3])
		return -1;

	for (i = 0; i < 4; i++) {
		if (m[i] == 0)
			break;
		for (j = 0; j < 8; j++) {
			if (1 << j == (256 - m[i]))
				break;
		}
		if (j == 8)
			return -1;
	}
	return 0;
}
static void hexdump(char *ptr, int len)
{
	int i;
	for (i = 0; len > 0;) {
		printf("%02X ", *ptr);
		i++;
		if (i == 8) putchar(' '); else if (i == 16) { i = 0; putchar('\n'); }
		ptr++;
		len--;
	}
	putchar('\n');
	putchar('\n');
}
static int delete_inet_address_shortcut(char *ifn, void *dat, void *ignored)
{
	char *argv[9] = {
			"netsh",
			"interface",
			"ip",
			"delete",
			"address",
			"XXX",
			"YYY",
			NULL,
	};
	argv[5] = ifn;
	argv[6] = (char *)dat;

	if (tryrun(argv)) {
		return 42; /* okay! */
	}

	return -1; /* let other handlers try */
}
int delete_inet_address_from_interface(int interface_num, char *ip)
{
	struct address_t *top, *sub, *x, *y;
	
	int ipregkey_type;
	char *ipregkey_buf;
	unsigned int ipregkey_len;

	int subregkey_type;
	char *subregkey_buf;
	unsigned int subregkey_len;

	HKEY h;


	switch (interface_connect(interface_num, &h,
				delete_inet_address_shortcut,
				(void *)ip, NULL)) {
	case -1: return -1;
	case 42:
		need_reboot = 0;
		return 0;
	default:
		need_reboot = 1;
		break;
	};

	fprintf(stderr, "Looking to get ipaddress info: %u\n", h);
	if (interface_load_addresses(h, "IPAddress", &top, &ipregkey_type) == -1) {
		interface_disconnect(h);
		return -1;
	}

	for (y = top; y; y = y->next)
		if (strcmp(y->ip, ip) == 0)
			break;
	if (!y) {
		/* not found */
		interface_disconnect(h);
		return 0;
	}

	y->ip = NULL;

	if (interface_load_addresses(h, "SubnetMask", &sub, &subregkey_type) == -1) {
		interface_disconnect(h);
		free_addresslist(top);
		return -1;
	}
	for (x = sub; x; x = x->next)
		if (y->num == x->num) {
			y->ip = NULL;
			break;
		}

	compress_addresslist(top, &ipregkey_buf, &ipregkey_len);
	compress_addresslist(sub, &subregkey_buf, &subregkey_len);

	/* push both into registry */
	if (RegSetValueEx(h, "IPAddress", 0, ipregkey_type, ipregkey_buf, ipregkey_len) != ERROR_SUCCESS) {
		interface_disconnect(h);
		free(ipregkey_buf);
		free(subregkey_buf);
		free_addresslist(top);
		free_addresslist(sub);
		return -1;
	}
	if (RegSetValueEx(h, "SubnetMask", 0, subregkey_type, subregkey_buf, subregkey_len) != ERROR_SUCCESS) {
		fprintf(stderr, "Warning! IPAddress was updated but SubnetMask was not!\n");
		fprintf(stderr, "System may be unusable after reboot!\n");
		interface_disconnect(h);
		free(ipregkey_buf);
		free(subregkey_buf);
		free_addresslist(top);
		free_addresslist(sub);
		return -1;
	}

	/* destroy addresslist */
	free(ipregkey_buf);
	free(subregkey_buf);
	free_addresslist(top);
	free_addresslist(sub);
		
	interface_disconnect(h);

	return 0;	
}
int add_inet_address_shortcut(char *ifn, void *qa, void *qb)
{
	char *argv[9] = {
			"netsh",
			"interface",
			"ip",
			"add",
			"address",
			"XXX",
			"YYY",
			"ZZZ",
			NULL,
	};
	argv[5] = ifn;
	argv[6] = (char *)qa;
	argv[7] = (char *)qb;

	if (tryrun(argv)) {
		return 42; /* okay! */
	}

	return -1; /* let other handlers try */
}
int add_inet_address_to_interface(int interface_num, char *ip, char *subnet_passed)
{
	struct address_t *top, *sub, *x, *y;
	HKEY h;
	
	int ipregkey_type;
	char *ipregkey_buf;
	unsigned int ipregkey_len;

	int subregkey_type;
	char *subregkey_buf;
	unsigned int subregkey_len;

	char *subnetmask;
	int i;

	for (i = 0; subnet_passed[i]; i++)
		if (!isdigit(subnet_passed[i])) break;
	if (!subnet_passed[i]) {
		/* cidr: translate */
		subnetmask = cidr2l(subnet_passed);
	} else
		subnetmask = subnet_passed;

	switch (interface_connect(interface_num, &h,
				add_inet_address_shortcut,
				ip, subnetmask)) {
	case -1: return -1;
	case 42:
		need_reboot = 0;
		return 0;
	default:
		need_reboot = 1;
		break;
	};

	fprintf(stderr, "Looking to add ipaddress info: %u\n", h);
	if (interface_load_addresses(h, "IPAddress", &top, &ipregkey_type) == -1) {
		interface_disconnect(h);
		return -1;
	}

	for (y = top; y; y = y->next)
		if (strcmp(y->ip, ip) == 0)
			break;
	if (y) {
		/* found */
		free_addresslist(top);
		interface_disconnect(h);
		return 0;
	}

	if (interface_load_addresses(h, "SubnetMask", &sub, &subregkey_type) == -1) {
		free_addresslist(top);
		interface_disconnect(h);
		return -1;
	}

	x = (struct address_t *)malloc(sizeof(struct address_t));
	y = (struct address_t *)malloc(sizeof(struct address_t));

	if (!x || !y) {
		perror("malloc");
		exit(1);
	}

	/* add this guy to the beginning */
	x->freeme = NULL;
	y->freeme = NULL;
	x->ip = ip;
	y->ip = subnetmask;
	x->num = 0;
	y->num = 0;
	x->next = top;
	x->prev = NULL;
	if (x->next)
		x->next->prev = x;
	y->next = sub;
	y->prev = NULL;
	if (y->next)
		y->next->prev = y;
	top = x;
	sub = y;

	compress_addresslist(top, &ipregkey_buf, &ipregkey_len);
	compress_addresslist(sub, &subregkey_buf, &subregkey_len);

	/* push both into registry */
	if (RegSetValueEx(h, (const char *)"IPAddress", 0, ipregkey_type,
			ipregkey_buf, ipregkey_len) != ERROR_SUCCESS) {
		interface_disconnect(h);
		free(ipregkey_buf);
		free(subregkey_buf);
		free_addresslist(top);
		free_addresslist(sub);
		return -1;
	}
	if (RegSetValueEx(h, (const char *)"SubnetMask", 0, subregkey_type,
			subregkey_buf, subregkey_len) != ERROR_SUCCESS) {
				
		fprintf(stderr, "Warning! IPAddress was updated but SubnetMask was not!\n");
		fprintf(stderr, "System may be unusable after reboot!\n");
		interface_disconnect(h);
		free(ipregkey_buf);
		free(subregkey_buf);
		free_addresslist(top);
		free_addresslist(sub);
		return -1;
	}

	/* destroy addresslist */
	free(ipregkey_buf);
	free(subregkey_buf);
	free_addresslist(top);
	free_addresslist(sub);
		
	interface_disconnect(h);

	return 0;	
}

int do_inet_config(const char *argv0, int interface_num, char **argv, int argc)
{
	int i, j;
	int did_changes = 0;
	char *defsub = 0;

	for (i = 0; i < argc; i++) {
		if (strcmpi(argv[i], "/cidr") == 0) {
			prefer_cidr = 1;
			continue;
		}
		if (strcmpi(argv[i], "/help") == 0 || strcmp(argv[i], "/?") == 0 || strcmpi(argv[i], "/h") == 0)
			display_usage_and_exit(argv0);
	}
	for (i = 0; i < argc; i++) {
		if (strcmpi(argv[i], "/list") == 0 || strcmpi(argv[i], "/l") == 0) {
			dump_interface_info(interface_num);
			continue;
		}
		
		if (strcmpi(argv[i], "/add") == 0 || strcmpi(argv[i], "/a") == 0) {
			if (i == argc - 2){
				/* optional: ip/cidr or ip/subnet */
				for (j = 0; argv[i+1][j] != '/' && argv[i+1][j]; j++);
				if (argv[i+1][j]) {
					if (test_valid_ipaddress(argv[i+1]) == -1) {
						fprintf(stderr, "%s is not a valid IP address\n", argv[i+1]);
						return 1;
					}
					if (test_valid_subnetmask(argv[i+1] + (j + 1)) == -1) {
						fprintf(stderr, "%s is a bogus network mask\n", argv[i+1] + (j+1));
						return 1;
					}
					switch (add_inet_address_to_interface(interface_num, argv[i+1],
								argv[i+1] + (j+1))) {
					case -1:
						fprintf(stderr, "Failed to insert address onto adapter\n");
						return 1;
					case 0:
						break;
					}
					did_changes = 1;
					i++;
					i++;
					continue;
				}

				/* fall through; will use "default" subnet from primary interface */
				if (test_valid_ipaddress(argv[i+1]) == -1) {
					fprintf(stderr, "%s is not a valid IP address\n", argv[i+1]);
					return 1;
				}

				defsub = get_default_subnet_mask(interface_num);
				if (!defsub) {
					fprintf(stderr, "/add cannot determine subnet mask where there is no primary address\n");
					return 1;
				}

				switch (add_inet_address_to_interface(interface_num, argv[i+1], defsub)) {
				case -1:
					fprintf(stderr, "Failed to insert address onto adapter\n");
					return 1;
				case 0:
					break;
				}
				did_changes = 1;
				i++;
				i++;
				continue;
			}

			if (i > argc - 3){
				fprintf(stderr, "/add requires 2 arguments: IP address and subnet mask\n");
				return 1;
			}
			if (test_valid_ipaddress(argv[i+1]) == -1) {
				fprintf(stderr, "%s is not a valid IP address\n", argv[i+1]);
				return 1;
			}
			if (!strcmp(argv[i+2], "-") || !strcmp(argv[i+2], "*") || !strcmp(argv[i+2], "?")) {
				defsub = get_default_subnet_mask(interface_num);

			} else if (test_valid_subnetmask(argv[i+2]) == -1) {
				fprintf(stderr, "%s is a bogus network mask\n", argv[i+2]);
				return 1;
			} else {
				defsub = argv[i+2];
			}

			switch (add_inet_address_to_interface(interface_num, argv[i+1], defsub)) {
			case -1:
				fprintf(stderr, "Failed to insert address onto adapter\n");
				return 1;
			case 0:
				break;
			}
			did_changes = 1;
			i++;
			i++;
			i++;
			continue;
		}
		if (strcmpi(argv[i], "/del") == 0 || strcmpi(argv[i], "/delete") == 0 || strcmpi(argv[i], "/d") == 0) {
			if (i > argc - 2){
				fprintf(stderr, "/delete requires 1 argument: IP address\n");
				return 1;
			}
			switch (delete_inet_address_from_interface(interface_num, argv[i+1])) {
			case -1:
				fprintf(stderr, "Failed to remove address onto adapter\n");
				return 1;
			case 0:
				break;
			}
			did_changes = 1;
			i++;
			continue;
			
		}
	}
	if (did_changes) {
		if (need_reboot) {
			fprintf(stderr, "You must restart Windows for your changes to take effect.\n");
			return 1;
		} else {
			fprintf(stderr, "All changes have taken effect immediately.\n");
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	char *ifn;
	int i, interface_num;

	if (argc == 1)
		display_usage_and_exit(argv[0]);

	if (argv[1][0] == '/' && argv[2] && argv[2][0] != '/') {
		ifn = argv[1];
		argv[1] = argv[2];
		argv[2] = ifn;
	}

	if (argc == 2 && strcmpi(argv[1], "/list") == 0) {
		dump_interfaces();
		return 0;
	}

	ifn = argv[1];
	for (i = 0; ifn[i]; i++)
		ifn[i] = tolower(ifn[i]);
	if (strncmp(ifn, INET_INTERFACE_ID, strlen(INET_INTERFACE_ID)-1) == 0) {

		interface_num = atoi(ifn + (strlen(INET_INTERFACE_ID)));

		if (interface_num < 0 || interface_num > 255) {
			fprintf(stderr, "Interface is invalid: ``%s''\n", ifn);
			return 1;
		}
		return do_inet_config(argv[0], interface_num,
				(char **)argv+2, argc-2);
	}

	fprintf(stderr, "Unknown interface type: ``%s''\n", ifn);
	return 1;
}
