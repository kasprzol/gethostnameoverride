#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <map>
#include <string>
#include <fstream>
#include <sstream>

using std::string;

typedef struct hostent* (*libc_gethostbyname_t)(const char *name);
typedef int (*libc_gethostbyname_r_t)(const char *name,
               struct hostent *ret, char *buf, size_t buflen,
               struct hostent **result, int *h_errnop);
typedef int (*libc_getaddrinfo_t)(const char *node, const char *service,
		        const struct addrinfo *hints, struct addrinfo **res);
typedef int (*libc_connect_t)(int sockfd, const struct sockaddr *addr,
		                    socklen_t addrlen);

libc_gethostbyname_t libc_gethostbyname;
libc_gethostbyname_r_t libc_gethostbyname_r;
libc_getaddrinfo_t libc_getaddrinfo;
libc_connect_t libc_connect;

static std::map< string, string > hosts_override;
static bool host_overrides_loaded = false;

void get_orig_funcs()
{
	/* get reference to original (libc provided) write */
	libc_gethostbyname = (struct hostent*(*)(const char*)) dlsym(RTLD_NEXT, "gethostbyname");
	libc_gethostbyname_r = (libc_gethostbyname_r_t)dlsym(RTLD_NEXT, "gethostbyname_r");
	libc_getaddrinfo = (libc_getaddrinfo_t)dlsym(RTLD_NEXT, "getaddrinfo");
	libc_connect = (libc_connect_t)dlsym(RTLD_NEXT, "connect");
}

void load_host_overrides()
{
	string home = getenv( "HOME" );
	string filename = home + "/.hosts";
	std::ifstream hosts_file( filename );
	string line;
	while (std::getline( hosts_file, line ) ) {
		if ( line.find('#') != string::npos ) {
			line.resize( line.find('#') );
		}
		if ( line.empty() ) {
			continue;
		}
		printf("load_host_overrides: line: %s\n", line.c_str());
		std::istringstream iss( line );
		string host, override;
		iss >> override >> host;
		hosts_override[host] = override;
		printf("load_host_overrides: Will redirect [%s] to [%s]\n", host.c_str(), override.c_str());
	}
	printf("\nActive overrides:\n");
	for ( auto it: hosts_override ) {
		printf("[%s] -> [%s]\n", it.first.c_str(), it.second.c_str());
	}
}

void common()
{
	if ( ! libc_gethostbyname_r ) {
		get_orig_funcs();
	}

	if ( ! host_overrides_loaded ) {
		load_host_overrides();
		host_overrides_loaded = true;
	}
}

std::string sockaddr_to_string( const struct sockaddr *addr )
{
	char buffer[100] = {0};
	switch (addr->sa_family)
	{
		case AF_INET:
		{
			struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
			inet_ntop(AF_INET, &(addr_in->sin_addr.s_addr), buffer, 99);
			break;
		}
		case AF_INET6:
		{
			struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
			inet_ntop(AF_INET6, &(addr_in6->sin6_addr), buffer, 99);
			break;
		}
		default:
			return "<UNKNOWN>";
	}
	return buffer;
}

extern "C" {

struct hostent *gethostbyname(const char *name)
{
  common();
	printf("I'm in your gethostbyname! Checking [%s]\n", name);
	auto it = hosts_override.find(name);
	if ( it != hosts_override.end() ) {
		printf("gethostbyname: REDIRECTING [%s] to [%s]!!!!!!!!\n", name, it->second.c_str());
		name = it->second.c_str();
	}
	return libc_gethostbyname(name);
}

int gethostbyname_r(const char *name,
                    struct hostent *ret, char *buf, size_t buflen,
                    struct hostent **result, int *h_errnop)
{
	common();
	printf("I'm in your gethostbyname_r! Checking [%s]\n", name);
	auto it = hosts_override.find(name);
	if ( it != hosts_override.end() ) {
		printf("gethostbyname_r: REDIRECTING [%s] to [%s]!!!!!!!!\n", name, it->second.c_str());
		name = it->second.c_str();
	}
	return libc_gethostbyname_r(name, ret, buf, buflen, result, h_errnop);
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res)
{
	common();
	printf("I'm in your getaddrinfo! Checking [%s]\n", node);
	auto it = hosts_override.find(node);
	if ( it != hosts_override.end() ) {
		printf("getaddrinfo: REDIRECTING [%s] to [%s]!!!!!!!!\n", node, it->second.c_str());
		node = it->second.c_str();
	}
	int ret = libc_getaddrinfo(node, service, hints, res);
	if ( ret != 0 ) {
		printf("getaddrinfo returns FAILURE!! [%d -- %s]\n", ret, gai_strerror(ret));
	} else {
		printf( "getaddrinfo returns succesfully! [%d]\n", ret);
		printf( "getaddrinfo results: " );
		for (addrinfo *the_address = *res;
			the_address != NULL;
			the_address = the_address->ai_next)
			{
				struct sockaddr *addr = (struct sockaddr *)the_address->ai_addr;
				std::string ip_string = sockaddr_to_string( addr );
				printf( "[%s] ", ip_string.c_str() );
			}
		printf( "\n" );
	}
	return ret;

}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	common();
	const char *family;
	const struct sockaddr *orig_addr = addr;
	switch ( addr->sa_family ) {
		case AF_INET:
			family = "IPv4";
			break;
		case AF_INET6:
			family = "IPv6";
			break;
		default:
			family = "unknown family";
			break;
	}
	printf("I'm in your connect (%s)!\n", family);
	if ( addr->sa_family == AF_INET ) {
		const sockaddr_in *a = reinterpret_cast< const sockaddr_in* >( addr );
		auto dest = sockaddr_to_string( addr );
		printf( "Connect to %s:%d (IPv4)\n", dest.c_str(), ntohs(a->sin_port) );
		auto it = hosts_override.find( dest );
		if ( it != hosts_override.end() ) {
			printf( "[connect] Redirecting %s to %s\n", dest.c_str(), it->second.c_str() );
			sockaddr_in *new_addr = reinterpret_cast< sockaddr_in* >( malloc( sizeof( sockaddr_in ) ) );
			if ( ! new_addr ) {
				printf( "Failed to allocate memory for the redirected addr struct!\n");
				exit(1);
			}
			memcpy( new_addr, a, sizeof( sockaddr_in ) );
			inet_pton( AF_INET, it->second.c_str(), &new_addr->sin_addr.s_addr );
			addr = reinterpret_cast< sockaddr* >( new_addr );
		}
#ifdef REDIRECT_PORT_80_TO_8080
		if ( ntohs( a->sin_port ) == 80 ) {
			a->sin_port = htons( 8080 );
			printf( "Redirecting from port 80 to 8080!!\n" );
		}
#endif
	} else if ( addr->sa_family == AF_INET6 ) {
		const sockaddr_in6 *a = reinterpret_cast< const sockaddr_in6* >( addr );
		printf( "Connect to %s:%d (IPv6)\n", sockaddr_to_string( addr ).c_str(), ntohs(a->sin6_port) );
#ifdef REDIRECT_PORT_80_TO_8080
		if ( ntohs( a->sin6_port ) == 80 ) {
			a->sin6_port = htons( 8080 );
			printf( "Redirecting from port 80 to 8080!!\n" );
		}
#endif
	}
	int ret = libc_connect( sockfd, addr, addrlen );
	if ( ret ) {
		printf( "Connection error! errno = %d(%s)\n", errno, strerror( errno ) );
	} else {
		printf( "Connected successfully\n" );
	}
	if ( addr != orig_addr ) {
		free( const_cast< struct sockaddr* >( addr ) );
	}
	return ret;
}

} // extern "C" {
