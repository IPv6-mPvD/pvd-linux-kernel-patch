This document aims at:
1. clarifing a bit the code design of this patch in fulfilling the PvD feature;
2. exposing some un-addressed issues regarding this patch: what is the problem, potential solutions, pro/con/cost of the soltions;

Such that experienced users or futher devoloppers can easily pick it up and push it further.

# Usage of this patch

The patch in this k415 branch is build upon Ubuntu 1804 LTS source tree (commit hash: 1221ffab3e8e42c17c6c54cf60e037abd76e199a), and should be applied to 4.15 kernels.

The PvD feature is controlled by the Kernel configuration option CONFIG_NETPVD under _drivers->net_ (doesn't seem to me as the most fitting place).

The feature can be activated (by default)/deactivated on a per interface base through sytsctl entry _net.conf.ipv6.[interface].parse_pvd_. (NOTE: like _accepte_ra_ entry, there is no handle implemented for __all__ interface.)

A tutorial on how to apply this patch and run PvD-aware applications on top of it can be found in [pvd-dev](https://github.com/IPv6-mPvD/pvd-dev.git).

# PvD data structure in network namespace

[Network namespace](https://lwn.net/Articles/531114/), like other linux namespaces, provides resource isolation, assoicated with networking, e.g. network devices, IP addresses and routing tables.
Accordingly, it is all fitting and even necessary that each network namespace has its individual view of PvD. To that end, this patch adds PvD-related data structure to network namespace data strucutre and manges them, in a way similar to how current kernel manages network devices: __struct__ _net_device_.

In _include/net/net_namespace.h_ under kernel source repository, we can find the definition of __struct__ _net_ for network namespace. 
Those PvD-related attributes are are enclosed in __CONFIG_NETPVD__ ifdef pre-processor:
```C
struct net {
	refcount_t		passive;	/* To decided when the network
						 * namespace should be freed.
						 */
	atomic_t		count;		/* To decided when the network
						 *  namespace should be shut down.
						 */
	spinlock_t		rules_mod_lock;

	atomic64_t		cookie_gen;

	struct list_head	list;		/* list of network namespaces */
	struct list_head	cleanup_list;	/* namespaces on death row */
	struct list_head	exit_list;	/* Use only net_mutex */

    /* attributes omitted */

	struct list_head 	dev_base_head;
	struct hlist_head 	*dev_name_head;
	struct hlist_head	*dev_index_head;
	unsigned int		dev_base_seq;	/* protected by rtnl_mutex */
	int			ifindex;
	unsigned int		dev_unreg_count;

#ifdef	CONFIG_NETPVD
	/*
	 * Pvd related info
	 * pvdindex : sequence number used to allocate a unique
	 * number to each pvd
	 *
	 * pvd_free_slots[] is a linked list of indexes (each cell
	 * contains the index of the next free pvd slot). first_free_pvd_ix
	 * is the index of the first free slot (-1 means no more slots)
	 *
	 * pvd_used_slots[] is an array of pointer to active pvd
	 * structures. The pvd structures are linked together via
	 * a next field. first_used_pvd points to the head of the
	 * pvd current list. The pvd_used_slots[] is used to perform
	 * consistency checks on pvds, and not (for now) to list
	 * them
	 *
	 * If a slot is not part of the pvd_free_slots[] list,
	 * then its pvd_used_slots[] entry points to a pvd
	 */
	/* WQ: why linked list of pvds won't suffice? */
	unsigned int		pvd_base_seq;	/* protected by rtnl_mutex */
	u32			pvdindex;
	void			*pvd_used_slots[MAXPVD];/* struct net_pvd *[] */
	void			*first_used_pvd;	/* struct net_pvd * */
	int			pvd_free_slots[MAXPVD];	/* array of indexes */
	int			first_free_pvd_ix;	/* index */
	unsigned int		pvd_unreg_count;

	void			*pvd_cached_ra;

	struct timer_list	pvd_timer;
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry	*proc_pvdd;
#endif
#endif	/* CONFIG_NETPVD */

    /* attributes omitted */
    }
```

The current PvD-related data strucutre basically constructs a growable array with max size equal to MAXPVD.
Everytime a PvD is added to or removed from a network namesapce, __pvd_used_slots__, __pvd_free_slots__, __first_free_pvd_ix__, __first_used_pvd__ need to be potentially updated.
To really understand how they are manuipulated, __register_pvd()__ and __unregister_pvd()__ in _net/core/pvd.c_ would be the ultimate, self-explanatory places to look at.
Apart from the non-intuitive (at least for me) approach, the main draw back is that since they are not built-in data structures such as linked-list, protecting them from concurrent access is painful and error prone.

A better practice would be to mimic how __net_device__ is managed in network namespace, more in __net/core/dev.c__.
Foundementally, this implies (not exhaustive): 
1. incorporate __list_head__ in __net_pvd__ defined in _include/net/pvd.h_;
2. change the way pvdindex is generated, this and following change deals with _net/core/pvd.c_;
3. change the way a pvd is added to and removed from the network namespace using rcu primitives;
4. change the way a pvd is searched by it name, pvdindex, associating device, etc, using rcu primitives.

# Bind a thread/process/socket to a PvD
The action of binding a thread/process/socket to a PvD dictates that the network traffic associated to the thread/process/socket is only allowed to use the routes, source addresses (managed in kernel) and DNS serverses (managed in userspace, say by [glibc](https://github.com/IPv6-mPvD/glibc.git)) attached to the PvD.

> [Out-of-scope comment] A PvD-aware application should then be at least capable of:
>1. learning about the avaiable PvDs and their attribites and characteristics;
>2. bind its child processes/threads, or sockets to one or some PvDs according to its application network delivery needs (NOTE: the PvD binding of thread and process may change over their lifetime. What happens if we change the PvD binding of TCP socket during its lifetime?).

>Or the above function is realised by a middleware provding socket-like API, e.g. [NEAT](https://www.neat-project.org/publications/).

By default, that is when without any specification, socket inherits the binding of __current__ thread/process, thread/process inherits the binding of its parent.
A special binding status is binding to no PvD, which permits a thread/process/socket to use whatever route, addresses, regardless the laters' PvD association.

This patch brings data strucutre amendments to realise the above described behaviour.
For thread/process, the key change lies in __struct__ _task_struct_ defined in _include/linux/sched.h_.
```c
struct task_struct {
    /* attributes omitted */
#ifdef CONFIG_NETPVD
	char	*bound_pvd;	/* 0 : inherit; -1 : unset, otherwise : set */
#endif
   /* attributes omitted */
}
```
A char pointer _bound_pvd_ is added to the massive _task_struct_ to record its PvD binding status.
The value of this point is set to `((void *) 0)` when a thread/process inherts PvD binding from its parent; to `((void *) -1)` when a thread/process binds to no PvD.
In order to explicitly bind a thread/process to a PvD, a new option __SO_BINDTOPVD__, along with some others in _/include/uapi/asm-generic/socket.h_, is added to the standard _setsockopt_ API.
```c
/* lines omitted*/
#define	SO_GETPVDLIST		62
#define	SO_GETPVDATTRIBUTES	63
#define	SO_CREATEPVD		64
```
>Personally, I don't think set/getsockopt should be the userfacing interface for __SO_GETPVDLIST__, __SO_GETPVDATTRIBUTES__, __SO_CREATEPVD__. Ideally, they should rather be rtnetlink messages and be manipulated through [iproute2](https://github.com/IPv6-mPvD/iproute2.git). More discussion on this issue in later section. 

In the definition for __function__ _sock_setsockopt()_ in _net/core/sock.c_, we can see that the __SO_BINDTOPVD__ option is implemented by __function__ _sock_setbindtopvd()_ in  _net/core_pvd.c_.
```c
int sock_setbindtopvd(
		struct sock *sk,
		char __user *optval,
		int optlen) {

        /* many things skipped */
    thread_scope :
        /* many things skipped */

        if (! (p->bound_pvd = kstrdup(pvdname, GFP_KERNEL))) {
				p->bound_pvd = FORCE_NO_PVD_PTR;
				ret = -ENOSPC;
        }

        /* many things skipped */
        return ret;
}
```
Basically, the above function sets the _bound_pvd_ char pointer to 
a string containing the PvD name, a full qualified domain name (FQDN) when regarding an explicit PvD.
The problem of the above code is that it doesn't verify whether the __string__ _pvdname_ corresponds to a currently existing PvD seen by the kernel.
As a matter of fact, a thread/process can be asked to bind to an arbitray string as PvD without any immediate error!

So how the PvD binding status of a thread/process is reflected in the choice of route and source address? And what's the consequence in these choices when bound to a non-existant PvD? Let's look one possible code path regarding TCP connection creation, implemented in _net/ipv6/tcp_ipv6.c_.
```c
static int tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr,
			  int addr_len)
{
    /* many things skipped */
#ifdef	CONFIG_NETPVD
	/*
	 * fl6.pvd will only be used during the route and
	 * source address selection of the connect() process
	 *
	 * We can and must pvd_put() it before returning
	 */
	if ((err = pvd_getboundpvd(sk, (struct net_pvd **) &fl6.pvd)) != 0) {
		goto failure;
	}
#endif

	opt = rcu_dereference_protected(np->opt, lockdep_sock_is_held(sk));
	final_p = fl6_update_dst(&fl6, opt, &final);

	security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));

	dst = ip6_dst_lookup_flow(sk, &fl6, final_p);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		goto failure;
	}

    /* many things skipped */
}
```
It is via a call to _pvd_getboundpvd_, the corresponding __struct__ _flowi6_ (defined in _inlcude/net/flow.h_) learns the PvD binding of the current socket, which might eventually depend on the PvD binding of the __current__ thread/process or its parent. Later on, route and source address selection are performaned in awareness of the PvD pointer of _fl6_.
__function__ _pvd_getboundpvd_ will return with error code network unreachable, if the 1/ the socket PvD binding depends on its parent thread/process and 2/ the later binds to a non-existant PvD. More concretely in _net/core/pvd.c_:
```c
static int _pvd_getboundpvd(struct sock *sk, struct net_pvd **pvd, int scope)
{
    struct task_struct *p = current;
    /* many things skipped */
    thread_scope :
	/* many things skipped */
		pvd_hold(*pvd = __pvd_get_by_name(
					sock_net(sk),
					p->bound_pvd,
					NULL,	/* dev */
					NULL));	/* lla */
		if (*pvd == NULL) {
			ret = -ENETUNREACH;
		}
    /% many things skipped %/
	return ret;
}
```
This behaviour could be very annoying: an application will lose network connection because end-user or application itself carelessly forces the binding to a non-existant PvD.
To avoid such consequence yet without changing the patch, we recommend verifying the binding result (thread/process scope) before generating traffic. An example code snippet for PvD-aware application is provided below:
```c
/* tcp client that can be configured with a proc scope pvd binding*/
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <libpvd.h>
#include <string.h>
#include <strings.h>

#define SERVE_PORT 8888

int main(int argc, char *argv[])
{
    int sock_fd = -1;
    struct sockaddr_in6 server_addr;
    int ret;
    char buf[65535];

    if (argc !=3) {
        printf("Usage: %s pvdname server_addr\n pvdname null/none for not binding to any pvd\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcasecmp(argv[1], "null") && strcasecmp(argv[1], "none")) {
        printf("Trying to bind to %s\n", argv[1]);
        /* proc_bind_to_pvd exposed in libpvd.h, more in repo pvd-dev */
        if (proc_bind_to_pvd(argv[1]) < 0) {
            printf("Binding to %s failed\n", argv[1]);
            return EXIT_FAILURE;
        }

        char pvdname[256];
        proc_get_bound_pvd(pvdname);

        if (strcmp(pvdname, argv[1]) == 0) {
            printf("Process is successfully bound to pvd %s\n", argv[1]);
        } else {
            if (proc_bind_to_nopvd() < 0) {
                printf("Process failed binding to pvd %s and as well as failed unbinding\n", argv[1]);
                return EXIT_FAILURE;
            } else {
                printf("Process failed binding to pvd %s, thus remain unbound to any pvd\n", argv[1]);
            }
        }
    }

    sock_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

    /* standard socket communication in the following up */

}
```
More on PvD-aware application development can be found in [pvd-dev](https://github.com/IPv6-mPvD/pvd-dev.git).

One possible improvement to/change on the patch is to verify whether the PvD actually exisits when binding a thread/process to it, by simply calling _pvd_get_by_name_rcu()_ in _sock_setbindtopvd()_. As a matter of fact, _sock_setbindtopvd()_ does already similar verification for socket level PvD binding:
```c
int sock_setbindtopvd(
		struct sock *sk,
		char __user *optval,
		int optlen)
{
    /* many things skipped */
    socket_scope :
    /* many things skipped */

        /* pvd_get_by_name_rcu doesn't hold PvD reference */
        if (! (pvd = pvd_get_by_name_rcu(net, pvdname, NULL, NULL))) {
			sk->sk_pvd_bind_type = PVD_BIND_NOPVD;
			ret = -ENETUNREACH;
		}
		else {
			sk->sk_bound_pvd = pvd_get_fullindex(pvd);
		}

        /* many things skipped */
    return ret;
}
```
Correspondingly, the PvD related data structure amendement to __struct__ _sock_ in _include/net/sock.h_ is a bit different from that of __strucut__ _task_struct_.
```c
struct sock {
    /* attributes omitted */
#ifdef	CONFIG_NETPVD
	int			skc_pvd_bind_type;	/* 0 : inherit, 1 : unset, 2 : set */
	int			skc_bound_pvd;		/* pvd index if type == 2 */
#endif
    /* attributes omitted */
}
```
Instead of referencing to the the name of the attaching PvD, __struct__ _sock_ remembers the PvD index.

__struct__ _task_struct_ and __struct__ _sock_ are both very important structures in kernel. It would be great to discuss with kernel maintainers on the best approach incorprating PvD info in them and on the behaviour of binding to non existant PvD.

One missing feature on current patch is that: the binding of of thread/process/socket to multiple PvDs. This feature does not only deals with the PvD data structure in __struct__ _task_struct_ and __struct__ _sock_, but as well how PvD is enforced when performing route lookup and source address selection which will be discussed in detail later on.

# PvD reference held by other data structures -- a view from PvD destruction process

From a data structure point of view, making the kernel aware of PvD is to make certain kernel structures aware of its PvD context.
What happens to __struct__ _task_struct_ and __struct__ _sock_ (the above section) is just a part of the stroy.
How these structs hold and release the PvD reference impacts the destrcution of PvD data structure in kernel, either by garbage collection or by explicit command. 

Here below is an exhaustive list of structures in kernel that have been ammended in this patch so that they can be associated to a PvD:
* __struct__ _task_struct_ in _include/linux/sched.h_;
* __struct__ _sock_ in _include/net/sock.h_;
* __struct__ _flowi6_ in _include/net/flow.h_;
* __struct__ _inet6_ifaddr_ in _include/net/if_inet6.h_;
* __struct__ _fib6_config_ in include/net/ip6_fib.h;
* __struct__ _rt6_info_ in include/net/ip6_fib.h.

As discussed in earlier, __struct__ _task_struct_ and __struct__ _sock_ do not hold reference to __struct__ _net_pvd_ instances.
It is thus possible that they store names and indexes referring to non-existing PvDs.

__struct__ _flowi6_ holds the PvD reference, and releases it as soon as route lookup and source address selection is done.

__struct__ _inet6_ifaddr_ holds PvD reference, and it is forced to release the reference by migrating to a NULL PvD when get removed, via a call to __function__ _pvd_migrate_addr()_ defined in _net/core/pvd.c_.
Similarily, __struct__ _rt6_info_ holds as well PvD reference, and releases it when removed through a call to __function__ _pvd_migrate_route()_ implmented in _net/core/pvd.c_.

__struct__ _fib6_config_ is an intermediate structure (my personal understanding) for creating a route. A concerned call path is when the kernel receives an RA with PIO, the kernel creates a route for the prefix of the PIO. The whole call path is given as the follow:
1. __function__ _ndisc_router_discovery()_ in _net/ipv6/ndisc.c_;
2. __function__ _addrconf_prefix_rcv()_ in _net/ipv6/addrconf.c_;
3. __function__ _addrconf_prefix_route()_ in _net/ipv6/addrconf.c_, here a variable of __struct__ _fib_config_ in type is created and given the PvD pointer;
4. __function__ _ip6_route_add()_ in _net/ipv6/route.c_;
5. __function__ _ip6_route_info_create()_ in _net/ip6/route.c_, here a route is created according to the _fib_config_ "template", and migrate to the the PvD specified by the _fib_config_ parameter.

We can see that the PvD pointer __struct__ _fib6_config_ is eventually held by __struct__ _rt6_info_.

# PvD-aware IP forwarding and its relation to PBR, VRF/l3 domain
So far, we have seen that many data structual changes have been made to mark the presence of PvD in kernel.
But what are they for?

The main feature of this patch can be roughly cut into following pieces:
1. PvD discovery as a part of router discovery: associate each default route, prefix route, RIO route, address from PIO with A-flag to a correspoinding PvD;
2. PvD subsystem: manages the creation, deletion, as well as the association of PvD with other data strucutres;
3. API and kernel implementation for binding a thread/process/socket to a subset of PvDs;
4. API and kernel implemetation for querying and manipulating PvD datastructures in kernel.
5. PvD-aware IP forwarding: PvD-specific route lookup and source address selection;

As a matter of fact, PvD-aware IP forwarding is the core/ultimate purpose of all the above listed functions. All the rest can be regarded as preparations for the this final hit.

## PvD-aware IP forwarding
PvD-aware IP forwarding is composed of two parts: route lookup and source address selection.
In both parts, a route or an addressed can only be selected for IP forwarding if they satisfy
the PvD association specified by the application context, i.e. thread/process/socket PvD binding.

More concretely, when a thread/process/socket is bound to no PvD, the kernel selects among all the avaible routes regardless their PvD association (just as what we do today), then picks the source address whose PvD matches the selected route (among other rules). Therefore the PvD feature in this patch can be seen as an implementation for the "famous" rule 5.5 defined in [RFC6724](https://tools.ietf.org/html/rfc6724).

When a thread/process/socket is bound to one single PvD, the kernel should only employ the routes and source addresses associated to the specified PvD.

When a thread/process/socket is bound to multiple PvDs (not implemented), the kernel should:
1. either first tie break among avaible PvDs, via middleware, a transport scheduler, etc., then follow the principal of the case with singel PvD;
2. either directly select among all routes whose associated PvD is within the specified PvD set, then pick the source address accordingly.

What does it take to fullfill the above IP forwarding behaviour?
We first disucss the possibility of realising them using existing techniques and tools, then move on to the implementation given by this patch.

## Can PvD-aware IP forwarding be implemented as Policy Based Routing?
The basic idea is leverage the multiple routing table feature:
1. create a routing table per PvD, and populate this routing table with routes belonging to this PvD.
2. Attach the table to a fwmark rule;
3. tag per-process traffic with cgroups;
4. fwmark traffic with netfilter according their cgroups,example [here](https://www.evolware.org/?p=369);

In case multiple or all PvD need to be considered, multiple routing tables can be chained up according to their priorities.

The fatal issue of this approach is that it doesn't address the PvD compliance in source address selection.

## Can PvD-aware IP forwarding be implemented with VRF, or rather a L3 master device?
Can a PvD be regarded as a VRF device with is own routing table?

## The implementation in this patch

## Issue with the fib trie traversal

## What happens removing a PvD while its previous address and routing still in use? 
## Does incoming traffic has PvD attachment? If a server app bound to a PvD, how the kernel routes incoming traffic?
## What happens we change the socket PvD binding during a connection?

# neighbour discovery and associating routes and addresses to a PvD

# PvD management via rtnetlink

# address, route config via ioctl and rtnetlink

__struct__ _in6_ifreq_ in _include/uapi/linux/ipv6.h_ should (NOT DONE) as well have a PvD related field. _inet6_ioctl_ calls _addrconf_add_ifaddr_ to add an
IPv6 address to a certain interface. 
The _ioctl_ caller in userspace might want to specify the PvD attachment of this added IPv6 address.
_addrconf_add_ifaddr_ casts user space request into __struct__ _in6_ifreq_ and calls _inet6_addr_add_ to do the real job. _inet6_addr_add_ takes a PvD pointer (currently set to NULL) which shall be derived from __struct__ _in6_ifreq_.


# net_device removal
Discuss the reference of other datas tructures held by net_pvd.


# ifdef pre-prossesor

