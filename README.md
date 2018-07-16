This document aims at:
1. clarifing a bit the code design of this patch in fulfilling the PvD feature;
2. exposing some un-addressed issues regarding this patch: what is the problem, potential solutions, pro/con/cost of the soltions;

Such that experienced users or future devoloppers can easily pick it up and push it further.

Since the end of 2017, there has been continuous [IETF efforts](https://tools.ietf.org/html/draft-bruneau-intarea-provisioning-domains-02) 
to standardize a mechanism of discoverying (for host)/advertising(for network) [Provision Domains](https://tools.ietf.org/html/rfc7556) (PvD) via IPv6 Router Advertisement (RA).

This Linux kernel patch mainly implements:
* __neighbour discovery:__ parsing of RAs containing PvD Option; associating IPv6 addresses and routes to a certain PvD;
* __socket/thread/process binding__: setsockopt options to bind a socket/thread/process to a specified PvD;
* __IPv6 route & source address selection:__ IPv6 route selection in compliance with socket PvD binding; IPv6 source address selection in compliance with route PvD association; the PvD-aware source address selection behaviour can be regarded as an implementation for rule 5.5 defined in [RFC6724](https://tools.ietf.org/html/rfc6724).

Table of Contents
=================

* [Table of Contents](#table-of-contents)
* [Usage of this patch](#usage-of-this-patch)
* [PvD data structure in network namespace](#pvd-data-structure-in-network-namespace)
* [Bind a thread/process/socket to a PvD](#bind-a-threadprocesssocket-to-a-pvd)
* [PvD pointer held by other data structures](#pvd-pointer-held-by-other-data-structures)
* [PvD\-aware IP forwarding and its relation to PBR, VRF/l3 domain](#pvd-aware-ip-forwarding-and-its-relation-to-pbr-vrfl3-domain)
  * [PvD\-aware IP forwarding](#pvd-aware-ip-forwarding)
  * [Can PvD\-aware IP forwarding be implemented as Policy Based Routing?](#can-pvd-aware-ip-forwarding-be-implemented-as-policy-based-routing)
  * [Can PvD\-aware IP forwarding be implemented with VRF/L3 master device?](#can-pvd-aware-ip-forwarding-be-implemented-with-vrfl3-master-device)
  * [The implementation in this patch](#the-implementation-in-this-patch)
* [Parsing PvD option in RA](#parsing-pvd-option-in-ra)
* [PvD notification and management](#pvd-notification-and-management)
* [address, route config via ioctl and rtnetlink](#address-route-config-via-ioctl-and-rtnetlink)
* [PvD datastructure in kernel and the pointers it holds](#pvd-datastructure-in-kernel-and-the-pointers-it-holds)
* [ifdef pre\-prossesor](#ifdef-pre-prossesor)
# Usage of this patch

The patch in this k415 branch is build upon Ubuntu 1804 LTS source tree (commit hash: 1221ffab3e8e42c17c6c54cf60e037abd76e199a), and should be applied to 4.15 kernels.

The PvD feature is controlled by the Kernel configuration option CONFIG_NETPVD under _drivers->net_ (doesn't seem to me as the most fitting place).

The feature can be activated (by default)/deactivated on a per interface base through sytsctl entry _net.conf.ipv6.[interface].parse_pvd_. (NOTE: like _accepte_ra_ entry, there is no handler implemented for __all__ interface.)

A tutorial on how to apply this patch and run PvD-aware applications on top of it can be found in [pvd-dev](https://github.com/IPv6-mPvD/pvd-dev.git).

# PvD data structure in network namespace

[Network namespace](https://lwn.net/Articles/531114/), like other linux namespaces, provides resource isolation, assoicated with networking, e.g. network devices, IP addresses and routing tables.
Accordingly, it is all fitting and even necessary that each network namespace has its individual view of PvD. To that end, this patch adds PvD-related data structure to network namespace data strucutre and manges them in a way similar to how current kernel manages network devices: __struct__ _net_device_.

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
Apart from the non-intuitive (at least for me) approach, the main draw back is that since they are not built-in data structures such as linked-list, protecting them from concurrent access can rely on the RCU mechanism, instead RWLOCK is used.

A better practice would be to mimic how __net_device__ is managed in network namespace, more in __net/core/dev.c__.
Fundementally, this implies (not exhaustive): 
1. incorporate __list_head__ in __struct__ _net_pvd_ defined in _include/net/pvd.h_;
2. change the way pvdindex is generated, this and following changes deal with _net/core/pvd.c_;
3. change the way a pvd is added to and removed from the network namespace using rcu primitives;
4. change the way a pvd is searched by it name, pvdindex, associating device, etc, using rcu primitives.

# Bind a thread/process/socket to a PvD
The action of binding a thread/process/socket to a PvD dictates that the network traffic associated to the thread/process/socket is only allowed to use the routes, source addresses (managed in kernel) and DNS serverses (managed in userspace, say by [glibc](https://github.com/IPv6-mPvD/glibc.git)) attached to the PvD.

> [Out-of-scope comment] A PvD-aware application should then be at least capable of:
>1. learning about the avaiable PvDs and their attribites and characteristics;
>2. bind its child processes/threads, or sockets to one or some PvDs according to its application delivery needs (NOTE: the PvD binding of thread and process may change over their lifetime. What happens if we change the PvD binding of TCP socket during its lifetime?).

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
char pvdname[256];
proc_get_bound_pvd(pvdname);

if (strcmp(pvdname, target_pvd) == 0) {
    printf("Process is successfully bound to pvd %s\n", argv[1]);
} else {
    if (proc_bind_to_nopvd() < 0) {
        printf("Process failed binding to pvd %s and as well as failed unbinding\n", argv[1]);
        return EXIT_FAILURE;
    } else {
        printf("Process failed binding to pvd %s, thus remain unbound to any pvd\n", argv[1]);
    }
}
```
More on PvD-aware application development can be found in [glibc/test](https://github.com/MiDiBa/glibc-mPvD).

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

# PvD pointer held by other data structures

From a data structure point of view, making the kernel aware of PvD is to make certain kernel structures aware of its PvD context.
What happens to __struct__ _task_struct_ and __struct__ _sock_ (the above section) is just a part of the stroy.
How these structs hold and release the PvD pointers impacts the life cycle of PvD datastructures in kernel.

Here below is an exhaustive list of structures that are ammended in this patch so that they can be associated to a PvD:
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

__struct__ _fib6_config_ is an intermediate structure (my personal understanding) to route creation. A concerned call path is when the kernel receives an RA with PIO, the kernel creates a route for the prefix of the PIO. The whole call path is given as the follow:
1. __function__ _ndisc_router_discovery()_ in _net/ipv6/ndisc.c_;
2. __function__ _addrconf_prefix_rcv()_ in _net/ipv6/addrconf.c_;
3. __function__ _addrconf_prefix_route()_ in _net/ipv6/addrconf.c_, here a variable of __struct__ _fib_config_ in type is created and given the PvD pointer;
4. __function__ _ip6_route_add()_ in _net/ipv6/route.c_;
5. __function__ _ip6_route_info_create()_ in _net/ip6/route.c_, here a route is created according to the _fib_config_ "template", and migrate to the the PvD specified by the _fib_config_ parameter.

We can see that the PvD pointer __struct__ _fib6_config_ is eventually held by __struct__ _rt6_info_.

# PvD-aware IP forwarding and its relation to PBR, VRF/l3 domain
So far, we have seen that many datastructual changes have been made to mark the presence of PvD in kernel.
But what are they for?

The main feature of this patch can be roughly cut into following pieces:
1. PvD discovery as a part of router discovery: associate each default route, prefix route, RIO route, address from PIO with A-flag to a correspoinding PvD (NOTE: need extend to other RA options in the future);
2. PvD module: manages the creation, deletion, as well as the association of PvD with other data strucutres;
3. API and kernel implementation for binding a thread/process/socket to a subset of PvDs;
4. API and kernel implemetation for querying and manipulating PvD attributes;
5. PvD-aware IP forwarding: PvD-specific route lookup and source address selection;

As a matter of fact, PvD-aware IP forwarding is the core/ultimate purpose of all the above listed functions. All the rest can be regarded as preparations for the this final hit.

## PvD-aware IP forwarding
PvD-aware IP forwarding is composed of two parts: route lookup and source address selection.
In both parts, a route or an addressed can only be selected and employed for IP forwarding if its PvD association satisfies the the application context, i.e. thread/process/socket PvD binding.

More concretely, when a thread/process/socket is bound to no PvD, the kernel selects among all the avaible routes regardless their PvD association (just as what we do today), then picks the source address whose PvD matches the selected route (among other rules). Therefore the PvD feature in this patch can be seen as an implementation for the "famous" rule 5.5 defined in [RFC6724](https://tools.ietf.org/html/rfc6724).

When a thread/process/socket is bound to one single PvD, the kernel should only employ the routes and source addresses associated to the specified PvD.

When a thread/process/socket is bound to multiple PvDs (not yet implemented), the kernel should:
1. either first tie break among avaible PvDs, via middleware, a transport scheduler, etc., then follow the principal of the case with singel PvD;
2. either directly select among all routes whose associated PvD is within the specified PvD set, then pick the source address accordingly (closer to the procedure of binding to no PvD).

What does it take to fullfill the above IP forwarding behaviour?
We first disucss the possibilities of realising them using existing techniques and tools, then move on to the implementation given by this patch.

## Can PvD-aware IP forwarding be implemented as Policy Based Routing?
The basic idea is to leverage the multiple routing table feature:
1. create a routing table per PvD, and populate this routing table with routes belonging to this PvD.
2. Attach the table to a fwmark rule;
3. tag per-process traffic with [cgroup](https://lwn.net/Articles/679786/);
4. fwmark traffic with netfilter according their cgroup,example [here](https://www.evolware.org/?p=369);

In case multiple or all PvDs need to be considered, multiple routing tables can be chained up according to their priorities.

The fatal issue of this approach is that it doesn't address the PvD compliance in source address selection.

## Can PvD-aware IP forwarding be implemented with VRF/L3 master device?
Pushing the idea of one-routing-tabel-per-PvD further and addressing the issue of source address selection, one might naturally think of implementing PvD as a VRF.

When each interface on a host is exposed to at most one PvD (explicit and implicit), i.e. between any two PvD VRF their enslaving devices have no intersection, the approach is quite straightforward:
1. handle received PvD as a VRF/L3 master device;
2. enslave the interfaces receiving RA containing that PvD;
3. populate VRF routing table with routes generated by the concerned RA(s);
4. bind socket to PvD VRF, so that route lookup and source address selection only happens within the specified VRF L3 domain.

In order to bind to multiple PvDs, an application (itself or via a middleware) has to first tie break among the mulitple VRF choices.

Since each device can only be enslved by at most one VRF/L3 master device, this VRF appraoch becomes ill-fitting when an interface may receive multiple PvDs. This is actualy one driving case for the deployment of PvD, IPv6 multi-homing stub sites (e.g. entreprise network) exposing mulitple upstream providers (pure connection provider or application/service provider) to endhosts in the form of multiple defualt routes/next hops on each of their interfaces.

An "ugly trick" though may work: for devices exposed to multiple PvDs, creat for each PvD a virtual interface and bridge it to the physical one. Each virtual interface is addressed with corresponding PvD options and enslaved to corresponding PvD VRF.
This trick may complicate a lot the router discovery process, more specifically regarding device addressing:
* when a phyiscal devices receives an RA it has first to discover all the PvDs, then spawn virtual devices if necessary, and eventually creat addresses and routes associated to it;
* spawned virtual interface creats addresses and routes accoridng to its L3 domain association.

The fundemental misfit of VRF with PvD is that there could acutally be a n*m mapping relationship between interfaces and PvDs, i.e. one PvD can present on multiple interfaces, while multiple PvDs may as well be present on a single interface.

## The implementation in this patch
According to the earlier discussion on kernel data strucutre change, we regard PvD rather as a tag attached to flows, addresses and routes. This results minimum changes in implementing PvD-aware IP forwarding in a fairely nature way: add PvD matching test when performaning route lookup and source address selection.

More concretely, route lookup is composed of two big steps (once we know which table to look at) according to __function__ _ip6_pol_route()_ implemented in _net/ipv6_route.c_ (NOTE: __function__ _ip6_pol_route_lookup()_ is another route lookup API only used by netfilter; its call path won't be explained here):
1. traverse the FIB trie (longest prefix matching) via a call to __function__ _fib6_lookup()_ then _fib6_lookup_1()_ defined in _net/ipv6/ip6_fib.c_ which returns a _fib6_node_ that contains pointer(s) to __struct__ _rt6_info_ (if RTN_RTINFO flag set for this _fib6_node_). A more detail explanation can be found [here](https://vincent.bernat.im/en/blog/2017-ipv6-route-lookup-linux). Most importantly, this patch changes nothing at this step.
2. from the _fib_node_, select the best fitting route. Round-robin among routes of same metric, multipath routing (what's the difference between the two?), lookup in route cache, etc. may be involved in this step.
This patch forces the selection of _rt6_info_ holding the specified PvD refernce in 
__function__ _find_rr_leaf()_ along the call path from __function__ _rt6_select()_.

>If FIB trie traversal lands on a _fib6_node_ contains not route with matching PvD, _ip6_pol_route()_ goes upward in the fib trie, i.e. fib node with shorter prefix matching length, via a call to __function__ _fib_backtrack()_.

When it deals with source address selection, the patch imposes the PvD compliance by completing the rule 5 in __function__ _ipv6_get_saddr_eval()_ defined in _net/ipv6/addrconf.c_:
```c
static int ipv6_get_saddr_eval(struct net *net,
			       struct ipv6_saddr_score *score,
			       struct ipv6_saddr_dst *dst,
			       int i)
{
	/*lines omitted*/
	case IPV6_SADDR_RULE_OIF:
		/* Rule 5: Prefer pvd (if specified) then outgoing interface */
#ifdef	CONFIG_NETPVD
	    	if (dst->pvd != NULL && dst->pvd != score->ifa->pvd) {
			ret = 0;
			break;
		}
#endif
		ret = (!dst->ifindex ||
		       dst->ifindex == score->ifa->idev->dev->ifindex);
		break;
	/*lines omitted*/
}
```

## Q&A
### What happens removing a PvD while its previous address and routing still in use?
It depends on whether the route lookup and source address selection result is cached in socket or not.

### Does incoming traffic has PvD attachment? If a server app is bound to a PvD, how the kernel routes incoming traffic?
TODO

### What happens we change the socket PvD binding during a connection?
Let's first see what happens if we change the device binding of a TCP connection.

# Parsing PvD option in RA
The PvD association of IPv6 routes and addresses is a result of rotuer discovery, i.e. parsing of RA.
According to [current draft](https://tools.ietf.org/html/draft-ietf-intarea-provisioning-domains-02),
each RA can contain at most one PvD option. Each PvD option can embed RA options.

When an RA contains no PvD option, all the routes (default routes, PIO routes, RIO routes
) and addresess(auto config from PIO) are associated to a PvD identified by the LLA of the router and the host interface receving the RA. Such PvD is known as implict PvD.

When an RA contains an PvD option, all the routes and addresses (no matter in or outside the PvD option)
are associate to the PvD identified by its PvD ID. The patch parses ND options in RA in order, no matter in or outside the PvD option. PvD-unware hosts ignores the entire PvD option "container", while PvD-aware hosts can look into the PvD option "container" and parse ND options there.

In order to fulfill the above behaviour, the patch made following changes to _net/ipv6/ndisc.c_:
1. a parser for PvD option and ND options inside __function__ _pvdid_parse_opt()_;
2. __function__ _ndisc_parse_options()_ is modified to handle PvD option;
3. __function__ _ndisc_router_discovery()_ is modified to create PvD object and associte routes and addresses to it;
4. __function__ _ndisc_next_option()_ and _ndisc_next_useropt()_ are modified to iterate ND options inside PvD option "container".

# PvD notification and management
Currently we can receive updates on PvD status, RDNS, DNSSL update via rtnetlink. Message code defined in _inlcude/uapi/linux/rtnetlink.h_:
```c
/*many line omitted*/
RTM_PVDSTATUS = 100,
#define RTM_PVDSTATUS RTM_PVDSTATUS
	RTM_RDNSS = 101,
#define RTM_RDNSS RTM_RDNSS
	RTM_DNSSL = 102,
#define RTM_DNSSL RTM_DNSSL

	__RTM_MAX,
#define RTM_MAX		(((__RTM_MAX + 3) & ~3) - 1)
};
/*many line omitted*/
```

However, the creation, deletion, and attribute query to a PvD are actually done via set/getsockopt options. Option types are defined in _include/upai/asm-generic/socket.h_:
```c
#define	SO_BINDTOPVD		61
#define	SO_GETPVDLIST		62
#define	SO_GETPVDATTRIBUTES	63
#define	SO_CREATEPVD		64
```
The implementation for these options can be found in _net/core/pvd.c_.

The ideal would be rather via rtnetlink. This requries:
* defining PvD message attributes;
* add RTM message definition; the attributes could include addresses and routes;
* register handler for these messages;
* change the current implementation output.

# address, route config via ioctl and rtnetlink

Apart from PvD assocaition obtained from RA parsing, it is as well possible to create addresses and routes with PvD association via rtnetlink, RTM_NEWROUTE and RTM_NEWADDR separatly.
Route message attributes are extended in _inlcude/uapi/linux/rtnetlink.h_, while address message attributes are extended in _inlcude/uapi/linux/if_addr.h_.
Corresponding handlers are hence as well modified:
* __function__ _inet6_rtm_newaddr()_ is a handler registered in _net/ipv6/addrconf.c_ for RTM_NEWADDR message;
* __function__ _inet6_rtm_newroute()_ in _net/ipv6/route.c_ for RTM_NEWROUTE remain unchanged, yet on its call path __function__ _rtm_to_fib6_config()_ defined in the same file has been changed.

__struct__ _in6_ifreq_ in _include/uapi/linux/ipv6.h_ should (NOT DONE) as well have a PvD related field. _inet6_ioctl_ calls _addrconf_add_ifaddr_ to add an
IPv6 address to a certain interface. 
The _ioctl_ caller in userspace might want to specify the PvD attachment of this added IPv6 address.
_addrconf_add_ifaddr_ casts user space request into __struct__ _in6_ifreq_ and calls _inet6_addr_add_ to do the real job. _inet6_addr_add_ takes a PvD pointer (currently set to NULL) which shall be derived from __struct__ _in6_ifreq_.

# PvD datastructure in kernel and the pointers it holds
Last but not least, let's have a look at how a PvD object looks like in kernel.
__struct__ _net_pvd_ is defined in _include/net/pvd.h_:
```c
struct net_pvd {
	struct net_pvd		*next;

	char			name[PVDNAMSIZ];
	struct hlist_node	name_hlist;
	int __percpu		*pcpu_refcnt;
	u32			pvdindex;	/* unique number */
	int			_index;		/* index in net->pvd_used_slots */
	int			notifications_blocked;

	/*
	 * Attributes of the pvd
	 */
	int			sequence_number;
	int			h_flag;
	int			l_flag;
	int 		a_flag;  /* introduced in draft 01 */
	int			implicit_flag;

	possible_net_t		nd_net;

	struct net_device	*dev;	/* the device it has been received on */
	struct in6_addr		lla;	/* the associated router lla */
	int			nroutes;
	struct rt6_info		*routes[MAXROUTESPERPVD];
	int			naddresses;
	struct inet6_ifaddr	*addresses[MAXADDRPERPVD];
	
	int			ndnssl;
	char			*dnssl[MAXDNSSLPERPVD];
	unsigned long		dnsslExpire[MAXDNSSLPERPVD];


	int			nrdnss;
	struct in6_addr		rdnss[MAXRDNSSPERPVD];
	unsigned long		rdnssExpire[MAXRDNSSPERPVD];

#ifdef CONFIG_NETPVD
	/*
	 * pvd.d/
	 * 	<pvdname>/
	 * 		attrs
	 * 		routes
	 * 		addrs
	 * 		sockets
	 */
	struct proc_dir_entry 	*proc_pvd;		/* dir */
	struct proc_dir_entry 	*proc_pvd_attrs;	/* file */
	struct proc_dir_entry 	*proc_pvd_routes;	/* file */
	struct proc_dir_entry 	*proc_pvd_addrs;	/* file */
	struct proc_dir_entry 	*proc_pvd_rdnss;	/* file */
	struct proc_dir_entry 	*proc_pvd_dnssl;	/* file */
	struct proc_dir_entry 	*proc_pvd_sockets;	/* file */
#endif
};
```
We can see form above that a PvD object might hold pointer to the _net_device_ via which it is received, addresses and routes attached to it. dnssl and rdnss are not kernel data strucutres, and we are not going to cover them here.

As explained earlier, when address or route get removed, _pvd_migrate_addr()_ and _pvd_migrate_route()_ (sep.) are called to release the PvD pointer they hold.
The two migrations function update the address and route list in _net_pvd_ structure correspodningly, so that _net_pvd_ won't refer to freed pointers.

It is a bit different when it deals with _net_device_ pointer.
Only implicit PvD holds the device pointer, as its creation and existence partially relies on the existence of the device.
Explicit PvD has its device pointer set to NULL. 
The device pointer held by _net_pvd_ is only relased at the removal of a PvD. 
This implies a removal of _net_device_, or other operation resulting a removal of _net_device_ say removal of a network namespace, might be blocked the presence of PvD that can only be removed via setscockopt call. 

The ideal would be implemeting a device event handler for NETDEV_UNREGISTER and NETDEV_UNREGISTER_FINAL. 
For example, upon the removal of a _net_device_, we remove automatically the PvDs relying on that interface as well. As a matter of fact, a tentative implementation (not used) is present in this patch __function__ _pvd_netdev_event()_ in _net/core/pvd.c_. However the registeration fails when initating the PvD module at boot phase for reasons currently unknown to the auther.

# ifdef pre-prossesor
Which codes should be enclosed in ifdef-pre-prossesor CONFIG_NETPVD?

