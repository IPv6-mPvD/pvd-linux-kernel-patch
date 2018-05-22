The patch is functional, yet still far from perfect.
Here a list of potential issues.

# stale README

The patch in this k415 branch is build upon Ubuntu 1804 LTS source, and should be applied to 4.15 kernels.

Will correct it before official release.
Reference the pvd-dev project on how to use this patch.

# PvD data structure in network namespace

In _include/net/net_namespace.h_, we can find the definition of __struct__ _net_ for each network namespace. 
Thist patch adds attributes relating to PvD to this strucutre so that each network namespace has its own view on PvD.
These attributes are enclosed in __CONFIG_NETPVD__ ifdef pre-processor:
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
	/* WQ: why a single linked list of pvds won't suffice? */
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

The current pvd related data structure is basically a growable array with max size equal to MAXPVD.
Everytime a  PvD is added to or removed from a network namesapce, __pvd_used_slots__, __pvd_free_slots__, __first_free_pvd_ix__, __first_used_pvd__ need to be potentially updated.
To really understand how they are manuipulated, __register_pvd()__ and __unregister_pvd()__ in _net/core/pvd.c_ would be a good starting point.
Apart from the non-intuitive (at least for me) approach, the main draw back is that since they are not simply built-in data structures such as link-list, protecting them from concurrent access is painful and error prone.

A better practice would be to mimic how __net_device__ is managed in network namespace, more in __net/core/dev.c__.
Foundementally, this implies (not exhaustive): 
1. incorporate __list_head__ in __net_pvd__ defined in _include/net/pvd.h_;
2. change the way pvdindex is generated, this and following change deals with _net/core/pvd.c_;
3. add hash fucntions to generate pvd identifiers;
4. change the way a pvd is added to and removed from the network namespace using rcu primitives;
5. change the way a pvd is searched by it name, pvdindex, associating device, etc, using rcu primitives.

# Bind a thread/process/socket to a PvD

The action of binding a thread/process/socket to a PvD dictates that the network traffic associated to the thread/process/socket is only allowed to use the routes, source addresses (managed in kernel) and DNS serverses (managed in userspace, say by [glibc](https://github.com/IPv6-mPvD/glibc.git)) attached to the PvD.
By default, that is without any specification, socket inherits the binding of current thread, thread/process inherits the binding of its parent.
A special binding status is binding to no PvD, which permits a thread/process/socket to use whatever route, addresses, regardless their PvD association.

This patch brings data strucutre amendments to realize the above described behaviour.
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
A char pointer _bound_pvd_ is added to the massive _task_struct_ to showcase its PvD binding status.
The value of this point is set to `((void *) 0)` when a thread/process inherts PvD binding from its parent; to `((void *) -1)` when a thread/process binds to no PvD.
In order to explicitly bind a thread/process to a PvD, __function__ _sock_setbindtopvd()_ (implemented in  _net/core_pvd.c_) will be called.
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
Basically, the task_struct will learn the string containing the PvD name, a full qualified domain name (FQDN) when regarding an explicit PvD.
The problem of the above code is that it doesn't verify whether the __string__ _pvdname_ corresponds to a currently existing PvD in the kernel.
As a matter of fact, a thread/process can be asked to bind to an arbitray string as PvD without any immediate error!

So how the PvD binding status of a thread/process is reflected in the choice of route and source address? And what's the consequence in these choices when bound to a non-existant PvD? Let's look one possible code path via TCP connection creation, implemented in _net/ipv6/tcp_ipv6.c_.
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
It is via a call to _pvd_getboundpvd_, the corresponding __struct__ _flowi6_ (defined in _inlcude/net/flow.h_) learns the PvD binding of the current socket, which might eventually depend on the PvD binding of current thread/process or its parent. Later on, route and source address selection are performaned in awareness of the PvD pointer of _fl6_.
_pvd_getboundpvd_ will return with error code network unreachable, if the 1/ the socket PvD binding depends on its parent thread/process and 2/ the later binds to a non-existant PvD. More concretely in _net/core/pvd.c_:
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
This behaviour could be very annoying: an application will loose network connection because end-user or application itself carelessly forces the binding to a non-existatn PvD or a PvD have just disapeared.
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

One possible improvement/change is to verify whether the PvD actually exisits when binding a thread/process to it, by simply calling _pvd_get_by_name()_ in _sock_setbindtopvd()_. As a matter of fact, _sock_setbindtopvd()_ does already similar verification for socket level PvD binding:
```c
int sock_setbindtopvd(
		struct sock *sk,
		char __user *optval,
		int optlen)
{
    /* many things skipped */
    socket_scope :
    /* many things skipped */

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
Correspondingly, the PvD related data structure amendement to __struct__ _sock_ in _include/net/sock.h_ is a bit different from that of __strucut__ _task_struct__.
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

__struct__ _task_struct_ and __struct__ _sock_ are both very important structures in kernel. It would be great to discuss with kernel maintainers on the best approach incorprating PvD info in them and on the behaviour of binding to non existant PvD.

# Unregister PvD
Discuss the pvd referece in other data strucutre.

What happens unregistering a PvD while there is still thread/process/socket bound to it?

# net_device removal
Discuss the reference of other datas tructures held by net_pvd.


# ifdef pre-prossesor

# 
