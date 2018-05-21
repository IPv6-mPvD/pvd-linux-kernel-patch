The patch is functional, yet still far from perfect.
Here a list of potential issues are maintained.

# stale README

The patch in this k415 branch is build upon Ubuntu 1804 LTS source, and should be applied to 4.15 kernels.

Will correct it before official release.
Reference the pvd-dev project on how to use this patch.

# pvd structure in network namespace

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
1. incorporate __list_head__ in __net_pvd__ defined in  _include/net/pvd.h__;
2. change the way pvdindex is generated;
3. add hash fucntions to generate pvd identifiers;
4. change the way a pvd is added to and removed from the network namespace using rcu primitives;
5. change the way a pvd is searched by it name, pvdindex, associating device, etc, using rcu primitives.


