#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

struct ioctl_gntdev_grant_ref {
	/* The domain ID of the grant to be mapped. */
	uint32_t domid;
	/* The grant reference of the grant to be mapped. */
	uint32_t ref;
};

/*
 * Allocates a new page and creates a new grant reference.
 */
#define IOCTL_GNTALLOC_ALLOC_GREF \
_IOC(_IOC_NONE, 'G', 5, sizeof(struct ioctl_gntalloc_alloc_gref))
struct ioctl_gntalloc_alloc_gref {
	/* IN parameters */
	/* The ID of the domain to be given access to the grants. */
	uint16_t domid;
	/* Flags for this mapping */
	uint16_t flags;
	/* Number of pages to map */
	uint32_t count;
	/* OUT parameters */
	/* The offset to be used on a subsequent call to mmap(). */
	uint64_t index;
	/* The grant references of the newly created grant, one per page */
	/* Variable size, depending on count */
	uint32_t gref_ids[1];
};

#define GNTALLOC_FLAG_WRITABLE 1

/*
 * Deallocates the grant reference, allowing the associated page to be freed if
 * no other domains are using it.
 */
#define IOCTL_GNTALLOC_DEALLOC_GREF \
_IOC(_IOC_NONE, 'G', 6, sizeof(struct ioctl_gntalloc_dealloc_gref))
struct ioctl_gntalloc_dealloc_gref {
	/* IN parameters */
	/* The offset returned in the map operation */
	uint64_t index;
	/* Number of references to unmap */
	uint32_t count;
};

#define IOCTL_GNTDEV_MAP_GRANT_REF \
_IOC(_IOC_NONE, 'G', 0, sizeof(struct ioctl_gntdev_map_grant_ref))
struct ioctl_gntdev_map_grant_ref {
    /* IN parameters */
    /* The number of grants to be mapped. */
    uint32_t count;
    uint32_t pad;
    /* OUT parameters */
    /* The offset to be used on a subsequent call to mmap(). */
    uint64_t index;
    /* Variable IN parameter. */
    /* Array of grant references, of size @count. */
    struct ioctl_gntdev_grant_ref refs[1];
};
#define GNTDEV_MAP_WRITABLE 0x1

#define IOCTL_GNTDEV_UNMAP_GRANT_REF \
_IOC(_IOC_NONE, 'G', 1, sizeof(struct ioctl_gntdev_unmap_grant_ref))
struct ioctl_gntdev_unmap_grant_ref {
    /* IN parameters */
    /* The offset was returned by the corresponding map operation. */
    uint64_t index;
    /* The number of pages to be unmapped. */
    uint32_t count;
    uint32_t pad;
};

/*
 * Sets up an unmap notification within the page, so that the other side can do
 * cleanup if this side crashes. Required to implement cross-domain robust
 * mutexes or close notification on communication channels.
 *
 * Each mapped page only supports one notification; multiple calls referring to
 * the same page overwrite the previous notification. You must clear the
 * notification prior to the IOCTL_GNTALLOC_DEALLOC_GREF if you do not want it
 * to occur.
 */
#define IOCTL_GNTDEV_SET_UNMAP_NOTIFY \
_IOC(_IOC_NONE, 'G', 7, sizeof(struct ioctl_gntdev_unmap_notify))
struct ioctl_gntdev_unmap_notify {
	/* IN parameters */
	/* Index of a byte in the page */
	uint64_t index;
	/* Action(s) to take on unmap */
	uint32_t action;
	/* Event channel to notify */
	uint32_t event_channel_port;
};

/* Clear (set to zero) the byte specified by index */
#define UNMAP_NOTIFY_CLEAR_BYTE 0x1
/* Send an interrupt on the indicated event channel */
#define UNMAP_NOTIFY_SEND_EVENT 0x2

/*
 * Sets up an unmap notification within the page, so that the other side can do
 * cleanup if this side crashes. Required to implement cross-domain robust
 * mutexes or close notification on communication channels.
 *
 * Each mapped page only supports one notification; multiple calls referring to
 * the same page overwrite the previous notification. You must clear theb
 * notification prior to the IOCTL_GNTALLOC_DEALLOC_GREF if you do not want it
 * to occur.
 */
#define IOCTL_GNTALLOC_SET_UNMAP_NOTIFY \
_IOC(_IOC_NONE, 'G', 7, sizeof(struct ioctl_gntalloc_unmap_notify))
struct ioctl_gntalloc_unmap_notify {
	/* IN parameters */
	/* Index of a byte in the page */
	uint64_t index;
	/* Action(s) to take on unmap */
	uint32_t action;
	/* Event channel to notify */
	uint32_t event_channel_port;
};

/* Clear (set to zero) the byte specified by index */
#define UNMAP_NOTIFY_CLEAR_BYTE 0x1
/* Send an interrupt on the indicated event channel */
#define UNMAP_NOTIFY_SEND_EVENT 0x2

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
