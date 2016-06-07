#ifndef KVM__PSTORE_VIRTIO_H
#define KVM__PSTORE_VIRTIO_H

#include <kvm/virtio.h>
#include <sys/types.h>

#define VIRTIO_PSTORE_CMD_NULL   0
#define VIRTIO_PSTORE_CMD_OPEN   1
#define VIRTIO_PSTORE_CMD_READ   2
#define VIRTIO_PSTORE_CMD_WRITE  3
#define VIRTIO_PSTORE_CMD_ERASE  4
#define VIRTIO_PSTORE_CMD_CLOSE  5

#define VIRTIO_PSTORE_TYPE_UNKNOWN  0
#define VIRTIO_PSTORE_TYPE_DMESG    1

#define VIRTIO_PSTORE_FL_COMPRESSED  1

struct virtio_pstore_req {
	__virtio16		cmd;
	__virtio16		type;
	__virtio32		flags;
	__virtio64		id;
	__virtio32		count;
	__virtio32		reserved;
};

struct virtio_pstore_res {
	__virtio16		cmd;
	__virtio16		type;
	__virtio32		ret;
};

struct virtio_pstore_fileinfo {
	__virtio64		id;
	__virtio32		count;
	__virtio16		type;
	__virtio16		unused;
	__virtio32		flags;
	__virtio32		len;
	__virtio64		time_sec;
	__virtio32		time_nsec;
	__virtio32		reserved;
};

struct virtio_pstore_config {
	__virtio32		bufsize;
};

int virtio_pstore__init(struct kvm *kvm);
int virtio_pstore__exit(struct kvm *kvm);

#endif /* KVM__PSTORE_VIRTIO_H */
