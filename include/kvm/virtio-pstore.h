#ifndef KVM__PSTORE_VIRTIO_H
#define KVM__PSTORE_VIRTIO_H

struct kvm;

#define VIRTIO_PSTORE_TYPE_UNKNOWN  0
#define VIRTIO_PSTORE_TYPE_DMESG    1

#define VIRTIO_PSTORE_CMD_NULL   0
#define VIRTIO_PSTORE_CMD_OPEN   1
#define VIRTIO_PSTORE_CMD_READ   2
#define VIRTIO_PSTORE_CMD_WRITE  3
#define VIRTIO_PSTORE_CMD_ERASE  4
#define VIRTIO_PSTORE_CMD_CLOSE  5

#define VIRTIO_PSTORE_FL_COMPRESSED  1

struct pstore_hdr {
	u64			id;
	u32			flags;
	u16			cmd;
	u16			type;
	u64			time_sec;
	u32			time_nsec;
	u32			unused;
};

int virtio_pstore__init(struct kvm *kvm);
int virtio_pstore__exit(struct kvm *kvm);

#endif /* KVM__PSTORE_VIRTIO_H */
