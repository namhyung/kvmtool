#include "kvm/virtio-pstore.h"

#include "kvm/virtio-pci-dev.h"

#include "kvm/virtio.h"
#include "kvm/util.h"
#include "kvm/kvm.h"
#include "kvm/threadpool.h"
#include "kvm/guest_compat.h"

#include <linux/virtio_ring.h>

#include <linux/list.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <linux/kernel.h>

#define NUM_VIRT_QUEUES			1
#define VIRTIO_PSTORE_QUEUE_SIZE	128

struct pstore_dev_job {
	struct virt_queue	*vq;
	struct pstore_dev	*pdev;
	struct thread_pool__job	job_id;
};

struct pstore_dev {
	struct list_head	list;
	struct virtio_device	vdev;

	int			fd;
	DIR			*dir;

	/* virtio queue */
	struct virt_queue	vqs[NUM_VIRT_QUEUES];
	struct pstore_dev_job	jobs[NUM_VIRT_QUEUES];
};

static LIST_HEAD(pdevs);
static int compat_id = -1;

static u8 *get_config(struct kvm *kvm, void *dev)
{
	/* Unused */
	return 0;
}

static u32 get_host_features(struct kvm *kvm, void *dev)
{
	/* Unused */
	return 0;
}

static void set_guest_features(struct kvm *kvm, void *dev, u32 features)
{
	/* Unused */
}

static void virtio_pstore_hdr_to_filename(struct kvm *kvm, struct pstore_hdr *hdr,
					  char *buf, size_t sz)
{
	const char *basename;

	switch (hdr->type) {
	case VIRTIO_PSTORE_TYPE_DMESG:
		basename = "dmesg";
		break;
	default:
		basename = "unknown";
		break;
	}

	snprintf(buf, sz, "%s/%s-%llu%s", kvm->cfg.pstore_path, basename,
		 hdr->id, hdr->flags & VIRTIO_PSTORE_FL_COMPRESSED ? ".enc.z" : "");
}

static void virtio_pstore_filename_to_hdr(struct kvm *kvm, struct pstore_hdr *hdr,
					  char *name, char *buf, size_t sz)
{
	size_t len = strlen(name);

	hdr->flags = 0;
	if (!strncmp(name + len - 6, ".enc.z", 6))
		hdr->flags |= VIRTIO_PSTORE_FL_COMPRESSED;

	snprintf(buf, sz, "%s/%s", kvm->cfg.pstore_path, name);

	if (!strncmp(name, "dmesg", 5)) {
		hdr->type = VIRTIO_PSTORE_TYPE_DMESG;
		name += 5;
	} else if (!strncmp(name, "unknown", 7)) {
		hdr->type = VIRTIO_PSTORE_TYPE_UNKNOWN;
		name += 7;
	}

	hdr->id = strtoul(name + 1, NULL, 0);
}

static int virtio_pstore_do_open(struct kvm *kvm, struct pstore_dev *pdev,
				 struct pstore_hdr *hdr, struct iovec *iov)
{
	pdev->dir = opendir(kvm->cfg.pstore_path);
	if (pdev->dir == NULL)
		return -errno;

	return 0;
}

static int virtio_pstore_do_close(struct kvm *kvm, struct pstore_dev *pdev,
				   struct pstore_hdr *hdr, struct iovec *iov)
{
	if (pdev->dir == NULL)
		return -1;

	closedir(pdev->dir);
	pdev->dir = NULL;

	return 0;
}

static ssize_t virtio_pstore_do_write(struct kvm *kvm, struct pstore_dev *pdev,
				      struct pstore_hdr *hdr, struct iovec *iov)
{
	char path[PATH_MAX];
	FILE *fp;
	ssize_t len = 0;

	virtio_pstore_hdr_to_filename(kvm, hdr, path, sizeof(path));

	fp = fopen(path, "a");
	if (fp == NULL)
		return -1;

	len = fwrite(iov[1].iov_base, iov[1].iov_len, 1, fp);
	if (len < 0 && errno == EAGAIN)
		len = 0;

	fclose(fp);
	return len;
}

static ssize_t virtio_pstore_do_read(struct kvm *kvm, struct pstore_dev *pdev,
				     struct pstore_hdr *hdr, struct iovec *iov)
{
	char path[PATH_MAX];
	FILE *fp;
	ssize_t len = 0;
	struct stat stbuf;
	struct dirent *dent;

	if (pdev->dir == NULL)
		return 0;

	dent = readdir(pdev->dir);
	while (dent) {
		if (dent->d_name[0] != '.')
			break;
		dent = readdir(pdev->dir);
	}

	if (dent == NULL)
		return 0;

	virtio_pstore_filename_to_hdr(kvm, hdr, dent->d_name, path, sizeof(path));
	if (stat(path, &stbuf) < 0)
		return -1;

	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;

	len = fread(iov[1].iov_base, 1, iov[1].iov_len, fp);
	if (len < 0 && errno == EAGAIN)
		len = 0;

	hdr->id  = virtio_host_to_guest_u64(pdev->vqs, hdr->id);
	hdr->flags  = virtio_host_to_guest_u32(pdev->vqs, hdr->flags);

	hdr->time_sec  = virtio_host_to_guest_u64(pdev->vqs, stbuf.st_ctim.tv_sec);
	hdr->time_nsec = virtio_host_to_guest_u32(pdev->vqs, stbuf.st_ctim.tv_nsec);

	fclose(fp);
	return len;
}

static ssize_t virtio_pstore_do_erase(struct kvm *kvm, struct pstore_dev *pdev,
				      struct pstore_hdr *hdr, struct iovec *iov)
{
	char path[PATH_MAX];

	virtio_pstore_hdr_to_filename(kvm, hdr, path, sizeof(path));

	return unlink(path);
}

static bool virtio_pstore_do_io_request(struct kvm *kvm, struct pstore_dev *pdev,
					struct virt_queue *vq)
{
	struct iovec iov[VIRTIO_PSTORE_QUEUE_SIZE];
	struct pstore_hdr *hdr;
	ssize_t len = 0;
	u16 out, in, head;

	head = virt_queue__get_iov(vq, iov, &out, &in, kvm);

	hdr = iov[0].iov_base;

	switch (virtio_guest_to_host_u16(vq, hdr->cmd)) {
	case VIRTIO_PSTORE_CMD_OPEN:
		len = virtio_pstore_do_open(kvm, pdev, hdr, iov);
		break;
	case VIRTIO_PSTORE_CMD_READ:
		len = virtio_pstore_do_read(kvm, pdev, hdr, iov);
		break;
	case VIRTIO_PSTORE_CMD_WRITE:
		len = virtio_pstore_do_write(kvm, pdev, hdr, iov);
		break;
	case VIRTIO_PSTORE_CMD_CLOSE:
		virtio_pstore_do_close(kvm, pdev, hdr, iov);
		break;
	case VIRTIO_PSTORE_CMD_ERASE:
		len = virtio_pstore_do_erase(kvm, pdev, hdr, iov);
		break;
	default:
		return false;
	}

	if (len < 0)
		return false;

	virt_queue__set_used_elem(vq, head, len);

	return true;
}

static void virtio_pstore_do_io(struct kvm *kvm, void *param)
{
	struct pstore_dev_job *job	= param;
	struct virt_queue *vq		= job->vq;
	struct pstore_dev *pdev		= job->pdev;

	while (virt_queue__available(vq))
		virtio_pstore_do_io_request(kvm, pdev, vq);

	pdev->vdev.ops->signal_vq(kvm, &pdev->vdev, vq - pdev->vqs);
}

static int init_vq(struct kvm *kvm, void *dev, u32 vq, u32 page_size, u32 align,
		   u32 pfn)
{
	struct pstore_dev *pdev = dev;
	struct virt_queue *queue;
	struct pstore_dev_job *job;
	void *p;

	compat__remove_message(compat_id);

	queue		= &pdev->vqs[vq];
	queue->pfn	= pfn;
	p		= virtio_get_vq(kvm, queue->pfn, page_size);

	job = &pdev->jobs[vq];

	vring_init(&queue->vring, VIRTIO_PSTORE_QUEUE_SIZE, p, align);

	*job = (struct pstore_dev_job) {
		.vq	= queue,
		.pdev	= pdev,
	};

	thread_pool__init_job(&job->job_id, kvm, virtio_pstore_do_io, job);

	return 0;
}

static int notify_vq(struct kvm *kvm, void *dev, u32 vq)
{
	struct pstore_dev *pdev = dev;

	thread_pool__do_job(&pdev->jobs[vq].job_id);

	return 0;
}

static int get_pfn_vq(struct kvm *kvm, void *dev, u32 vq)
{
	struct pstore_dev *pdev = dev;

	return pdev->vqs[vq].pfn;
}

static int get_size_vq(struct kvm *kvm, void *dev, u32 vq)
{
	return VIRTIO_PSTORE_QUEUE_SIZE;
}

static int set_size_vq(struct kvm *kvm, void *dev, u32 vq, int size)
{
	/* FIXME: dynamic */
	return size;
}

static struct virtio_ops pstore_dev_virtio_ops = {
	.get_config		= get_config,
	.get_host_features	= get_host_features,
	.set_guest_features	= set_guest_features,
	.init_vq		= init_vq,
	.notify_vq		= notify_vq,
	.get_pfn_vq		= get_pfn_vq,
	.get_size_vq		= get_size_vq,
	.set_size_vq		= set_size_vq,
};

int virtio_pstore__init(struct kvm *kvm)
{
	struct pstore_dev *pdev;
	int r;

	if (!kvm->cfg.pstore_path)
		return 0;

	pdev = malloc(sizeof(*pdev));
	if (pdev == NULL)
		return -ENOMEM;

	r = virtio_init(kvm, pdev, &pdev->vdev, &pstore_dev_virtio_ops,
			VIRTIO_DEFAULT_TRANS(kvm), PCI_DEVICE_ID_VIRTIO_PSTORE,
			VIRTIO_ID_PSTORE, PCI_CLASS_PSTORE);
	if (r < 0)
		goto cleanup;

	list_add_tail(&pdev->list, &pdevs);

	if (compat_id == -1)
		compat_id = virtio_compat_add_message("virtio-pstore", "CONFIG_VIRTIO_PSTORE");
	return 0;
cleanup:
	free(pdev);

	return r;
}
virtio_dev_init(virtio_pstore__init);

int virtio_pstore__exit(struct kvm *kvm)
{
	struct pstore_dev *pdev, *tmp;

	list_for_each_entry_safe(pdev, tmp, &pdevs, list) {
		list_del(&pdev->list);
		pdev->vdev.ops->exit(kvm, &pdev->vdev);
		free(pdev);
	}

	return 0;
}
virtio_dev_exit(virtio_pstore__exit);
