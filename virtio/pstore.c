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
#include <sys/eventfd.h>

#define NUM_VIRT_QUEUES			2
#define VIRTIO_PSTORE_QUEUE_SIZE	128

struct io_thread_arg {
	struct kvm		*kvm;
	struct pstore_dev	*pdev;
};

struct pstore_dev {
	struct list_head	list;
	struct virtio_device	vdev;
	pthread_t		io_thread;
	int			io_efd;
	int			done;

	struct virtio_pstore_config *config;

	int			fd;
	DIR			*dir;
	u64			id;

	/* virtio queue */
	struct virt_queue	vqs[NUM_VIRT_QUEUES];
};

static LIST_HEAD(pdevs);
static int compat_id = -1;

static u8 *get_config(struct kvm *kvm, void *dev)
{
	struct pstore_dev *pdev = dev;

	return (u8*)pdev->config;
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

static void virtio_pstore_to_filename(struct kvm *kvm, struct pstore_dev *pdev,
				      char *buf, size_t sz,
				      struct virtio_pstore_req *req)
{
	const char *basename;
	unsigned long long id = 0;
	unsigned int flags = virtio_host_to_guest_u64(pdev->vqs, req->flags);

	switch (req->type) {
	case VIRTIO_PSTORE_TYPE_DMESG:
		basename = "dmesg";
		id = pdev->id++;
		break;
	default:
		basename = "unknown";
		break;
	}

	snprintf(buf, sz, "%s/%s-%llu%s", kvm->cfg.pstore_path, basename, id,
		 flags & VIRTIO_PSTORE_FL_COMPRESSED ? ".enc.z" : "");
}

static void virtio_pstore_from_filename(struct kvm *kvm, char *name,
					char *buf, size_t sz,
					struct virtio_pstore_fileinfo *info)
{
	size_t len = strlen(name);

	snprintf(buf, sz, "%s/%s", kvm->cfg.pstore_path, name);

	info->flags = 0;
	if (len > 6 && !strncmp(name + len - 6, ".enc.z", 6))
		info->flags |= VIRTIO_PSTORE_FL_COMPRESSED;

	if (!strncmp(name, "dmesg-", 6)) {
		info->type = VIRTIO_PSTORE_TYPE_DMESG;
		name += strlen("dmesg-");
	} else if (!strncmp(name, "unknown-", 8)) {
		info->type = VIRTIO_PSTORE_TYPE_UNKNOWN;
		name += strlen("unknown-");
	}

	info->id = strtoul(name, NULL, 0);
}

static int virtio_pstore_do_open(struct kvm *kvm, struct pstore_dev *pdev,
				 struct virtio_pstore_req *req,
				 struct iovec *iov)
{
	pdev->dir = opendir(kvm->cfg.pstore_path);
	if (pdev->dir == NULL)
		return -errno;

	return 0;
}

static int virtio_pstore_do_close(struct kvm *kvm, struct pstore_dev *pdev,
				  struct virtio_pstore_req *req,
				  struct iovec *iov)
{
	if (pdev->dir == NULL)
		return -1;

	closedir(pdev->dir);
	pdev->dir = NULL;

	return 0;
}

static ssize_t virtio_pstore_do_read(struct kvm *kvm, struct pstore_dev *pdev,
				     struct virtio_pstore_req *req,
				     struct iovec *iov,
				     struct virtio_pstore_fileinfo *info)
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

	virtio_pstore_from_filename(kvm, dent->d_name, path, sizeof(path), info);
	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;

	if (fstat(fileno(fp), &stbuf) < 0)
		return -1;

	len = fread(iov[3].iov_base, 1, iov[3].iov_len, fp);
	if (len < 0 && errno == EAGAIN) {
		len = 0;
		goto out;
	}

	info->id     = virtio_host_to_guest_u64(pdev->vqs, info->id);
	info->type   = virtio_host_to_guest_u64(pdev->vqs, info->type);
	info->flags  = virtio_host_to_guest_u32(pdev->vqs, info->flags);
	info->len    = virtio_host_to_guest_u32(pdev->vqs, len);

	info->time_sec  = virtio_host_to_guest_u64(pdev->vqs, stbuf.st_ctim.tv_sec);
	info->time_nsec = virtio_host_to_guest_u32(pdev->vqs, stbuf.st_ctim.tv_nsec);

	len += sizeof(*info);

out:
	fclose(fp);
	return len;
}

static ssize_t virtio_pstore_do_write(struct kvm *kvm, struct pstore_dev *pdev,
				      struct virtio_pstore_req *req,
				      struct iovec *iov)
{
	char path[PATH_MAX];
	FILE *fp;
	ssize_t len = 0;

	virtio_pstore_to_filename(kvm, pdev, path, sizeof(path), req);

	fp = fopen(path, "a");
	if (fp == NULL)
		return -1;

	len = fwrite(iov[1].iov_base, 1, iov[1].iov_len, fp);
	if (len < 0 && errno == EAGAIN)
		len = 0;

	fclose(fp);
	return 0;
}

static ssize_t virtio_pstore_do_erase(struct kvm *kvm, struct pstore_dev *pdev,
				      struct virtio_pstore_req *req,
				      struct iovec *iov)
{
	char path[PATH_MAX];

	virtio_pstore_to_filename(kvm, pdev, path, sizeof(path), req);

	return unlink(path);
}

static bool virtio_pstore_do_io_request(struct kvm *kvm, struct pstore_dev *pdev,
					struct virt_queue *vq)
{
	struct iovec iov[VIRTIO_PSTORE_QUEUE_SIZE];
	struct virtio_pstore_req *req;
	struct virtio_pstore_res *res;
	struct virtio_pstore_fileinfo *info;
	ssize_t len = 0;
	u16 out, in, head;
	int ret = 0;

	head = virt_queue__get_iov(vq, iov, &out, &in, kvm);

	if (iov[0].iov_len != sizeof(*req) || iov[out].iov_len != sizeof(*res)) {
		return false;
	}

	req = iov[0].iov_base;
	res = iov[out].iov_base;

	switch (virtio_guest_to_host_u16(vq, req->cmd)) {
	case VIRTIO_PSTORE_CMD_OPEN:
		ret = virtio_pstore_do_open(kvm, pdev, req, iov);
		break;
	case VIRTIO_PSTORE_CMD_READ:
		info = iov[out + 1].iov_base;
		ret = virtio_pstore_do_read(kvm, pdev, req, iov, info);
		if (ret > 0) {
			len = ret;
			ret = 0;
		}
		break;
	case VIRTIO_PSTORE_CMD_WRITE:
		ret = virtio_pstore_do_write(kvm, pdev, req, iov);
		break;
	case VIRTIO_PSTORE_CMD_CLOSE:
		ret = virtio_pstore_do_close(kvm, pdev, req, iov);
		break;
	case VIRTIO_PSTORE_CMD_ERASE:
		ret = virtio_pstore_do_erase(kvm, pdev, req, iov);
		break;
	default:
		return false;
	}

	res->cmd  = req->cmd;
	res->type = req->type;
	res->ret  = virtio_host_to_guest_u32(vq, ret);

	virt_queue__set_used_elem(vq, head, sizeof(*res) + len);

	return ret == 0;
}

static void virtio_pstore_do_io(struct kvm *kvm, struct pstore_dev *pdev,
				struct virt_queue *vq)
{
	bool done = false;

	while (virt_queue__available(vq)) {
		virtio_pstore_do_io_request(kvm, pdev, vq);
		done = true;
	}

	if (done)
		pdev->vdev.ops->signal_vq(kvm, &pdev->vdev, vq - pdev->vqs);
}

static void *virtio_pstore_io_thread(void *arg)
{
	struct io_thread_arg *io_arg = arg;
	struct pstore_dev *pdev = io_arg->pdev;
	struct kvm *kvm = io_arg->kvm;
	u64 data;
	int r;

	kvm__set_thread_name("virtio-pstore-io");

	while (!pdev->done) {
		r = read(pdev->io_efd, &data, sizeof(u64));
		if (r < 0)
			continue;

		virtio_pstore_do_io(kvm, pdev, &pdev->vqs[0]);
		virtio_pstore_do_io(kvm, pdev, &pdev->vqs[1]);
	}
	free(io_arg);

	pthread_exit(NULL);
	return NULL;
}

static int init_vq(struct kvm *kvm, void *dev, u32 vq, u32 page_size, u32 align,
		   u32 pfn)
{
	struct pstore_dev *pdev = dev;
	struct virt_queue *queue;
	void *p;

	compat__remove_message(compat_id);

	queue		= &pdev->vqs[vq];
	queue->pfn	= pfn;
	p		= virtio_get_vq(kvm, queue->pfn, page_size);

	vring_init(&queue->vring, VIRTIO_PSTORE_QUEUE_SIZE, p, align);

	return 0;
}

static int notify_vq(struct kvm *kvm, void *dev, u32 vq)
{
	struct pstore_dev *pdev = dev;
	u64 data = 1;
	int r;

	r = write(pdev->io_efd, &data, sizeof(data));
	if (r < 0)
		return r;

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
	struct io_thread_arg *io_arg = NULL;
	int r;

	if (!kvm->cfg.pstore_path)
		return 0;

	pdev = calloc(1, sizeof(*pdev));
	if (pdev == NULL)
		return -ENOMEM;

	pdev->config = calloc(1, sizeof(*pdev->config));
	if (pdev->config == NULL) {
		r = -ENOMEM;
		goto cleanup;
	}

	pdev->id = 1;

	io_arg = malloc(sizeof(*io_arg));
	if (io_arg == NULL) {
		r = -ENOMEM;
		goto cleanup;
	}

	pdev->io_efd = eventfd(0, 0);

	*io_arg = (struct io_thread_arg) {
		.pdev   = pdev,
		.kvm    = kvm,
	};
	r = pthread_create(&pdev->io_thread, NULL,
			   virtio_pstore_io_thread, io_arg);
	if (r < 0)
		goto cleanup;

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
	free(io_arg);
	free(pdev->config);
	free(pdev);

	return r;
}
virtio_dev_init(virtio_pstore__init);

int virtio_pstore__exit(struct kvm *kvm)
{
	struct pstore_dev *pdev, *tmp;

	list_for_each_entry_safe(pdev, tmp, &pdevs, list) {
		list_del(&pdev->list);
		close(pdev->io_efd);
		pdev->vdev.ops->exit(kvm, &pdev->vdev);
		free(pdev);
	}

	return 0;
}
virtio_dev_exit(virtio_pstore__exit);
