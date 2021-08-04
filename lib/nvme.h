#include<sys/stat.h>
#include<sys/types.h>
#include<unistd.h>
#include<sys/ioctl.h>

int nvme_get_nsid(int fd)
{
	static struct stat nvme_stat;
	int err = fstat(fd, &nvme_stat);

	if (err < 0)
		return -errno;

	return ioctl(fd, NVME_IOCTL_ID);
}

void set_logical_block_size(struct fio_file *f)
{
	ioctl(f->fd, BLKSSZGET, &f->logical_block_size);
}

void set_nsid(struct fio_file *f)
{
	f->nsid = nvme_get_nsid(f->fd);
}
