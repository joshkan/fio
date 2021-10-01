#include<sys/stat.h>
#include<sys/types.h>
#include<unistd.h>
#include<sys/ioctl.h>
#include<stdbool.h>

#define NVME_ID_CNS_NS_PRESENT	0x11
#define NVME_ID_CNS_NS	0x00
#define NVME_IDENTIFY_DATA_SIZE 4096
#define nvme_admin_identify 0x06

struct nvme_lbaf {
	__le16			ms;
	__u8			ds;
	__u8			rp;
};

struct nvme_id_ns {
	__le64			nsze;
	__le64			ncap;
	__le64			nuse;
	__u8			nsfeat;
	__u8			nlbaf;
	__u8			flbas;
	__u8			mc;
	__u8			dpc;
	__u8			dps;
	__u8			nmic;
	__u8			rescap;
	__u8			fpi;
	__u8			dlfeat;
	__le16			nawun;
	__le16			nawupf;
	__le16			nacwu;
	__le16			nabsn;
	__le16			nabo;
	__le16			nabspf;
	__le16			noiob;
	__u8			nvmcap[16];
	__le16			npwg;
	__le16			npwa;
	__le16			npdg;
	__le16			npda;
	__le16			nows;
	__le16			mssrl;
	__le32			mcl;
	__u8			msrc;
	__u8			rsvd81[11];
	__le32			anagrpid;
	__u8			rsvd96[3];
	__u8			nsattr;
	__le16			nvmsetid;
	__le16			endgid;
	__u8			nguid[16];
	__u8			eui64[8];
	struct nvme_lbaf	lbaf[16];
	__u8			rsvd192[192];
	__u8			vs[3712];
};

char *nvme_get_ctrl_attr(const char *path, const char *attr)
{
	char *attrpath, *value;
	ssize_t ret;
	int fd, i;

	ret = asprintf(&attrpath, "%s/%s", path, attr);
	if (ret < 0)
		return NULL;

	value = calloc(1, 1024);
	if (!value)
		goto err_free_path;

	fd = open(attrpath, O_RDONLY);
	if (fd < 0)
		goto err_free_value;

	ret = read(fd, value, 1024);
	if (ret < 0) {
		fprintf(stderr, "read :%s :%s\n", attrpath, strerror(errno));
		goto err_close_fd;
	}

	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';

	for (i = 0; i < strlen(value); i++) {
		if (value[i] == ',')
			value[i] = ' ';
	}

	close(fd);
	free(attrpath);
	return value;
err_close_fd:
	close(fd);
err_free_value:
	free(value);
err_free_path:
	free(attrpath);
	return NULL;
}

int nvme_logical_block_size_from_ns_char(const char *dev)
{
	int ret;
	int id, nsid;
	char *path = NULL;
	char *s;

	ret = sscanf(dev, "/dev/ng%dn%d", &id, &nsid);
	if (ret != 2)
		return -EINVAL;

	if (asprintf(&path, "/sys/block/nvme%dn%d/queue", id, nsid) < 0)
		path = NULL;

	if (!path)
		return -EINVAL;

	s = nvme_get_ctrl_attr(path, "logical_block_size");
	if (!s)
		return -EINVAL;

	return atoi(s);
}

void set_logical_block_size(struct fio_file *f)
{
	f->logical_block_size = nvme_logical_block_size_from_ns_char(f->file_name);
}

int nvme_submit_admin_passthru(int fd, struct nvme_passthru_cmd *cmd)
{
	return ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);
}

int nvme_identify13(int fd, __u32 nsid, __u32 cdw10, __u32 cdw11, void *data)
{
	struct nvme_admin_cmd cmd = {
		.opcode		= nvme_admin_identify,
		.nsid		= nsid,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= NVME_IDENTIFY_DATA_SIZE,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
	};

	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_identify(int fd, __u32 nsid, __u32 cdw10, void *data)
{
	return nvme_identify13(fd, nsid, cdw10, 0, data);
}

int nvme_identify_ns(int fd, __u32 nsid, bool present, void *data)
{
	int cns = present ? NVME_ID_CNS_NS_PRESENT : NVME_ID_CNS_NS;

	return nvme_identify(fd, nsid, cns, data);
}

int nvme_get_nsid(int fd)
{
	static struct stat nvme_stat;
	int err = fstat(fd, &nvme_stat);

	if (err < 0)
		return -errno;

	return ioctl(fd, NVME_IOCTL_ID);
}

unsigned long long get_char_size(struct fio_file *f)
{
	int fd, ret;
	struct nvme_id_ns ns;
	long long lba;
	double nsze;

	fd = open(f->file_name, O_RDONLY);
	f->nsid = nvme_get_nsid(fd);
	ret = nvme_identify_ns(fd, f->nsid, 0, &ns);
	if (ret)
		return -1ULL;
	lba	= 1 << ns.lbaf[(ns.flbas & 0x0f)].ds;
	nsze	= ns.nsze * lba;
	return (unsigned long long)nsze;

}
