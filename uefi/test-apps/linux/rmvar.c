// SPDX-License-Identifier: MIT
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int flags;
	int fd;

	if (argc != 2)
		return 64;
	fd = open(argv[1], O_RDONLY);
	if (fd < 0 || ioctl(fd, FS_IOC_GETFLAGS, &flags) < 0) {
		perror(argv[1]);
		return 1;
	}
	flags &= ~FS_IMMUTABLE_FL;
	if (ioctl(fd, FS_IOC_SETFLAGS, &flags) < 0 || unlink(argv[1]) < 0) {
		perror(argv[1]);
		return 1;
	}
	return 0;
}
