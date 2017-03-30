/*
 *
 * Copyright (C) 2011 Novell Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/splice.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include "overlayfs.h"

/* 每次copy 1MB */
#define OVL_COPY_UP_CHUNK_SIZE (1 << 20)

int ovl_copy_xattr(struct dentry *old, struct dentry *new)
{
	ssize_t list_size, size, value_size = 0;
	char *buf, *name, *value = NULL;
	int uninitialized_var(error);

	if (!old->d_inode->i_op->getxattr ||
	    !new->d_inode->i_op->getxattr)
		return 0;

	/* buf为NULL,返回拓展属性需要的最小的长度,是所有扩展属性name的总长度 */
	list_size = vfs_listxattr(old, NULL, 0);
	if (list_size <= 0) {
		if (list_size == -EOPNOTSUPP)
			return 0;
		return list_size;
	}

	buf = kzalloc(list_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* 返回写入buffer的长度 */
	list_size = vfs_listxattr(old, buf, list_size);
	if (list_size <= 0) {
		error = list_size;
		goto out;
	}

	/* 尽量减少重新分配buffer的次数 */
	for (name = buf; name < (buf + list_size); name += strlen(name) + 1) {
retry:
		/* 获取xattr value的长度 */
		size = vfs_getxattr(old, name, value, value_size);
		/* 如果value_size小于xattr value的长度 */
		if (size == -ERANGE)
			size = vfs_getxattr(old, name, NULL, 0);

		if (size < 0) {
			error = size;
			break;
		}

		/* 前一次的value_size比通过vfs_getxattr获取的size小的时候,就需要重新分配空间 */
		if (size > value_size) {
			void *new;

			new = krealloc(value, size, GFP_KERNEL);
			if (!new) {
				error = -ENOMEM;
				break;
			}
			value = new;
			value_size = size;
			goto retry;
		}

		/* 将xattr的value写入new */
		error = vfs_setxattr(new, name, value, size, 0);
		if (error)
			break;
	}
	kfree(value);
out:
	kfree(buf);
	return error;
}

/* 将old中数据copy到new中 */
static int ovl_copy_up_data(struct path *old, struct path *new, loff_t len)
{
	struct file *old_file;
	struct file *new_file;
	loff_t old_pos = 0;
	loff_t new_pos = 0;
	int error = 0;

	if (len == 0)
		return 0;

	old_file = ovl_path_open(old, O_LARGEFILE | O_RDONLY);
	if (IS_ERR(old_file))
		return PTR_ERR(old_file);

	new_file = ovl_path_open(new, O_LARGEFILE | O_WRONLY);
	if (IS_ERR(new_file)) {
		error = PTR_ERR(new_file);
		goto out_fput;
	}

	/* FIXME: copy up sparse files efficiently */
	while (len) {
		size_t this_len = OVL_COPY_UP_CHUNK_SIZE;
		long bytes;

		if (len < this_len)
			this_len = len;

		if (signal_pending_state(TASK_KILLABLE, current)) {
			error = -EINTR;
			break;
		}

		/* splice操作 */
		bytes = do_splice_direct(old_file, &old_pos,
					 new_file, &new_pos,
					 this_len, SPLICE_F_MOVE);
		if (bytes <= 0) {
			error = bytes;
			break;
		}
		WARN_ON(old_pos != new_pos);

		len -= bytes;
	}

	fput(new_file);
out_fput:
	fput(old_file);
	return error;
}

static char *ovl_read_symlink(struct dentry *realdentry)
{
	int res;
	char *buf;
	struct inode *inode = realdentry->d_inode;
	mm_segment_t old_fs;

	res = -EINVAL;
	if (!inode->i_op->readlink)
		goto err;

	res = -ENOMEM;
	/* 分配一个空闲页面 */
	buf = (char *) __get_free_page(GFP_KERNEL);
	if (!buf)
		goto err;

	/*
	 * buf需要时用户空间地址(0-3G),但是我们用一个内核地址代替(3G-4G),
	 * 为了避免kernel中权限检查出现错误,需要使用下面的代码.
	 */
	old_fs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	/* 返回copy的长度 */
	res = inode->i_op->readlink(realdentry,
				    (char __user *)buf, PAGE_SIZE - 1);
	/* 还原addr_limit */
	set_fs(old_fs);
	if (res < 0) {
		free_page((unsigned long) buf);
		goto err;
	}
	/* 字符串以'\0'结尾 */
	buf[res] = '\0';

	return buf;

err:
	return ERR_PTR(res);
}

static int ovl_set_timestamps(struct dentry *upperdentry, struct kstat *stat)
{
	struct iattr attr = {
		.ia_valid =
		     ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET | ATTR_MTIME_SET,
		.ia_atime = stat->atime,
		.ia_mtime = stat->mtime,
	};

	return notify_change(upperdentry, &attr, NULL);
}

int ovl_set_attr(struct dentry *upperdentry, struct kstat *stat)
{
	int err = 0;

	if (!S_ISLNK(stat->mode)) {
		struct iattr attr = {
			.ia_valid = ATTR_MODE,
			.ia_mode = stat->mode,
		};
		err = notify_change(upperdentry, &attr, NULL);
	}
	if (!err) {
		struct iattr attr = {
			.ia_valid = ATTR_UID | ATTR_GID,
			.ia_uid = stat->uid,
			.ia_gid = stat->gid,
		};
		err = notify_change(upperdentry, &attr, NULL);
	}
	if (!err)
		ovl_set_timestamps(upperdentry, stat);

	return err;
}

static int ovl_copy_up_locked(struct dentry *workdir, struct dentry *upperdir,
			      struct dentry *dentry, struct path *lowerpath,
			      struct kstat *stat, const char *link)
{
	struct inode *wdir = workdir->d_inode;
	struct inode *udir = upperdir->d_inode;
	struct dentry *newdentry = NULL;
	struct dentry *upper = NULL;
	umode_t mode = stat->mode;
	int err;

	/* 在workdir中生成一个临时文件(文件名是 #dentry的地址),    返回这个临时文件的dentry                  */
	newdentry = ovl_lookup_temp(workdir, dentry);
	err = PTR_ERR(newdentry);
	if (IS_ERR(newdentry))
		goto out;

	/* 在upperdir下找dentry的name */
	upper = lookup_one_len(dentry->d_name.name, upperdir,
			       dentry->d_name.len);
	err = PTR_ERR(upper);
	if (IS_ERR(upper))
		goto out1;

	/* Can't properly set mode on creation because of the umask */
	stat->mode &= S_IFMT;
	/* 在work创建文件,其文件类型由stat决定 */
	err = ovl_create_real(wdir, newdentry, stat, link, NULL, true);
	stat->mode = mode;
	if (err)
		goto out2;

	if (S_ISREG(stat->mode)) {
		/* 普通文件在copy up的时候,需要把data一并copy up */
		struct path upperpath;
		ovl_path_upper(dentry, &upperpath);
		/* 没有copy up的upperpath.dentry一定是NULL */
		BUG_ON(upperpath.dentry != NULL);
		upperpath.dentry = newdentry;

		/* 将数据从lower dir的文件数据copy到work dir下 */
		err = ovl_copy_up_data(lowerpath, &upperpath, stat->size);
		if (err)
			goto out_cleanup;
	}

	/* 将lowerpath->dentry的扩展属性copy给临时文件 */
	err = ovl_copy_xattr(lowerpath->dentry, newdentry);
	if (err)
		goto out_cleanup;

	mutex_lock(&newdentry->d_inode->i_mutex);
	/* 设置临时文件的属性 */
	err = ovl_set_attr(newdentry, stat);
	mutex_unlock(&newdentry->d_inode->i_mutex);
	if (err)
		goto out_cleanup;

	/* 将work dir中的dentry   r ename到upper dir下 */
	err = ovl_do_rename(wdir, newdentry, udir, upper, 0);
	if (err)
		goto out_cleanup;

	/* 给dentry指定__upperdentry */
	ovl_dentry_update(dentry, newdentry);
	newdentry = NULL;

	/*
	 * Non-directores become opaque when copied up.
	 */
	/* copy up的文件都有opaque标志 */
	if (!S_ISDIR(stat->mode))
		ovl_dentry_set_opaque(dentry, true);
out2:
	dput(upper);
out1:
	dput(newdentry);
out:
	return err;

out_cleanup:
	ovl_cleanup(wdir, newdentry);
	goto out2;
}

/*
 * Copy up a single dentry
 *
 * Directory renames only allowed on "pure upper" (already created on
 * upper filesystem, never copied up).  Directories which are on lower or
 * are merged may not be renamed.  For these -EXDEV is returned and
 * userspace has to deal with it.  This means, when copying up a
 * directory we can rely on it and ancestors being stable.
 *
 * Non-directory renames start with copy up of source if necessary.  The
 * actual rename will only proceed once the copy up was successful.  Copy
 * up uses upper parent i_mutex for exclusion.  Since rename can change
 * d_parent it is possible that the copy up will lock the old parent.  At
 * that point the file will have already been copied up anyway.
 */
/*
 * 只有"pure upper"的目录才能被rename(只在upper dir中存在的,而却不会从底层
 * copy up的目录). 在lower dir或者merge dir中存在的目录是不能被rename的.
 * 否则将会返回一个-EXDEV错误.
 */
int ovl_copy_up_one(struct dentry *parent, struct dentry *dentry,
		    struct path *lowerpath, struct kstat *stat)
{
	struct dentry *workdir = ovl_workdir(dentry);
	int err;
	struct kstat pstat;
	struct path parentpath;
	struct dentry *upperdir;
	struct dentry *upperdentry;
	const struct cred *old_cred;
	struct cred *override_cred;
	char *link = NULL;

	/* 如果使用了copy up那么就说明upper dir 存在,故需要workdir */
	if (WARN_ON(!workdir))
		return -EROFS;

	/* 从parent的dentry中获取数据到parentpath */
	ovl_path_upper(parent, &parentpath);
	/* upperdir就是parent的dentry */
	upperdir = parentpath.dentry;

	err = vfs_getattr(&parentpath, &pstat);
	if (err)
		return err;

	/* 如果lower dir指向的是一个符号链接,获取目标文件名 */
	if (S_ISLNK(stat->mode)) {
		link = ovl_read_symlink(lowerpath->dentry);
		if (IS_ERR(link))
			return PTR_ERR(link);
	}

	err = -ENOMEM;
	/* 创建一个当前task的subjective context(task->cred)的副本 */
	override_cred = prepare_creds();
	if (!override_cred)
		goto out_free_link;

	override_cred->fsuid = stat->uid;
	override_cred->fsgid = stat->gid;
	/*
	 * CAP_SYS_ADMIN for copying up extended attributes
	 * CAP_DAC_OVERRIDE for create
	 * CAP_FOWNER for chmod, timestamp update
	 * CAP_FSETID for chmod
	 * CAP_CHOWN for chown
	 * CAP_MKNOD for mknod
	 */
	cap_raise(override_cred->cap_effective, CAP_SYS_ADMIN);
	cap_raise(override_cred->cap_effective, CAP_DAC_OVERRIDE);
	cap_raise(override_cred->cap_effective, CAP_FOWNER);
	cap_raise(override_cred->cap_effective, CAP_FSETID);
	cap_raise(override_cred->cap_effective, CAP_CHOWN);
	cap_raise(override_cred->cap_effective, CAP_MKNOD);
	old_cred = override_creds(override_cred);

	err = -EIO;
	if (lock_rename(workdir, upperdir) != NULL) {
		pr_err("overlayfs: failed to lock workdir+upperdir\n");
		goto out_unlock;
	}
	/* 还没开始copy up就已经找到upper dentry */
	upperdentry = ovl_dentry_upper(dentry);
	if (upperdentry) {
		/* Raced with another copy-up?  Nothing to do, then... */
		err = 0;
		goto out_unlock;
	}

	err = ovl_copy_up_locked(workdir, upperdir, dentry, lowerpath,
				 stat, link);
	if (!err) {
		/* Restore timestamps on parent (best effort) */
		ovl_set_timestamps(upperdir, &pstat);
	}
out_unlock:
	unlock_rename(workdir, upperdir);
	revert_creds(old_cred);
	put_cred(override_cred);

out_free_link:
	if (link)
		free_page((unsigned long) link);

	return err;
}

int ovl_copy_up(struct dentry *dentry)
{
	int err;

	err = 0;
	while (!err) {
		struct dentry *next;
		struct dentry *parent;
		struct path lowerpath;
		struct kstat stat;
		enum ovl_path_type type = ovl_path_type(dentry);

		/* upper dir中的文件不需要copy up */
		if (OVL_TYPE_UPPER(type))
			break;

		next = dget(dentry);
		/* find the topmost dentry not yet copied up */
		/* 向上层目录遍历,找到最后一个需要copy up的dentry */
		for (;;) {
			parent = dget_parent(next);

			type = ovl_path_type(parent);
			if (OVL_TYPE_UPPER(type))
				break;

			dput(next);
			next = parent;
		}

		ovl_path_lower(next, &lowerpath);
		err = vfs_getattr(&lowerpath, &stat);
		if (!err)
			err = ovl_copy_up_one(parent, next, &lowerpath, &stat);

		dput(parent);
		dput(next);
	}

	return err;
}
