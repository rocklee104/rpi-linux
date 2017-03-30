/*
 *
 * Copyright (C) 2011 Novell Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>
#include "overlayfs.h"

MODULE_AUTHOR("Miklos Szeredi <miklos@szeredi.hu>");
MODULE_DESCRIPTION("Overlay filesystem");
MODULE_LICENSE("GPL");

#define OVERLAYFS_SUPER_MAGIC 0x794c7630

/* 保存挂载使用使用的路径名 */
struct ovl_config {
	char *lowerdir;
	char *upperdir;
	char *workdir;
};

/* private information held for overlayfs's superblock */
struct ovl_fs {
	struct vfsmount *upper_mnt;
	/* lower dir的个数 */
	unsigned numlower;
	/* lower mnt指针数组 */
	struct vfsmount **lower_mnt;
	/* 指向创建出来的work */
	struct dentry *workdir;
	long lower_namelen;
	/* pathnames of lower and upper dirs, for show_options */
	struct ovl_config config;
};

struct ovl_dir_cache;

/* private information held for every overlayfs dentry */
/* 保存在dentry的d_fsdata中 */
struct ovl_entry {
	struct dentry *__upperdentry;
	struct ovl_dir_cache *cache;
	union {
		struct {
			/* 目录使用扩展属性区别opaque,version记录cache的version */
			u64 version;
			/* 文件使用opaque标志 */
			bool opaque;
		};
		struct rcu_head rcu;
	};
	/* lower的个数 */
	unsigned numlower;
	struct path lowerstack[];
};

#define OVL_MAX_STACK 500

/* 总返回第一个lower的dentry */
static struct dentry *__ovl_dentry_lower(struct ovl_entry *oe)
{
	return oe->numlower ? oe->lowerstack[0].dentry : NULL;
}

enum ovl_path_type ovl_path_type(struct dentry *dentry)
{
	/* 从dentry的private data中取出ovl_entry */
	struct ovl_entry *oe = dentry->d_fsdata;
	enum ovl_path_type type = 0;

	if (oe->__upperdentry) {
		type = __OVL_PATH_UPPER;

		/*
		 * Non-dir dentry can hold lower dentry from previous
		 * location. Its purity depends only on opaque flag.
		 */
		if (oe->numlower && S_ISDIR(dentry->d_inode->i_mode))
			/* 有upper也有lower,同时dentry是一个目录的dentry,这种目录就属于merge */
			type |= __OVL_PATH_MERGE;
		else if (!oe->opaque)
			/* 当没有对应的lower, 或者lower对应的是一个文件, 最后没有opaque标志, 就设置pure标志 */
			type |= __OVL_PATH_PURE;
	} else {
		/* 没有upper, lower数量大于1,这样的dentry也属于merge */
		if (oe->numlower > 1)
			type |= __OVL_PATH_MERGE;
	}
	return type;
}

static struct dentry *ovl_upperdentry_dereference(struct ovl_entry *oe)
{
	return lockless_dereference(oe->__upperdentry);
}

void ovl_path_upper(struct dentry *dentry, struct path *path)
{
	/* 获取overlayfs的sb */
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	struct ovl_entry *oe = dentry->d_fsdata;

	path->mnt = ofs->upper_mnt;
	path->dentry = ovl_upperdentry_dereference(oe);
}

enum ovl_path_type ovl_path_real(struct dentry *dentry, struct path *path)
{
	enum ovl_path_type type = ovl_path_type(dentry);

	if (!OVL_TYPE_UPPER(type))
		ovl_path_lower(dentry, path);
	else
		ovl_path_upper(dentry, path);

	return type;
}

/* dentry->oe->upperdentry */
struct dentry *ovl_dentry_upper(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	return ovl_upperdentry_dereference(oe);
}

struct dentry *ovl_dentry_lower(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	return __ovl_dentry_lower(oe);
}

/*
 * overlayfs dentry选择函数
 * 如果存在upperdir返回upper的dentry,否则返回lower的dentry
*/
struct dentry *ovl_dentry_real(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;
	struct dentry *realdentry;

	realdentry = ovl_upperdentry_dereference(oe);
	/* 如果没有upper,那么lower的个数一定要大于1 */
	if (!realdentry)
		realdentry = __ovl_dentry_lower(oe);

	return realdentry;
}

/* 如果upper dir有对应的dentry,is_upper是true */
struct dentry *ovl_entry_real(struct ovl_entry *oe, bool *is_upper)
{
	struct dentry *realdentry;

	realdentry = ovl_upperdentry_dereference(oe);
	if (realdentry) {
		*is_upper = true;
	} else {
		realdentry = __ovl_dentry_lower(oe);
		*is_upper = false;
	}
	return realdentry;
}

struct ovl_dir_cache *ovl_dir_cache(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	return oe->cache;
}

void ovl_set_dir_cache(struct dentry *dentry, struct ovl_dir_cache *cache)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	oe->cache = cache;
}

/* 如果有多个lower dir, 第一个lower dir才是真正意义上的lower dir */
void ovl_path_lower(struct dentry *dentry, struct path *path)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	*path = oe->numlower ? oe->lowerstack[0] : (struct path) { NULL, NULL };
}

/* 判断dentry所指向的upper mnt是否能写 */
int ovl_want_write(struct dentry *dentry)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	return mnt_want_write(ofs->upper_mnt);
}

void ovl_drop_write(struct dentry *dentry)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	mnt_drop_write(ofs->upper_mnt);
}

struct dentry *ovl_workdir(struct dentry *dentry)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	return ofs->workdir;
}

bool ovl_dentry_is_opaque(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;
	return oe->opaque;
}

void ovl_dentry_set_opaque(struct dentry *dentry, bool opaque)
{
	struct ovl_entry *oe = dentry->d_fsdata;
	oe->opaque = opaque;
}

void ovl_dentry_update(struct dentry *dentry, struct dentry *upperdentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	WARN_ON(!mutex_is_locked(&upperdentry->d_parent->d_inode->i_mutex));
	WARN_ON(oe->__upperdentry);
	BUG_ON(!upperdentry->d_inode);
	/*
	 * Make sure upperdentry is consistent before making it visible to
	 * ovl_upperdentry_dereference().
	 */
	smp_wmb();
	oe->__upperdentry = upperdentry;
}

void ovl_dentry_version_inc(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	WARN_ON(!mutex_is_locked(&dentry->d_inode->i_mutex));
	oe->version++;
}

u64 ovl_dentry_version_get(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	WARN_ON(!mutex_is_locked(&dentry->d_inode->i_mutex));
	return oe->version;
}

/* 判断dentry指向的文件是否是一个whiteout */
bool ovl_is_whiteout(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	return inode && IS_WHITEOUT(inode);
}

/* 对于目录来说,opaque只能通过xattr指定 */
static bool ovl_is_opaquedir(struct dentry *dentry)
{
	int res;
	char val;
	struct inode *inode = dentry->d_inode;

	if (!S_ISDIR(inode->i_mode) || !inode->i_op->getxattr)
		return false;

	res = inode->i_op->getxattr(dentry, OVL_XATTR_OPAQUE, &val, 1);
	if (res == 1 && val == 'y')
		return true;

	return false;
}

static void ovl_dentry_release(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	if (oe) {
		unsigned int i;

		dput(oe->__upperdentry);
		for (i = 0; i < oe->numlower; i++)
			dput(oe->lowerstack[i].dentry);
		kfree_rcu(oe, rcu);
	}
}

static struct dentry *ovl_d_real(struct dentry *dentry, struct inode *inode)
{
	struct dentry *real;

	if (d_is_dir(dentry)) {
		if (!inode || inode == d_inode(dentry))
			return dentry;
		goto bug;
	}

	real = ovl_dentry_upper(dentry);
	if (real && (!inode || inode == d_inode(real)))
		return real;

	real = ovl_dentry_lower(dentry);
	if (!real)
		goto bug;

	if (!inode || inode == d_inode(real))
		return real;

	/* Handle recursion */
	if (real->d_flags & DCACHE_OP_REAL)
		return real->d_op->d_real(real, inode);

bug:
	WARN(1, "ovl_d_real(%pd4, %s:%lu\n): real dentry not found\n", dentry,
	     inode ? inode->i_sb->s_id : "NULL", inode ? inode->i_ino : 0);
	return dentry;
}

static int ovl_dentry_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct ovl_entry *oe = dentry->d_fsdata;
	unsigned int i;
	int ret = 1;

	for (i = 0; i < oe->numlower; i++) {
		struct dentry *d = oe->lowerstack[i].dentry;

		if (d->d_flags & DCACHE_OP_REVALIDATE) {
			ret = d->d_op->d_revalidate(d, flags);
			if (ret < 0)
				return ret;
			if (!ret) {
				if (!(flags & LOOKUP_RCU))
					d_invalidate(d);
				return -ESTALE;
			}
		}
	}
	return 1;
}

static int ovl_dentry_weak_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct ovl_entry *oe = dentry->d_fsdata;
	unsigned int i;
	int ret = 1;

	for (i = 0; i < oe->numlower; i++) {
		struct dentry *d = oe->lowerstack[i].dentry;

		if (d->d_flags & DCACHE_OP_WEAK_REVALIDATE) {
			ret = d->d_op->d_weak_revalidate(d, flags);
			if (ret <= 0)
				break;
		}
	}
	return ret;
}

static const struct dentry_operations ovl_dentry_operations = {
	.d_release = ovl_dentry_release,
	.d_select_inode = ovl_d_select_inode,
	.d_real = ovl_d_real,
};

static const struct dentry_operations ovl_reval_dentry_operations = {
	.d_release = ovl_dentry_release,
	.d_select_inode = ovl_d_select_inode,
	.d_real = ovl_d_real,
	.d_revalidate = ovl_dentry_revalidate,
	.d_weak_revalidate = ovl_dentry_weak_revalidate,
};

static struct ovl_entry *ovl_alloc_entry(unsigned int numlower)
{
	/* 通过offsetof获取柔性数组下个成员,继而获取整个结构体的大小 */
	size_t size = offsetof(struct ovl_entry, lowerstack[numlower]);
	struct ovl_entry *oe = kzalloc(size, GFP_KERNEL);

	if (oe)
		oe->numlower = numlower;

	return oe;
}

static bool ovl_dentry_remote(struct dentry *dentry)
{
	return dentry->d_flags &
		(DCACHE_OP_REVALIDATE | DCACHE_OP_WEAK_REVALIDATE);
}

static bool ovl_dentry_weird(struct dentry *dentry)
{
	return dentry->d_flags & (DCACHE_NEED_AUTOMOUNT |
				  DCACHE_MANAGE_TRANSIT |
				  DCACHE_OP_HASH |
				  DCACHE_OP_COMPARE);
}

static inline struct dentry *ovl_lookup_real(struct dentry *dir,
					     struct qstr *name)
{
	struct dentry *dentry;

	mutex_lock(&dir->d_inode->i_mutex);
	dentry = lookup_one_len(name->name, dir, name->len);
	mutex_unlock(&dir->d_inode->i_mutex);

	if (IS_ERR(dentry)) {
		if (PTR_ERR(dentry) == -ENOENT)
			dentry = NULL;
	} else if (!dentry->d_inode) {
		dput(dentry);
		dentry = NULL;
	} else if (ovl_dentry_weird(dentry)) {
		dput(dentry);
		/* Don't support traversing automounts and other weirdness */
		dentry = ERR_PTR(-EREMOTE);
	}
	return dentry;
}

/*
 * Returns next layer in stack starting from top.
 * Returns -1 if this is the last layer.
 */
/*
 * upper layer: 0
 * lower[0]:	1
 * lower[1]:	2
 * ...
*/
int ovl_path_next(int idx, struct dentry *dentry, struct path *path)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	BUG_ON(idx < 0);
	if (idx == 0) {
		/* 一个overlay只有一个upper,获取upper的path */
		ovl_path_upper(dentry, path);
		/* 如果有upperdir,如果有lower dir,不管lowerdir有几个,都返回1 */
		if (path->dentry)
			return oe->numlower ? 1 : -1;
		/*  如果没有upperdir */
		idx++;
	}
	BUG_ON(idx > oe->numlower);
	*path = oe->lowerstack[idx - 1];

	/* 返回下次循环需要处理的index */
	return (idx < oe->numlower) ? idx + 1 : -1;
}

struct dentry *ovl_lookup(struct inode *dir, struct dentry *dentry,
			  unsigned int flags)
{
	struct ovl_entry *oe;
	struct ovl_entry *poe = dentry->d_parent->d_fsdata;
	struct path *stack = NULL;
	struct dentry *upperdir, *upperdentry = NULL;
	unsigned int ctr = 0;
	struct inode *inode = NULL;
	bool upperopaque = false;
	struct dentry *this, *prev = NULL;
	unsigned int i;
	int err;

	/* 获取父目录的upperdir */
	upperdir = ovl_upperdentry_dereference(poe);
	if (upperdir) {
		/* 当需要查询一个dentry时,首先去父目录的upperdir查找 */
		this = ovl_lookup_real(upperdir, &dentry->d_name);
		err = PTR_ERR(this);
		if (IS_ERR(this))
			goto out;

		if (this) {
			/* upperdir是不能在remote fs中的 */
			if (unlikely(ovl_dentry_remote(this))) {
				dput(this);
				err = -EREMOTE;
				goto out;
			}
			if (ovl_is_whiteout(this)) {
				dput(this);
				this = NULL;
				upperopaque = true;
			} else if (poe->numlower && ovl_is_opaquedir(this)) {
				upperopaque = true;
			}
		}
		upperdentry = prev = this;
	}

	if (!upperopaque && poe->numlower) {
		err = -ENOMEM;
		stack = kcalloc(poe->numlower, sizeof(struct path), GFP_KERNEL);
		if (!stack)
			goto out_put_upper;
	}

	for (i = 0; !upperopaque && i < poe->numlower; i++) {
		bool opaque = false;
		struct path lowerpath = poe->lowerstack[i];

		this = ovl_lookup_real(lowerpath.dentry, &dentry->d_name);
		err = PTR_ERR(this);
		if (IS_ERR(this)) {
			/*
			 * If it's positive, then treat ENAMETOOLONG as ENOENT.
			 */
			if (err == -ENAMETOOLONG && (upperdentry || ctr))
				continue;
			goto out_put;
		}
		if (!this)
			continue;
		if (ovl_is_whiteout(this)) {
			dput(this);
			break;
		}
		/*
		 * Only makes sense to check opaque dir if this is not the
		 * lowermost layer.
		 */
		if (i < poe->numlower - 1 && ovl_is_opaquedir(this))
			opaque = true;

		if (prev && (!S_ISDIR(prev->d_inode->i_mode) ||
			     !S_ISDIR(this->d_inode->i_mode))) {
			/*
			 * FIXME: check for upper-opaqueness maybe better done
			 * in remove code.
			 */
			if (prev == upperdentry)
				upperopaque = true;
			dput(this);
			break;
		}
		/*
		 * If this is a non-directory then stop here.
		 */
		if (!S_ISDIR(this->d_inode->i_mode))
			opaque = true;

		stack[ctr].dentry = this;
		stack[ctr].mnt = lowerpath.mnt;
		ctr++;
		prev = this;
		if (opaque)
			break;
	}

	oe = ovl_alloc_entry(ctr);
	err = -ENOMEM;
	if (!oe)
		goto out_put;

	if (upperdentry || ctr) {
		struct dentry *realdentry;

		realdentry = upperdentry ? upperdentry : stack[0].dentry;

		err = -ENOMEM;
		inode = ovl_new_inode(dentry->d_sb, realdentry->d_inode->i_mode,
				      oe);
		if (!inode)
			goto out_free_oe;
		ovl_copyattr(realdentry->d_inode, inode);
	}

	oe->opaque = upperopaque;
	oe->__upperdentry = upperdentry;
	memcpy(oe->lowerstack, stack, sizeof(struct path) * ctr);
	kfree(stack);
	dentry->d_fsdata = oe;
	d_add(dentry, inode);

	return NULL;

out_free_oe:
	kfree(oe);
out_put:
	for (i = 0; i < ctr; i++)
		dput(stack[i].dentry);
	kfree(stack);
out_put_upper:
	dput(upperdentry);
out:
	return ERR_PTR(err);
}

struct file *ovl_path_open(struct path *path, int flags)
{
	return dentry_open(path, flags, current_cred());
}

static void ovl_put_super(struct super_block *sb)
{
	struct ovl_fs *ufs = sb->s_fs_info;
	unsigned i;

	dput(ufs->workdir);
	mntput(ufs->upper_mnt);
	for (i = 0; i < ufs->numlower; i++)
		mntput(ufs->lower_mnt[i]);
	/* vfsmount的2级指针可以free,其一级指针交给mntput */
	kfree(ufs->lower_mnt);

	kfree(ufs->config.lowerdir);
	kfree(ufs->config.upperdir);
	kfree(ufs->config.workdir);
	kfree(ufs);
}

/**
 * ovl_statfs
 * @sb: The overlayfs super block
 * @buf: The struct kstatfs to fill in with stats
 *
 * Get the filesystem statistics.  As writes always target the upper layer
 * filesystem pass the statfs to the upper filesystem (if it exists)
 */
static int ovl_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	struct dentry *root_dentry = dentry->d_sb->s_root;
	struct path path;
	int err;

	ovl_path_real(root_dentry, &path);

	err = vfs_statfs(&path, buf);
	if (!err) {
		buf->f_namelen = max(buf->f_namelen, ofs->lower_namelen);
		buf->f_type = OVERLAYFS_SUPER_MAGIC;
	}

	return err;
}

/**
 * ovl_show_options
 *
 * Prints the mount options for a given superblock.
 * Returns zero; does not fail.
 */
static int ovl_show_options(struct seq_file *m, struct dentry *dentry)
{
	struct super_block *sb = dentry->d_sb;
	struct ovl_fs *ufs = sb->s_fs_info;

	seq_show_option(m, "lowerdir", ufs->config.lowerdir);
	if (ufs->config.upperdir) {
		seq_show_option(m, "upperdir", ufs->config.upperdir);
		seq_show_option(m, "workdir", ufs->config.workdir);
	}
	return 0;
}

static int ovl_remount(struct super_block *sb, int *flags, char *data)
{
	struct ovl_fs *ufs = sb->s_fs_info;

	if (!(*flags & MS_RDONLY) && (!ufs->upper_mnt || !ufs->workdir))
		return -EROFS;

	return 0;
}

static const struct super_operations ovl_super_operations = {
	.put_super	= ovl_put_super,
	.statfs		= ovl_statfs,
	.show_options	= ovl_show_options,
	.remount_fs	= ovl_remount,
};

enum {
	OPT_LOWERDIR,
	OPT_UPPERDIR,
	OPT_WORKDIR,
	OPT_ERR,
};

static const match_table_t ovl_tokens = {
	{OPT_LOWERDIR,			"lowerdir=%s"},
	{OPT_UPPERDIR,			"upperdir=%s"},
	{OPT_WORKDIR,			"workdir=%s"},
	{OPT_ERR,			NULL}
};

static char *ovl_next_opt(char **s)
{
	char *sbegin = *s;
	char *p;

	if (sbegin == NULL)
		return NULL;

	for (p = sbegin; *p; p++) {
		if (*p == '\\') {
			p++;
			if (!*p)
				break;
		} else if (*p == ',') {
			*p = '\0';
			/* *s指向','后面那个字符,返回','之前的字符串 */
			*s = p + 1;
			return sbegin;
		}
	}
	/* 处理以','分隔的最后一部分字符串 */
	*s = NULL;
	return sbegin;
}

static int ovl_parse_opt(char *opt, struct ovl_config *config)
{
	char *p;

	while ((p = ovl_next_opt(&opt)) != NULL) {
		int token;
		substring_t args[MAX_OPT_ARGS];

		if (!*p)
			continue;

		token = match_token(p, ovl_tokens, args);
		switch (token) {
		case OPT_UPPERDIR:
			kfree(config->upperdir);
			config->upperdir = match_strdup(&args[0]);
			if (!config->upperdir)
				return -ENOMEM;
			break;

		case OPT_LOWERDIR:
			kfree(config->lowerdir);
			config->lowerdir = match_strdup(&args[0]);
			if (!config->lowerdir)
				return -ENOMEM;
			break;

		case OPT_WORKDIR:
			kfree(config->workdir);
			config->workdir = match_strdup(&args[0]);
			if (!config->workdir)
				return -ENOMEM;
			break;

		default:
			pr_err("overlayfs: unrecognized mount option \"%s\" or missing value\n", p);
			return -EINVAL;
		}
	}

	/* 当没有upperdir的时候,workdir也没用 */
	/* Workdir is useless in non-upper mount */
	if (!config->upperdir && config->workdir) {
		pr_info("overlayfs: option \"workdir=%s\" is useless in a non-upper mount, ignore\n",
			config->workdir);
		kfree(config->workdir);
		config->workdir = NULL;
	}

	return 0;
}

#define OVL_WORKDIR_NAME "work"

static struct dentry *ovl_workdir_create(struct vfsmount *mnt,
					 struct dentry *dentry)
{
	struct inode *dir = dentry->d_inode;
	struct dentry *work;
	int err;
	bool retried = false;

	err = mnt_want_write(mnt);
	if (err)
		return ERR_PTR(err);

	mutex_lock_nested(&dir->i_mutex, I_MUTEX_PARENT);
retry:
	/*
	 * 在dentry下查找"work",查找过程中会给work分配dentry.如果work->inode存在,
	 * 说明"work"文件存在,而overylay需要一个新的work,所以需要先将其删除.
	 * 最后,创建一个work目录.
	 */
	work = lookup_one_len(OVL_WORKDIR_NAME, dentry,
			      strlen(OVL_WORKDIR_NAME));

	if (!IS_ERR(work)) {
		/* 在ovl_create_real中创建目录 */
		struct kstat stat = {
			.mode = S_IFDIR | 0,
		};

		if (work->d_inode) {
			err = -EEXIST;
			if (retried)
				goto out_dput;

			retried = true;
			ovl_cleanup(dir, work);
			dput(work);
			/* retry之后work->inode还存在表示work没有成功删除 */
			goto retry;
		}

		/* 只有work不存在或者被成功删除后,才会创建一个新的work */
		err = ovl_create_real(dir, work, &stat, NULL, NULL, true);
		if (err)
			goto out_dput;
	}
out_unlock:
	mutex_unlock(&dir->i_mutex);
	mnt_drop_write(mnt);

	return work;

out_dput:
	dput(work);
	work = ERR_PTR(err);
	goto out_unlock;
}

/* 跳过'\\' */
static void ovl_unescape(char *s)
{
	char *d = s;

	for (;; s++, d++) {
		if (*s == '\\')
			s++;
		*d = *s;
		if (!*s)
			break;
	}
}

static int ovl_mount_dir_noesc(const char *name, struct path *path)
{
	int err = -EINVAL;

	if (!*name) {
		pr_err("overlayfs: empty lowerdir\n");
		goto out;
	}
	/* 根据name获取到path */
	err = kern_path(name, LOOKUP_FOLLOW, path);
	if (err) {
		pr_err("overlayfs: failed to resolve '%s': %i\n", name, err);
		goto out;
	}
	err = -EINVAL;
	/* 判断overlayfs是否支持这个dentry的flag */
	if (ovl_dentry_weird(path->dentry)) {
		pr_err("overlayfs: filesystem on '%s' not supported\n", name);
		goto out_put;
	}
	if (!S_ISDIR(path->dentry->d_inode->i_mode)) {
		pr_err("overlayfs: '%s' not a directory\n", name);
		goto out_put;
	}
	return 0;

out_put:
	path_put(path);
out:
	return err;
}

static int ovl_mount_dir(const char *name, struct path *path)
{
	int err = -ENOMEM;
	char *tmp = kstrdup(name, GFP_KERNEL);

	if (tmp) {
		ovl_unescape(tmp);
		/* path必须是一个目录 */
		err = ovl_mount_dir_noesc(tmp, path);

		if (!err)
			/* upper不能处于nfs中,也就是说upper必须处于local,但是lower可以 */
			if (ovl_dentry_remote(path->dentry)) {
				pr_err("overlayfs: filesystem on '%s' not supported as upperdir\n",
				       tmp);
				path_put(path);
				err = -EINVAL;
			}
		kfree(tmp);
	}
	return err;
}

static int ovl_lower_dir(const char *name, struct path *path, long *namelen,
			 int *stack_depth, bool *remote)
{
	int err;
	struct kstatfs statfs;

	err = ovl_mount_dir_noesc(name, path);
	if (err)
		goto out;

	/* 通过path获取到文件系统状态 */
	err = vfs_statfs(path, &statfs);
	if (err) {
		pr_err("overlayfs: statfs failed on '%s'\n", name);
		goto out_put;
	}
	*namelen = max(*namelen, statfs.f_namelen);
	*stack_depth = max(*stack_depth, path->mnt->mnt_sb->s_stack_depth);

	/* lower dir可以处于nfs中,但是upper不行 */
	if (ovl_dentry_remote(path->dentry))
		*remote = true;

	return 0;

out_put:
	path_put(path);
out:
	return err;
}

/* Workdir should not be subdir of upperdir and vice versa */
/* subdir和workdir不能为父子关系 */
static bool ovl_workdir_ok(struct dentry *workdir, struct dentry *upperdir)
{
	bool ok = false;

	if (workdir != upperdir) {
		ok = (lock_rename(workdir, upperdir) == NULL);
		unlock_rename(workdir, upperdir);
	}
	return ok;
}

static unsigned int ovl_split_lowerdirs(char *str)
{
	unsigned int ctr = 1;
	char *s, *d;

	for (s = d = str;; s++, d++) {
		if (*s == '\\') {
			s++;
		} else if (*s == ':') {
			*d = '\0';
			ctr++;
			continue;
		}
		*d = *s;
		if (!*s)
			break;
	}
	return ctr;
}

static int ovl_fill_super(struct super_block *sb, void *data, int silent)
{
	struct path upperpath = { NULL, NULL };
	struct path workpath = { NULL, NULL };
	struct dentry *root_dentry;
	struct ovl_entry *oe;
	struct ovl_fs *ufs;
	/* 记录多个lower dir的path */
	struct path *stack = NULL;
	char *lowertmp;
	char *lower;
	unsigned int numlower;
	unsigned int stacklen = 0;
	unsigned int i;
	bool remote = false;
	int err;

	err = -ENOMEM;
	ufs = kzalloc(sizeof(struct ovl_fs), GFP_KERNEL);
	if (!ufs)
		goto out;

	pr_err("rock data: %s\n", (char *)data);
	err = ovl_parse_opt((char *) data, &ufs->config);
	if (err)
		goto out_free_config;

	err = -EINVAL;
	if (!ufs->config.lowerdir) {
		pr_err("overlayfs: missing 'lowerdir'\n");
		goto out_free_config;
	}

	sb->s_stack_depth = 0;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	if (ufs->config.upperdir) {
		if (!ufs->config.workdir) {
			pr_err("overlayfs: missing 'workdir'\n");
			goto out_free_config;
		}

		/* 检查upperpath,并将路径字符串转成path结构 */
		err = ovl_mount_dir(ufs->config.upperdir, &upperpath);
		if (err)
			goto out_free_config;

		/* Upper fs should not be r/o */
		if (upperpath.mnt->mnt_sb->s_flags & MS_RDONLY) {
			pr_err("overlayfs: upper fs is r/o, try multi-lower layers mount\n");
			err = -EINVAL;
			goto out_put_upperpath;
		}

		/* 检查workdir */
		err = ovl_mount_dir(ufs->config.workdir, &workpath);
		if (err)
			goto out_put_upperpath;

		err = -EINVAL;
		/* upperdir必须要和workdir在同一个mnt中 */
		if (upperpath.mnt != workpath.mnt) {
			pr_err("overlayfs: workdir and upperdir must reside under the same mount\n");
			goto out_put_workpath;
		}
		if (!ovl_workdir_ok(workpath.dentry, upperpath.dentry)) {
			pr_err("overlayfs: workdir and upperdir must be separate subtrees\n");
			goto out_put_workpath;
		}
		/* overlay的s_stack_depth需要和upperdir所在sb相同 */
		sb->s_stack_depth = upperpath.mnt->mnt_sb->s_stack_depth;
	}
	err = -ENOMEM;
	lowertmp = kstrdup(ufs->config.lowerdir, GFP_KERNEL);
	if (!lowertmp)
		goto out_put_workpath;

	err = -EINVAL;
	stacklen = ovl_split_lowerdirs(lowertmp);
	if (stacklen > OVL_MAX_STACK) {
		pr_err("overlayfs: too many lower directries, limit is %d\n",
		       OVL_MAX_STACK);
		goto out_free_lowertmp;
	} else if (!ufs->config.upperdir && stacklen == 1) {
		/* upperdir不存在的时候,lowerdir必须有2个以上 */
		pr_err("overlayfs: at least 2 lowerdir are needed while upperdir nonexistent\n");
		goto out_free_lowertmp;
	}

	stack = kcalloc(stacklen, sizeof(struct path), GFP_KERNEL);
	if (!stack)
		goto out_free_lowertmp;

	lower = lowertmp;
	pr_err("ufs->config.lowerdir: %s, lower: %s\n", ufs->config.lowerdir, lower);
	for (numlower = 0; numlower < stacklen; numlower++) {
		/*
		 * ufs->lower_namelen中记录多个lower中最大的namelen.
		 * sb->s_stack_depth中记录多个lower中最大的s_stack_depth
		 */
		err = ovl_lower_dir(lower, &stack[numlower],
				    &ufs->lower_namelen, &sb->s_stack_depth,
				    &remote);
		if (err)
			goto out_put_lowerpath;

		lower = strchr(lower, '\0') + 1;
	}

	err = -EINVAL;
	sb->s_stack_depth++;
	if (sb->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("overlayfs: maximum fs stacking depth exceeded\n");
		goto out_put_lowerpath;
	}

	if (ufs->config.upperdir) {
		/* clone upperdir所在的vfsmount */
		ufs->upper_mnt = clone_private_mount(&upperpath);
		err = PTR_ERR(ufs->upper_mnt);
		if (IS_ERR(ufs->upper_mnt)) {
			pr_err("overlayfs: failed to clone upperpath\n");
			goto out_put_lowerpath;
		}

		ufs->workdir = ovl_workdir_create(ufs->upper_mnt, workpath.dentry);
		err = PTR_ERR(ufs->workdir);
		if (IS_ERR(ufs->workdir)) {
			/* work创建失败,文件系统将会以只读方式挂载 */
			pr_warn("overlayfs: failed to create directory %s/%s (errno: %i); mounting read-only\n",
				ufs->config.workdir, OVL_WORKDIR_NAME, -err);
			sb->s_flags |= MS_RDONLY;
			ufs->workdir = NULL;
		}
	}

	err = -ENOMEM;
	ufs->lower_mnt = kcalloc(numlower, sizeof(struct vfsmount *), GFP_KERNEL);
	if (ufs->lower_mnt == NULL)
		goto out_put_workdir;
	for (i = 0; i < numlower; i++) {
		struct vfsmount *mnt = clone_private_mount(&stack[i]);

		err = PTR_ERR(mnt);
		if (IS_ERR(mnt)) {
			pr_err("overlayfs: failed to clone lowerpath\n");
			goto out_put_lower_mnt;
		}
		/*
		 * Make lower_mnt R/O.  That way fchmod/fchown on lower file
		 * will fail instead of modifying lower fs.
		 */
		/* 底层dir的内容不会被overlay修改 */
		mnt->mnt_flags |= MNT_READONLY;

		ufs->lower_mnt[ufs->numlower] = mnt;
		ufs->numlower++;
	}

	/* If the upper fs is nonexistent, we mark overlayfs r/o too */
	if (!ufs->upper_mnt)
		sb->s_flags |= MS_RDONLY;

	if (remote)
		sb->s_d_op = &ovl_reval_dentry_operations;
	else
		sb->s_d_op = &ovl_dentry_operations;

	err = -ENOMEM;
	/* 构建overlay   entry给root dir */
	oe = ovl_alloc_entry(numlower);
	if (!oe)
		goto out_put_lower_mnt;

	/* 创建overlayfs的rootdir */
	root_dentry = d_make_root(ovl_new_inode(sb, S_IFDIR, oe));
	if (!root_dentry)
		goto out_free_oe;

	/* 之前获取到的uppper及lower的mnt需要释放 */
	mntput(upperpath.mnt);
	for (i = 0; i < numlower; i++)
		mntput(stack[i].mnt);
	/* lookup出来的work dentry及vfsmount都需要释放 */
	path_put(&workpath);
	kfree(lowertmp);

	oe->__upperdentry = upperpath.dentry;
	for (i = 0; i < numlower; i++) {
		oe->lowerstack[i].dentry = stack[i].dentry;
		oe->lowerstack[i].mnt = ufs->lower_mnt[i];
	}
	kfree(stack);

	root_dentry->d_fsdata = oe;

	ovl_copyattr(ovl_dentry_real(root_dentry)->d_inode,
		     root_dentry->d_inode);

	sb->s_magic = OVERLAYFS_SUPER_MAGIC;
	sb->s_op = &ovl_super_operations;
	sb->s_root = root_dentry;
	sb->s_fs_info = ufs;

	return 0;

out_free_oe:
	kfree(oe);
out_put_lower_mnt:
	for (i = 0; i < ufs->numlower; i++)
		mntput(ufs->lower_mnt[i]);
	kfree(ufs->lower_mnt);
out_put_workdir:
	dput(ufs->workdir);
	mntput(ufs->upper_mnt);
out_put_lowerpath:
	for (i = 0; i < numlower; i++)
		path_put(&stack[i]);
	kfree(stack);
out_free_lowertmp:
	kfree(lowertmp);
out_put_workpath:
	path_put(&workpath);
out_put_upperpath:
	path_put(&upperpath);
out_free_config:
	kfree(ufs->config.lowerdir);
	kfree(ufs->config.upperdir);
	kfree(ufs->config.workdir);
	kfree(ufs);
out:
	return err;
}

static struct dentry *ovl_mount(struct file_system_type *fs_type, int flags,
				const char *dev_name, void *raw_data)
{
	return mount_nodev(fs_type, flags, raw_data, ovl_fill_super);
}

static struct file_system_type ovl_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "overlay",
	.mount		= ovl_mount,
	.kill_sb	= kill_anon_super,
};
MODULE_ALIAS_FS("overlay");

static int __init ovl_init(void)
{
	return register_filesystem(&ovl_fs_type);
}

static void __exit ovl_exit(void)
{
	unregister_filesystem(&ovl_fs_type);
}

module_init(ovl_init);
module_exit(ovl_exit);
