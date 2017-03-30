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
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/xattr.h>
#include <linux/rbtree.h>
#include <linux/security.h>
#include <linux/cred.h>
#include "overlayfs.h"

struct ovl_cache_entry {
	/* name的长度 */
	unsigned int len;
	unsigned int type;
	u64 ino;
	/* 链表成员,链表头是ovl_readdir_data->list,或者ovl_readdir_data->middle           */
	struct list_head l_node;
	/* 红黑树节点 */
	struct rb_node node;
	struct ovl_cache_entry *next_maybe_whiteout;
	bool is_whiteout;
	char name[];
};

/* 保存在dentry->d_fsdata(ovl_dir_cache)中 */
struct ovl_dir_cache {
	long refcount;
	u64 version;
	/* 链表头,将目录下所有的文件的ovl_cache_entry链接起来 */
	struct list_head entries;
};

/* ovl_dir_read_merged中使用的临时数据结构 */
struct ovl_readdir_data {
	struct dir_context ctx;
	bool is_merge;
	/* 用于查找的rbt-tree的root,这个root是临时数据 */
	struct rb_root root;
	/* 链表头(指向ovl_dir_cache->list的地址)链表成员是ovl_cache_entry->l_node,链接非最底层的cache entry                */
	struct list_head *list;
	/* 链表头,链接最底层的cache entry用的临时链表头 */
	struct list_head middle;
	struct ovl_cache_entry *first_maybe_whiteout;
	/* 成功读取目录项的个数,包含"."和".." */
	int count;
	int err;
};

/* 保存在file->private_data */
struct ovl_dir_file {
	/* 判断是否是upper及lower合并的目录.1表示是非merge的目录 */
	bool is_real;
	/* 判断其realpath属于upper还是lower */
	bool is_upper;
	struct ovl_dir_cache *cache;
	/* 类似于文件指针,指向下个需要处理的目录项 */
	struct list_head *cursor;
	struct file *realfile;
	struct file *upperfile;
};

/* 从红黑树节点获取cache节点 */
static struct ovl_cache_entry *ovl_cache_entry_from_node(struct rb_node *n)
{
	return container_of(n, struct ovl_cache_entry, node);
}

static struct ovl_cache_entry *ovl_cache_entry_find(struct rb_root *root,
						    const char *name, int len)
{
	struct rb_node *node = root->rb_node;
	int cmp;

	while (node) {
		struct ovl_cache_entry *p = ovl_cache_entry_from_node(node);

		cmp = strncmp(name, p->name, len);
		if (cmp > 0)
			node = p->node.rb_right;
		else if (cmp < 0 || len < p->len)
			node = p->node.rb_left;
		else
			return p;
	}

	return NULL;
}

static struct ovl_cache_entry *ovl_cache_entry_new(struct ovl_readdir_data *rdd,
						   const char *name, int len,
						   u64 ino, unsigned int d_type)
{
	struct ovl_cache_entry *p;
	size_t size = offsetof(struct ovl_cache_entry, name[len + 1]);

	p = kmalloc(size, GFP_KERNEL);
	if (!p)
		return NULL;

	memcpy(p->name, name, len);
	p->name[len] = '\0';
	p->len = len;
	p->type = d_type;
	p->ino = ino;
	p->is_whiteout = false;

	/* 当文件类型是字符设备的时候 */
	if (d_type == DT_CHR) {
		/* 将p加入first_maybe_whiteout */
		p->next_maybe_whiteout = rdd->first_maybe_whiteout;
		rdd->first_maybe_whiteout = p;
	}
	return p;
}

static int ovl_cache_entry_add_rb(struct ovl_readdir_data *rdd,
				  const char *name, int len, u64 ino,
				  unsigned int d_type)
{
	struct rb_node **newp = &rdd->root.rb_node;
	struct rb_node *parent = NULL;
	struct ovl_cache_entry *p;

	while (*newp) {
		int cmp;
		struct ovl_cache_entry *tmp;

		parent = *newp;
		tmp = ovl_cache_entry_from_node(*newp);
		cmp = strncmp(name, tmp->name, len);
		if (cmp > 0)
			newp = &tmp->node.rb_right;
		else if (cmp < 0 || len < tmp->len)
			newp = &tmp->node.rb_left;
		else
			/* 如果在rb-tree中找到对应的节点,rdd->root.rb_node中就记录这个节点,并且返回 */
			return 0;
	}

	p = ovl_cache_entry_new(rdd, name, len, ino, d_type);
	if (p == NULL)
		return -ENOMEM;

	list_add_tail(&p->l_node, rdd->list);
	/* 将这个节点插入父节点 */
	rb_link_node(&p->node, parent, newp);
	rb_insert_color(&p->node, &rdd->root);

	return 0;
}

static int ovl_fill_lower(struct ovl_readdir_data *rdd,
			  const char *name, int namelen,
			  loff_t offset, u64 ino, unsigned int d_type)
{
	struct ovl_cache_entry *p;

	/*
	 * 在rb-tree中查找name节点,   有的话就不创建,也就是说如果upper dir中存在对应文件,
	 * lower dir中的文件不会加入dir cache.
	 */
	p = ovl_cache_entry_find(&rdd->root, name, namelen);
	if (p) {
		/* 在rb-tree中找到p */
		list_move_tail(&p->l_node, &rdd->middle);
	} else {
		/* 在rb-tree中没找到p,创建一个新的节点,加入rdd->middle */
		p = ovl_cache_entry_new(rdd, name, namelen, ino, d_type);
		if (p == NULL)
			rdd->err = -ENOMEM;
		else
			list_add_tail(&p->l_node, &rdd->middle);
	}

	return rdd->err;
}

void ovl_cache_free(struct list_head *list)
{
	struct ovl_cache_entry *p;
	struct ovl_cache_entry *n;

	list_for_each_entry_safe(p, n, list, l_node)
		kfree(p);

	INIT_LIST_HEAD(list);
}

static void ovl_cache_put(struct ovl_dir_file *od, struct dentry *dentry)
{
	struct ovl_dir_cache *cache = od->cache;

	WARN_ON(cache->refcount <= 0);
	cache->refcount--;
	/* refcount减少到0,就需要释放这个cache */
	if (!cache->refcount) {
		if (ovl_dir_cache(dentry) == cache)
			ovl_set_dir_cache(dentry, NULL);

		ovl_cache_free(&cache->entries);
		kfree(cache);
	}
}

static int ovl_fill_merge(struct dir_context *ctx, const char *name,
			  int namelen, loff_t offset, u64 ino,
			  unsigned int d_type)
{
	/* 通过ctx获取到ovl_readdir_data */
	struct ovl_readdir_data *rdd =
		container_of(ctx, struct ovl_readdir_data, ctx);

	/* 成功读取一条目录项 */
	rdd->count++;
	if (!rdd->is_merge)
		/* 非最低层的dir */
		return ovl_cache_entry_add_rb(rdd, name, namelen, ino, d_type);
	else
		/* 最底层的dir */
		return ovl_fill_lower(rdd, name, namelen, offset, ino, d_type);
}

static int ovl_check_whiteouts(struct dentry *dir, struct ovl_readdir_data *rdd)
{
	int err;
	struct ovl_cache_entry *p;
	struct dentry *dentry;
	const struct cred *old_cred;
	struct cred *override_cred;

	override_cred = prepare_creds();
	if (!override_cred)
		return -ENOMEM;

	/*
	 * CAP_DAC_OVERRIDE for lookup
	 */
	cap_raise(override_cred->cap_effective, CAP_DAC_OVERRIDE);
	old_cred = override_creds(override_cred);

	err = mutex_lock_killable(&dir->d_inode->i_mutex);
	if (!err) {
		while (rdd->first_maybe_whiteout) {
			p = rdd->first_maybe_whiteout;
			rdd->first_maybe_whiteout = p->next_maybe_whiteout;
			dentry = lookup_one_len(p->name, dir, p->len);
			if (!IS_ERR(dentry)) {
				p->is_whiteout = ovl_is_whiteout(dentry);
				dput(dentry);
			}
		}
		mutex_unlock(&dir->d_inode->i_mutex);
	}
	revert_creds(old_cred);
	put_cred(override_cred);

	return err;
}

static inline int ovl_dir_read(struct path *realpath,
			       struct ovl_readdir_data *rdd)
{
	struct file *realfile;
	int err;

	/* 打开一个真正的path,获取file* */
	realfile = ovl_path_open(realpath, O_RDONLY | O_DIRECTORY);
	if (IS_ERR(realfile))
		return PTR_ERR(realfile);

	rdd->first_maybe_whiteout = NULL;
	rdd->ctx.pos = 0;
	/* 正常情况下,一次循环就能读取所有的目录项 */
	do {
		rdd->count = 0;
		rdd->err = 0;
		/* 读取真正文件的目录项,用ovl_fill_merge填充,ctx->pos是实际fs目录项的偏移 */
		err = iterate_dir(realfile, &rdd->ctx);
		if (err >= 0)
			err = rdd->err;
	} while (!err && rdd->count);

	if (!err && rdd->first_maybe_whiteout)
		err = ovl_check_whiteouts(realpath->dentry, rdd);

	fput(realfile);

	return err;
}

static void ovl_dir_reset(struct file *file)
{
	struct ovl_dir_file *od = file->private_data;
	/* 获取到目录的缓存 */
	struct ovl_dir_cache *cache = od->cache;
	struct dentry *dentry = file->f_path.dentry;
	enum ovl_path_type type = ovl_path_type(dentry);

	if (cache && ovl_dentry_version_get(dentry) != cache->version) {
		/* 存在cache,但是cache和dentry的version不匹配,清除这个ovl_dir_file的cache指向 */
		ovl_cache_put(od, dentry);
		od->cache = NULL;
		od->cursor = NULL;
	}
	WARN_ON(!od->is_real && !OVL_TYPE_MERGE(type));
	/* 在ovl_dir_open中od->is_real = !OVL_TYPE_MERGE(type); */
	if (od->is_real && OVL_TYPE_MERGE(type))
		od->is_real = false;
}

/*
 * 读取merged dir, readdir时,每个dir分配一个dir cache,每个cache将当前目录下所有文件的name,
 * ino, type等信息记录到ovl_cache_entry,这些entry和 dir cache关联起来
 */
static int ovl_dir_read_merged(struct dentry *dentry, struct list_head *list)
{
	int err;
	struct path realpath;
	/* 每次读取merged目录就需要一个ovl_readdir_data */
	struct ovl_readdir_data rdd = {
		.ctx.actor = ovl_fill_merge,
		.list = list,
		.root = RB_ROOT,
		.is_merge = false,
	};
	int idx, next;

	/* merge dir中显示的内容可能是多层目录叠加的结果,所以要遍历这些叠加的目录 */
	for (idx = 0; idx != -1; idx = next) {
		next = ovl_path_next(idx, dentry, &realpath);

		if (next != -1) {
			/* 非最底层的dir */
			err = ovl_dir_read(&realpath, &rdd);
			if (err)
				break;
		} else {
			/*
			 * Insert lowest layer entries before upper ones, this
			 * allows offsets to be reasonably constant
			 */
			/*
			 * 最底层的dir, 其文件cache entry链接到middle中, 这个middle头插如list.
			 * 也就是说lower dir中ovl_cache_entry头插入rdd.list.
			 */
			list_add(&rdd.middle, rdd.list);
			rdd.is_merge = true;
			err = ovl_dir_read(&realpath, &rdd);
			list_del(&rdd.middle);
		}
	}
	return err;
}

static void ovl_seek_cursor(struct ovl_dir_file *od, loff_t pos)
{
	struct list_head *p;
	loff_t off = 0;

	list_for_each(p, &od->cache->entries) {
		/* 1个字节表示一个目录项,偏移到合适的目录项 */
		if (off >= pos)
			break;
		off++;
	}
	/* Cursor is safe since the cache is stable */
	od->cursor = p;
}

static struct ovl_dir_cache *ovl_cache_get(struct dentry *dentry)
{
	int res;
	struct ovl_dir_cache *cache;

	cache = ovl_dir_cache(dentry);
	/* 如果有cache,需要匹配dentry和cache的version */
	if (cache && ovl_dentry_version_get(dentry) == cache->version) {
		cache->refcount++;
		return cache;
	}
	/* cache初始化为NULL */
	ovl_set_dir_cache(dentry, NULL);

	cache = kzalloc(sizeof(struct ovl_dir_cache), GFP_KERNEL);
	if (!cache)
		return ERR_PTR(-ENOMEM);

	cache->refcount = 1;
	INIT_LIST_HEAD(&cache->entries);

	res = ovl_dir_read_merged(dentry, &cache->entries);
	if (res) {
		ovl_cache_free(&cache->entries);
		kfree(cache);
		return ERR_PTR(res);
	}

	cache->version = ovl_dentry_version_get(dentry);
	ovl_set_dir_cache(dentry, cache);

	return cache;
}

/* overlay readdir回调 */
static int ovl_iterate(struct file *file, struct dir_context *ctx)
{
	struct ovl_dir_file *od = file->private_data;
	struct dentry *dentry = file->f_path.dentry;
	struct ovl_cache_entry *p;

	if (!ctx->pos)
		ovl_dir_reset(file);

	/* 对于不是merge的dir,不需要用cache将upper dir和lower dir中的文件链接起来 */
	if (od->is_real)
		return iterate_dir(od->realfile, ctx);

	if (!od->cache) {
		/* 没有cache,需要创建 */
		struct ovl_dir_cache *cache;

		cache = ovl_cache_get(dentry);
		if (IS_ERR(cache))
			return PTR_ERR(cache);

		/* ovl_dir_file->cache指向dentry->ovl_entry->cache */
		od->cache = cache;
		ovl_seek_cursor(od, ctx->pos);
	}

	while (od->cursor != &od->cache->entries) {
		/* 通过链表获取到ovl_cache_entry */
		p = list_entry(od->cursor, struct ovl_cache_entry, l_node);
		if (!p->is_whiteout)
			/* 调用通用遍历器filldir,将数据拷贝到用户空间 */
			if (!dir_emit(ctx, p->name, p->len, p->ino, p->type))
				break;
		od->cursor = p->l_node.next;
		/* overlayfs中一个目录项长度是1,记录当前目录下有多少个文件(目录,包含'.','..') */
		ctx->pos++;
	}

	return 0;
}

static loff_t ovl_dir_llseek(struct file *file, loff_t offset, int origin)
{
	loff_t res;
	struct ovl_dir_file *od = file->private_data;

	mutex_lock(&file_inode(file)->i_mutex);
	if (!file->f_pos)
		ovl_dir_reset(file);

	/* 如果dir不是由overlayfs merged的 */
	if (od->is_real) {
		res = vfs_llseek(od->realfile, offset, origin);
		file->f_pos = od->realfile->f_pos;
	} else {
		res = -EINVAL;

		switch (origin) {
		case SEEK_CUR:
			offset += file->f_pos;
			break;
		case SEEK_SET:
			break;
		default:
			goto out_unlock;
		}
		if (offset < 0)
			goto out_unlock;

		if (offset != file->f_pos) {
			file->f_pos = offset;
			if (od->cache)
				ovl_seek_cursor(od, offset);
		}
		res = offset;
	}
out_unlock:
	mutex_unlock(&file_inode(file)->i_mutex);

	return res;
}

/* ovl_entry和ovl_dir_file可能不同步,执行sync的时候,将这两个缓存同步 */
static int ovl_dir_fsync(struct file *file, loff_t start, loff_t end,
			 int datasync)
{
	struct ovl_dir_file *od = file->private_data;
	struct dentry *dentry = file->f_path.dentry;
	struct file *realfile = od->realfile;

	/*
	 * Need to check if we started out being a lower dir, but got copied up
	 */
	/* 当查看ovl_dir_file发现realpath没有upper dir.但是dentry->ovl_entry却有upper dir */
	if (!od->is_upper && OVL_TYPE_UPPER(ovl_path_type(dentry))) {
		struct inode *inode = file_inode(file);

		/* 当is_upper是false,od->upperfile应该是NULL */
		realfile = lockless_dereference(od->upperfile);
		if (!realfile) {
			struct path upperpath;

			ovl_path_upper(dentry, &upperpath);
			realfile = ovl_path_open(&upperpath, O_RDONLY);
			smp_mb__before_spinlock();
			mutex_lock(&inode->i_mutex);
			if (!od->upperfile) {
				if (IS_ERR(realfile)) {
					mutex_unlock(&inode->i_mutex);
					return PTR_ERR(realfile);
				}
				od->upperfile = realfile;
			} else {
				/* 如果od->upperfile不是空 */
				/* somebody has beaten us to it */
				if (!IS_ERR(realfile))
					fput(realfile);
				realfile = od->upperfile;
			}
			mutex_unlock(&inode->i_mutex);
		}
	}

	return vfs_fsync_range(realfile, start, end, datasync);
}

static int ovl_dir_release(struct inode *inode, struct file *file)
{
	struct ovl_dir_file *od = file->private_data;

	if (od->cache) {
		mutex_lock(&inode->i_mutex);
		ovl_cache_put(od, file->f_path.dentry);
		mutex_unlock(&inode->i_mutex);
	}
	/* 在dentry_open中get */
	fput(od->realfile);
	if (od->upperfile)
		fput(od->upperfile);
	kfree(od);

	return 0;
}

static int ovl_dir_open(struct inode *inode, struct file *file)
{
	struct path realpath;
	struct file *realfile;
	struct ovl_dir_file *od;
	enum ovl_path_type type;

	od = kzalloc(sizeof(struct ovl_dir_file), GFP_KERNEL);
	if (!od)
		return -ENOMEM;

	/* realpath可能是lower dir 也可能是upper dir中的 */
	type = ovl_path_real(file->f_path.dentry, &realpath);
	/* 将file->flag复制到realpath */
	realfile = ovl_path_open(&realpath, file->f_flags);
	if (IS_ERR(realfile)) {
		kfree(od);
		return PTR_ERR(realfile);
	}
	od->realfile = realfile;
	od->is_real = !OVL_TYPE_MERGE(type);
	od->is_upper = OVL_TYPE_UPPER(type);
	/* 将ovl_dir_file保存在file->private_data中 */
	file->private_data = od;

	return 0;
}

const struct file_operations ovl_dir_operations = {
	.read		= generic_read_dir,
	.open		= ovl_dir_open,
	.iterate	= ovl_iterate,
	.llseek		= ovl_dir_llseek,
	.fsync		= ovl_dir_fsync,
	.release	= ovl_dir_release,
};

int ovl_check_empty_dir(struct dentry *dentry, struct list_head *list)
{
	int err;
	struct ovl_cache_entry *p;

	err = ovl_dir_read_merged(dentry, list);
	if (err)
		return err;

	err = 0;

	list_for_each_entry(p, list, l_node) {
		if (p->is_whiteout)
			continue;

		if (p->name[0] == '.') {
			if (p->len == 1)
				continue;
			if (p->len == 2 && p->name[1] == '.')
				continue;
		}
		err = -ENOTEMPTY;
		break;
	}

	return err;
}

void ovl_cleanup_whiteouts(struct dentry *upper, struct list_head *list)
{
	struct ovl_cache_entry *p;

	mutex_lock_nested(&upper->d_inode->i_mutex, I_MUTEX_CHILD);
	list_for_each_entry(p, list, l_node) {
		struct dentry *dentry;

		if (!p->is_whiteout)
			continue;

		dentry = lookup_one_len(p->name, upper, p->len);
		if (IS_ERR(dentry)) {
			pr_err("overlayfs: lookup '%s/%.*s' failed (%i)\n",
			       upper->d_name.name, p->len, p->name,
			       (int) PTR_ERR(dentry));
			continue;
		}
		if (dentry->d_inode)
			ovl_cleanup(upper->d_inode, dentry);
		dput(dentry);
	}
	mutex_unlock(&upper->d_inode->i_mutex);
}
