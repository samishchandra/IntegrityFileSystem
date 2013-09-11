/*
 * Copyright (c) 2003-2011 Erez Zadok
 * Copyright (c) 2003-2006 Charles P. Wright
 * Copyright (c) 2005-2007 Josef 'Jeff' Sipek
 * Copyright (c) 2005-2006 Junjiro Okajima
 * Copyright (c) 2005      Arun M. Krishnakumar
 * Copyright (c) 2004-2006 David P. Quigley
 * Copyright (c) 2003-2004 Mohammad Nayyer Zubair
 * Copyright (c) 2003      Puja Gupta
 * Copyright (c) 2003      Harikesavan Krishnan
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"
#include <asm/string.h>


// /* This is lifted from fs/xattr.c */
// void *unionfs_xattr_alloc(size_t size, size_t limit)
// {
// 	void *ptr;

// 	if (size > limit)
// 		return ERR_PTR(-E2BIG);

// 	if (!size)		/* size request, no buffer is needed */
// 		return NULL;

// 	ptr = kmalloc(size, GFP_KERNEL);
// 	if (unlikely(!ptr))
// 		return ERR_PTR(-ENOMEM);
// 	return ptr;
// }


/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
ssize_t wrapfs_getxattr(struct dentry *dentry, const char *name, void *value, size_t size)
{
    struct dentry *lower_dentry = NULL;
    int retval = -EOPNOTSUPP;
    struct dentry *lower_parent_dentry = NULL;
    struct path lower_path;

    if(name == NULL) {
		printk("wrapfs_getxattr: name cannot be NULL\n");
		retval = -EINVAL;
		goto out;
	}

	// ??? ask whether we need to check the input arguments for this method
	// if(!strcmp(name, ATTR_HAS_INTEGRITY)) {
	// 	if(size != 1) {
	// 		printk("wrapfs_setxattr: size=%d\n", size);
	// 		retval = -EINVAL;
	// 		goto out;
	// 	}
	// }

	// if(!strcmp(name, ATTR_INTEGRITY_VAL)) {
	// 	if(size <= 1 || size>=MAXLEN) {
	// 		printk("wrapfs_setxattr: size=%d\n", size);
	// 		retval = -EINVAL;
	// 		goto out;
	// 	}
	// }

    /* get the lower level path from the given wrapfs dentry */
    wrapfs_get_lower_path(dentry, &lower_path);
    lower_dentry = lower_path.dentry;

    /* lock the lower parent dentry object */
    lower_parent_dentry = lock_parent(lower_dentry);
    
    // printk("xattr.c: wrapfs_getxattr: calling vfs_getxattr\n");
    printk("xattr.c: wrapfs_getxattr: name=%s, size=%d\n", name, size);

    retval = vfs_getxattr(lower_dentry, (char *) name, (void *) value, size);

    /* unlock lower parent dentry object */
    unlock_dir(lower_parent_dentry);
    wrapfs_put_lower_path(dentry, &lower_path);

out:
    return retval;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
int wrapfs_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
	struct dentry *lower_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
    struct path lower_path;
	int retval = -EOPNOTSUPP;
	int integrity_val = -1;
	int temp_retval;
#ifdef EXTRA_CREDIT
	char *integrity_type;
	unsigned char ibuf;
#endif

	if(name == NULL || value == NULL) {
		printk("wrapfs_setxattr: name/value cannot be NULL\n");
		retval = -EINVAL;
		goto out;
	}

	if(!strcmp(name, ATTR_INTEGRITY_VAL)) {
		printk("wrapfs_setxattr: cannot set %s\n", ATTR_INTEGRITY_VAL);
		retval = -EOPNOTSUPP;
		goto out;
	}

	if(!strcmp(name, ATTR_HAS_INTEGRITY)) {
		if(!(current_uid() == 0)) {		
			printk("wrapfs_setxattr: only root can set the specified xattr\n");
			retval = -EOPNOTSUPP;
			goto out;
		}

		if(size != 1) {
			printk("wrapfs_setxattr: size is not 1\n");
			retval = -EINVAL;
			goto out;
		}

		integrity_val = *((char*)(value)) - '0';
		if(integrity_val != 0 && integrity_val != 1) {
			printk("wrapfs_setxattr: %s cannot have value=%d\n", ATTR_HAS_INTEGRITY, integrity_val);
			retval = -EINVAL;
			goto out;
		}
		
	}

#ifdef EXTRA_CREDIT
	if(!strcmp(name, ATTR_INTEGRITY_TYPE)) {
		if(!(current_uid() == 0)) {
			printk("wrapfs_setxattr: only root can set the specified xattr\n");
			retval = -EOPNOTSUPP;
			goto out;
		}

		if(!(size > 0 && size <= MAXLEN_ALGO_NAME)) {
			printk("wrapfs_setxattr: size provided is not valid\n");
			retval = -EINVAL;
			goto out;
		}

		integrity_type = (char*)value;
		integrity_type[size] = '\0';

		retval = crypto_has_alg(integrity_type, 1, 1);
		if(!retval) {
			printk("wrapfs_setxattr: crypto algo [%s] not supported \n", integrity_type);
			retval = -EINVAL;
			goto out;
		}
	}
#endif


	/* get the lower level path from the given wrapfs dentry */
    wrapfs_get_lower_path(dentry, &lower_path);
    lower_dentry = lower_path.dentry;

    /* lock the lower parent dentry object */
    lower_parent_dentry = lock_parent(lower_dentry);

    if(S_ISLNK(lower_dentry->d_inode->i_mode))
		printk("wrapfs_setxattr: test message\n");

    if(!S_ISREG(lower_dentry->d_inode->i_mode) &&
    	 !S_ISDIR(lower_dentry->d_inode->i_mode) &&
#ifdef EXTRA_CREDIT
    	 !S_ISLNK(lower_dentry->d_inode->i_mode) &&
#endif
    	 integrity_val != -1) {
			printk("wrapfs_setxattr: file type not supported for integrity\n");
			retval = -EOPNOTSUPP;
			goto unlock_out;
	}

    // printk("xattr.c: wrapfs_setxattr: calling vfs_setxattr\n");
    // ??? remove the (char *) value in the below line the '/0' is not sure to be set!
    // printk("xattr.c: wrapfs_setxattr: name=%s, value=%c, size=%d\n", (char *) name, *((char *) value), size);

	retval = vfs_setxattr(lower_dentry, (char *) name, (void *) value, size, flags);
	if(retval<0) {
		printk("wrapfs_setxattr: %s cannot be set!!\n", name);
		goto unlock_out;
	}

	/* if inode is a directory then skip the step of computing/removing integrity_val */
	if(S_ISDIR(lower_dentry->d_inode->i_mode))
		goto unlock_out;

	// printk("xattr.c: wrapfs_setxattr: not directory!!\n");

#ifdef EXTRA_CREDIT
	/* when integrity_type is set, we need to recompute the integrity_val*/
	if(integrity_val == -1)
	{
		vfs_getxattr(lower_dentry, ATTR_HAS_INTEGRITY, &ibuf, 1);
		if(ibuf == '1')
			integrity_val = 1;
	}
#endif

	if(integrity_val == 1) {
		retval = set_integrity_val(lower_path);
		if(retval<0) {
			retval = -EPERM;
			printk("xattr.c: wrapfs_setxattr: %s cannot be set!!\n", ATTR_INTEGRITY_VAL);
		}
	}
	else if(integrity_val == 0) {
		/* also remove the ATTR_INTEGRITY_VAL attribute 
		error should not be thrown if the integrity_val doesn't exist */
		temp_retval = vfs_removexattr(lower_dentry, ATTR_INTEGRITY_VAL);
		if(temp_retval == -ENODATA) {
			printk("%s already removed!!\n", ATTR_INTEGRITY_VAL);
		}
		else
			retval = temp_retval;
	}

unlock_out:
	/* unlock lower parent dentry object */
    unlock_dir(lower_parent_dentry);
    wrapfs_put_lower_path(dentry, &lower_path);
out:
	return retval;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */

/*


name already gets prefixed with "user.", if called from user land

*/

int wrapfs_removexattr(struct dentry *dentry, const char *name)
{
	struct dentry *lower_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
    struct path lower_path;
	int retval = -EOPNOTSUPP;
	int remove_integrity_val = 0;
	int temp_retval;
#ifdef EXTRA_CREDIT
	int update_integrity_val = 0;
#endif

	if(name == NULL) {
		printk("wrapfs_removexattr: name cannot be NULL\n");
		retval = -EINVAL;
		goto out;
	}

	if(!strcmp(name, ATTR_INTEGRITY_VAL)) {
		printk("wrapfs_removexattr: cannot remove %s\n", ATTR_INTEGRITY_VAL);
		retval = -EOPNOTSUPP;
		goto out;
	}

	if(!strcmp(name, ATTR_HAS_INTEGRITY)) {
		if(!(current_uid() == 0)) {		
			printk("wrapfs_removexattr: only root can remove the specified xattr\n");
			retval = -EOPNOTSUPP;
			goto out;
		}

		remove_integrity_val = 1;
	}

#ifdef EXTRA_CREDIT
	if(!strcmp(name, ATTR_INTEGRITY_TYPE)) {
		if(!(current_uid() == 0)) {		
			printk("wrapfs_removexattr: only root can remove the specified xattr\n");
			retval = -EOPNOTSUPP;
			goto out;
		}

		update_integrity_val = 1;
	}
#endif

	/* get the lower level path from the given wrapfs dentry */
    wrapfs_get_lower_path(dentry, &lower_path);
    lower_dentry = lower_path.dentry;

    /* lock the lower parent dentry object */
    lower_parent_dentry = lock_parent(lower_dentry);
    
    // printk("xattr.c: wrapfs_removexattr: calling vfs_removexattr\n");
    // ??? remove the (char *) value in the below line the '/0' is not sure to be set!
    // printk("xattr.c: wrapfs_removexattr: name=%s\n", (char *) name);

	retval = vfs_removexattr(lower_dentry, (char *) name);
	if(retval<0) {
		if(retval == -ENODATA)
			printk("wrapfs_removexattr: %s already removed!!\n", name);
		else
			printk("wrapfs_removexattr: %s is not removed!!\n", name);
		goto unlock_out;
	}

	if(remove_integrity_val) {
		/* also remove the ATTR_INTEGRITY_VAL attribute 
		error should not be thrown if the integrity_val doesn't exist */
		temp_retval = vfs_removexattr(lower_dentry, ATTR_INTEGRITY_VAL);
		if(temp_retval == -ENODATA) {
			printk("%s already removed!!\n", ATTR_INTEGRITY_VAL);
		}
		else {
			retval = temp_retval;
			goto unlock_out;
		}

#ifdef EXTRA_CREDIT
		temp_retval = vfs_removexattr(lower_dentry, ATTR_INTEGRITY_TYPE);
		if(temp_retval == -ENODATA) {
			printk("%s already removed!!\n", ATTR_INTEGRITY_TYPE);
		}
		else {
			retval = temp_retval;
			goto unlock_out;
		}
#endif
	}

#ifdef EXTRA_CREDIT
	if(update_integrity_val == 1) {
		retval = set_integrity_val(lower_path);
		if(retval<0) {
			printk("xattr.c: wrapfs_removexattr: %s cannot be set!!\n", ATTR_INTEGRITY_VAL);
		}
	}
#endif

unlock_out:
	/* unlock lower parent dentry object */
    unlock_dir(lower_parent_dentry);
    wrapfs_put_lower_path(dentry, &lower_path);
out:
    return retval;
}

/*
 * BKL held by caller.
 * dentry->d_inode->i_mutex locked
 */
ssize_t wrapfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	struct dentry *lower_dentry = NULL;
	struct dentry *lower_parent_dentry = NULL;
    struct path lower_path;
	int retval = -EOPNOTSUPP;
	char *encoded_list = NULL;
	
	/* get the lower level path from the given wrapfs dentry */
    wrapfs_get_lower_path(dentry, &lower_path);
    lower_dentry = lower_path.dentry;

    /* lock the lower parent dentry object */
    lower_parent_dentry = lock_parent(lower_dentry);
    
    // printk("xattr.c: wrapfs_listxattr: calling vfs_listxattr\n");
    // printk("xattr.c: wrapfs_listxattr: size=%d\n", size);

	encoded_list = list;
	retval = vfs_listxattr(lower_dentry, encoded_list, size);

	/* unlock lower parent dentry object */
    unlock_dir(lower_parent_dentry);
    wrapfs_put_lower_path(dentry, &lower_path);
    return retval;
}



