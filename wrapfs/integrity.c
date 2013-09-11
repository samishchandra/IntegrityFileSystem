/* Author: Samish Chandra Kolli
 * Year: 2013
 * This file containes necessary functions to implement integrity checking using 
 * extended attributes on top of wrapfs.
 */

#include "wrapfs.h"

/* Method to get the saved has_integrity
 * Input: lower_path
 * Output: returns the has_integrity flag or error incase of unssuccessful
 * Following are the steps:
 * 1. call vfs_getxattr to fetch the has_integrity
 * 2. corrently set the return value
 */
int has_integrity(struct path lower_path) {

	long retval = 0;
	unsigned char ibuf;

	/* get the existing has_integrity */
	retval = vfs_getxattr(lower_path.dentry, ATTR_HAS_INTEGRITY, &ibuf, 1);
    if(retval<0)
    	retval = 0;
	
	if(ibuf == '0')
		retval = 0;
	else if(ibuf == '1')
		retval = 1;
	else
		retval = -EPERM;

	return retval;
}

/* Method to get the saved crypto hash value
 * Input: lower_path, buffer to store integrity value, size of integrity value
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 * Following are the steps:
 * 1. call vfs_getxattr to fetch the integrity value
 */
long get_integrity(struct path lower_path, unsigned char *ibuf, unsigned int ilen) {
	long retval = 0;

    retval = vfs_getxattr(lower_path.dentry, ATTR_INTEGRITY_VAL, ibuf, ilen);
    if(retval<0) {
    	printk("get_integrity: not able to fetch existing integrity value\n");
    	goto normal_exit;
    }

    retval = 0;

normal_exit:
	return retval;
}

/* Method to set the has_integrity xattr and in turn integrity_val
 * Input: lower_path, char to store against has_integrity xattr key
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 * Following are the steps:
 * 1. call vfs_setxattr to set the has_integrity xattr
 * 2. check whether lower_path represents a directory
 * 3. if it is a regular file and has_integrity=1 then compute the crypto hash
 * 4. store the computed crypto hash against integrity_val (call to the function takes care of dynamic algo type)
 Note: make sure that the lower_parent_dentry is locked before this method is called
 */
long set_has_integrity(struct path lower_path, unsigned char buf) {

	long retval = 0;

	retval = vfs_setxattr(lower_path.dentry, ATTR_HAS_INTEGRITY, &buf, 1, XATTR_CREATE);
	if(retval<0) {
		printk("set_has_integrity: canont set %s!!\n", ATTR_HAS_INTEGRITY);
		goto out;
	}

	/* if inode is a directory then skip the step of computing/removing integrity_val */
	if(S_ISDIR(lower_path.dentry->d_inode->i_mode))
		goto out;

	if(buf == '1') {
		set_integrity_val(lower_path);
		if(retval<0) {
			printk("set_has_integrity: canont set %s!!\n", ATTR_INTEGRITY_VAL);
			goto out;
		}
	}

out:
	return retval;
}


/* Code method to save the crypto hash value against integrity_val xattr key
 * Input: lower_path
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 * Following are the steps:
 * 1. allocate memory for buffer to store the hash value
 * 2. allocate memory for storing algo name
 * 3. fetch algo name using vfs_getxattr
 * 4. call compute_integrity with update flag so that it saves the hash value to xattr
 Note: make sure that the lower_parent_dentry is locked before this method is called
 */
long set_integrity_val(struct path lower_path) {

	long retval = 0;
	unsigned char *ibuf = NULL;
	unsigned int ilen = MAXLEN;
	unsigned char *algo = ATTR_DEFAULTALGO;

	ibuf = (unsigned char*)kmalloc(ilen, GFP_KERNEL);
	if(!ibuf) {
		printk("set_integrity_val: out of memory for ibuf\n");
		retval = -ENOMEM;
		goto out;
	}
	memset(ibuf, '\0', ilen);

#ifdef EXTRA_CREDIT
	/* allocate memory for algo */
	algo = (unsigned char*)kmalloc(MAXLEN_ALGO_NAME, GFP_KERNEL);
	if(!algo) {
		printk("check_integrity: out of memory for algo\n");
		retval = -ENOMEM;
		goto out_free_ibuf;
	}
	memset(algo, '\0', MAXLEN_ALGO_NAME);

	/* get the existing integrity */
	retval = vfs_getxattr(lower_path.dentry, ATTR_INTEGRITY_TYPE, algo, MAXLEN_ALGO_NAME);
    if(retval<0) {
    	if(retval == -ENODATA) {
	    	printk("set_integrity_val: algo name not available, computing integrity with default algo\n");
	    	strcpy(algo, ATTR_DEFAULTALGO);
	    }
	    else {
	    	printk("set_integrity_val: error while fetching algo name\n");
	    	goto out_free_algo;
	    }
    }
#endif

	/* call compute_integrity with update flag */
	retval = compute_integrity(lower_path, ibuf, ilen, 1, algo);

#ifdef EXTRA_CREDIT
out_free_algo:
	kfree(algo);
out_free_ibuf:
#endif
	kfree(ibuf);
out:
	return retval;
}


long update_md5(const char *src, unsigned int len, struct hash_desc *desc) {
	long retval = 0;
	struct scatterlist sg;

	sg_init_one(&sg, src, len);
    retval = crypto_hash_update(desc, &sg, len);
	if(retval) {
		printk("Error updating crypto hash\n");
		goto normal_exit;
	}
   
normal_exit:
	return retval;
}

/* Core method used for running the crypto hash algorithm
 * Input: lower_path, buffer to store integrity value, size of integrity value, 
 	flag to tell whether to update the integrity value, algo to be used
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 * Following are the steps:
 * 1. allocate for crypto transform
 * 2. initialize the crypto hash
 * 3. open the file using dentry_open
 * 4. check if the read/write permissions exist
 * 5. allocate memory for temp buffer to store the chunks of the file
 * 6. read CHUNKSIZE bytes from the file and update the hash value
 * 7. finalize the hash value and write it to ibuf
 * 8. use vfs_setxattr to set the appropriate extended attribute value
 * 9. free the allocated memory accordingly
 */
long compute_integrity(struct path lower_path, unsigned char *ibuf, unsigned int ilen, 
	unsigned int flag, const char *algo) {
	
	long retval = 0;
	struct file *filp; /* for opening the file */
    mm_segment_t oldfs; /* used to restore fs */
    int bytes; 
    char *buffer; /* to store a chunk of a file */
    struct hash_desc desc; /* to compute and update integrity value */
    // int i;
    int digest_size;
	
	if(S_ISREG(lower_path.dentry->d_inode->i_mode)) {

		desc.flags = 0;
		desc.tfm = crypto_alloc_hash(algo, 0, CRYPTO_ALG_ASYNC);
		if(IS_ERR(desc.tfm)) {
			printk("compute_integrity: error attempting to allocate crypto context\n");
			retval = PTR_ERR(desc.tfm);
			goto normal_exit;
		}
		
		/* initialize the crypto hash */
	    retval = crypto_hash_init(&desc);
		if(retval) {
			printk("compute_integrity: error initializing crypto hash\n");
			goto free_hash;
		}

		/* check whether ilen > integrity value len */
		digest_size = crypto_hash_digestsize(desc.tfm);
		if(digest_size > ilen) {
			printk("compute_integrity: buf length is too short to store integrity value\n");
			retval = -EINVAL;
			goto free_hash;
		}
		else
			ilen = digest_size;
		
	    filp = dentry_open(lower_path.dentry, lower_path.mnt, O_RDONLY, current_cred());
	    if (!filp || IS_ERR(filp)) {
	    	printk("compute_integrity: cannot open the file in O_RDONLY mode\n");
	    	retval = (int) PTR_ERR(filp);
			goto free_hash;
	    }

	    filp->f_pos = 0;
		oldfs = get_fs();
		set_fs(KERNEL_DS);

		// // /* check whether read/write is available on the file */
		// // if (!filp->f_op->write) {
		// //    printk("compute_integrity: cannot read/write the file\n");
		// // 	retval = -ENOENT;
		// // 	goto filp_exit;
		// // }

		buffer = (char *)kmalloc(CHUNKSIZE, GFP_KERNEL);
		if(!buffer) {
			printk("compute_integrity: out of memory for buffer\n");
			retval = -ENOMEM;
			goto filp_exit;
		}

		/* read in chunks till the end and keep updating the hash */
		bytes =  filp->f_op->read(filp, buffer, CHUNKSIZE, &filp->f_pos);
		while(bytes>0) {
			retval = update_md5(buffer, bytes, &desc);
			if(retval)
				goto free_buffer;
			
			// buffer[bytes] = '\0';
			// printk("%s\n", buffer);
			bytes =  filp->f_op->read(filp, buffer, CHUNKSIZE, &filp->f_pos);
		}

		/* finalize the integrity value */
		retval = crypto_hash_final(&desc, ibuf);
		if(retval) {
			printk("compute_integrity: error finalizing crypto hash\n");
			goto free_buffer;
		}
	}
#ifdef EXTRA_CREDIT
	else if(S_ISLNK(lower_path.dentry->d_inode->i_mode)) {

		oldfs = get_fs();
		set_fs(KERNEL_DS);

		/* This is freed by the put_link method assuming a successful call. */
		buffer = (char *)kmalloc(CHUNKSIZE, GFP_KERNEL);
		if(!buffer) {
			printk("compute_integrity: out of memory for buffer\n");
			retval = -ENOMEM;
			goto filp_exit;
		}

		/* read the symlink */
		retval = lower_path.dentry->d_inode->i_op->readlink(lower_path.dentry, buffer, CHUNKSIZE);
		if (retval < 0) {
			printk("compute_integrity: cannot read link\n");
			goto free_buffer;
		}
		buffer[retval] = '\0';
		// printk("compute_integrity: %s\n", buffer);

		retval = calculate_integrity(ibuf, buffer, retval, algo);
		if(retval) {
			goto free_buffer;
		}

	}
#endif
	else {
		printk("compute_integrity: file type not supported for integrity\n");
		retval = -EOPNOTSUPP;
		goto normal_exit;
	}


	// printk("%d\n", digest_size);
	// for(i=0;i<ilen;i++)
	// 	printk("%x", ibuf[i]);

	//* update the integrity value if flag is set */
	if(flag) {
		/* set the xattr, if there exists one already replace it */
		/* vfs_setxattr will take care of mutex lock on the inode */
		retval = vfs_setxattr(lower_path.dentry, ATTR_INTEGRITY_VAL, ibuf, ilen, XATTR_CREATE);
	    if(retval<0) {
	    	if(retval == -EEXIST) {
	    		printk("compute_integrity: xattr already exists, replacing the value\n");
	    		retval = vfs_setxattr(lower_path.dentry, ATTR_INTEGRITY_VAL, ibuf, ilen, XATTR_REPLACE);
	    		if(retval<0){
		    		printk("compute_integrity: not able to replace integrity value\n");
		    		goto free_buffer;
		    	}
	    	}
	    	else {
	    		printk("compute_integrity: not able to set integrity value\n");
	    		goto free_buffer;
	    	}
	    }
	}

    retval = 0;

free_buffer:
 	kfree(buffer);
filp_exit:
	set_fs(oldfs);
    // fput(filp);
free_hash:
    crypto_free_hash(desc.tfm);
normal_exit:
	return retval;
}

/* Method to check the integrity of file
 * Compare integrity value with already existing integrity value, if they both match return 1
 * else return respective -EPERM
 * Input: lower_path of the file
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 * Following are the steps:
 * 1. allocate memory for buffer to store the saved hash value
 * 2. allocate memory for storing algo name
 * 3. fetch algo name using vfs_getxattr
 * 4. compute the integrity using helper compute_integrity function
 * 5. compare integrity values: if match return 1; else return -EPERM
 * 6. free the allocated memory accordingly
 */
int check_integrity(struct path lower_path) {

	long retval = 0;
	unsigned char *ibuf1;
	unsigned char *ibuf2;
	char *algo = ATTR_DEFAULTALGO;

	/* allocate memory for ibuf1 */
	ibuf1 = (unsigned char*)kmalloc(MAXLEN, GFP_KERNEL);
	if(!ibuf1) {
		printk("check_integrity: out of memory for ibuf1\n");
		retval = -ENOMEM;
		goto normal_exit;
	}
	memset(ibuf1, '\0', MAXLEN);

	/* get the existing integrity */
	retval = vfs_getxattr(lower_path.dentry, ATTR_INTEGRITY_VAL, ibuf1, MAXLEN);
    if(retval<0) {
    	printk("check_integrity: not able to fetch integrity value\n");
    	goto free_ibuf1;
    }

	/* allocate memory for ibuf2 */
	ibuf2 = (unsigned char*)kmalloc(MAXLEN, GFP_KERNEL);
	if(!ibuf2) {
		printk("check_integrity: out of memory for ibuf2\n");
		retval = -ENOMEM;
		goto free_ibuf1;
	}
	memset(ibuf2, '\0', MAXLEN);


#ifdef EXTRA_CREDIT
	/* allocate memory for algo */
	algo = (unsigned char*)kmalloc(MAXLEN_ALGO_NAME, GFP_KERNEL);
	if(!algo) {
		printk("check_integrity: out of memory for algo\n");
		retval = -ENOMEM;
		goto free_ibuf2;
	}
	memset(algo, '\0', MAXLEN_ALGO_NAME);

	/* get the existing integrity */
	retval = vfs_getxattr(lower_path.dentry, ATTR_INTEGRITY_TYPE, algo, MAXLEN_ALGO_NAME);
    if(retval<0) {
    	if(retval == -ENODATA) {
	    	printk("set_integrity_val: algo name not available, computing integrity with default algo\n");
	    	strcpy(algo, ATTR_DEFAULTALGO);
	    }
	    else {
	    	printk("set_integrity_val: error while fetching algo name\n");
	    	goto out_free_algo;
	    }
    }
#endif

	/* compute the integrity of the file */
	/* call compute_integrity with no update flag */
	// ??? need to fetch the algo from the stored attribute
	retval = compute_integrity(lower_path, ibuf2, MAXLEN, 0, algo);
	if(retval<0) {
		printk("check_integrity: not able to compute integrity value\n");
		goto out_free_algo;
	}

	// for(i=0;i<ilen;i++)
	// 	printk("%x", ibuf[i]);

	// for(i=0;i<ilen;i++)
	// 	printk("%x", ibuf[i]);

	/* compare the integrity */
	if(compare_integrity(ibuf1, ibuf2, MAXLEN))
		retval = 1;
	else
		retval = -EPERM;


out_free_algo:
#ifdef EXTRA_CREDIT
	kfree(algo);
free_ibuf2:
#endif
	kfree(ibuf2);
free_ibuf1:
	kfree(ibuf1);
normal_exit:
	return retval;
}


/* Function checks whether two integrity values match nor not.
 * Input: pointer to first integrity value, pointer to second integrity value
 * Output: return 1 if integrity values match; else return 0
 */
int compare_integrity(unsigned char *ibuf1, unsigned char *ibuf2, unsigned int ilen) {
	unsigned int rc = 1;
	int i;
	for(i=0;i<ilen;i++) {
		if(ibuf1[i] != ibuf2[i]) {
			rc = 0;
			break;
		}
	}
	return rc;
}


/* Method to compute the crpto hash using string src of len and using algo as crypto algo, 
 * the crypto hash is saved in the dest string
 * Input: destination char string to store hash value, source char string on which
 * integirty is computed, length of the source char string, algo to be used
 * Output: return 0 if the all steps are successful; else return respective -ERRNO
 * Following are the steps:
 * 1. initialize the crypto hash
 * 2. open the file using filp_open
 * 3. check if the read/write permissions exist
 * 4. call crypto_hash_update to compute the hash of the src string
 * 5. finalize the hash value and write it to dest
 */
int calculate_integrity(char *dest, char *src, int len, const char *algo) {
    struct scatterlist sg;
    struct hash_desc desc;
    int retval = 0;

    desc.flags = 0;
    desc.tfm = crypto_alloc_hash(algo, 0, CRYPTO_ALG_ASYNC);
    if(IS_ERR(desc.tfm)) {
        printk("calculate_integrity: error attempting to allocate crypto context\n");
        retval= PTR_ERR(desc.tfm);
        goto normal_exit;
    }

	retval= crypto_hash_init(&desc);
    if(retval) {
        printk("calculate_integrity: error initializing crypto hash\n");
        goto normal_exit;
    }

    sg_init_one(&sg, src, len);
     
    retval= crypto_hash_update(&desc, &sg, len);
    if(retval) {
        printk("calculate_integrity: error updating crypto hash\n");
        goto normal_exit;
    }
     
    retval= crypto_hash_final(&desc, dest);
    if(retval) {
        printk("calculate_integrity: error finalizing crypto hash\n");
        goto normal_exit;
    }

normal_exit:
    return retval;
}

