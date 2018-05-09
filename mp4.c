#define pr_fmt(fmt) "cs423_mp4: " fmt

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>
#include <linux/slab.h>
#include "mp4_given.h"

/**
 * get_inode_sid - Get the inode mp4 security label id
 *
 * @inode: the input inode
 *
 * @return the inode's security id if found.
 *
 */
static int get_inode_sid(struct inode *inode)
{
	struct dentry *dentry;
	int sid, rc, len;
	char *context;
	
	len = 100; 

	pr_info("Inside get_inode_sid\n");

	context = kmalloc(len, GFP_KERNEL);
	if (!context) {
		pr_err("context buffer not allocated\n");
		return 0;
	}
	
	dentry = d_find_alias(inode);
	if (dentry == NULL){
		return -ENOENT;
	}
	
	rc = inode->i_op->getxattr(dentry, XATTR_NAME_MP4, context, len);
	len=rc;

	if (rc == -ERANGE) {
		dput(dentry);
		pr_err("rc bigger than range\n");
		return 0;
	}
	
	dput(dentry);
	context[len] = '\0';
	sid = __cred_ctx_to_sid(context);
	pr_info("got sid %d\n", sid);
	kfree(context);
	return sid;
	
}


/**
 * mp4_bprm_set_creds - Set the credentials for a new task
 *
 * @bprm: The linux binary preparation structure
 *
 * returns 0 on success.
 */
static int mp4_bprm_set_creds(struct linux_binprm *bprm)
{
	int sid;
	struct mp4_security* new_label;
	struct inode *inode = bprm->file->f_path.dentry->d_inode;
	
	if (!inode) return 0;	

	new_label->mp4_flags = MP4_TARGET_SID;

	sid = get_inode_sid(inode);
	if (sid == MP4_TARGET_SID) {
		bprm->cred->security = new_label;
	}
	pr_info("completing bprm_set_creds\n");
	return 0;
}

/**
 * mp4_cred_alloc_blank - Allocate a blank mp4 security label
 *
 * @cred: the new credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct mp4_security* new_label;
	new_label = (struct mp4_security*) kmalloc(sizeof(struct mp4_security), gfp);
	if (new_label == NULL) {
		return -ENOMEM;
	}
	new_label->mp4_flags = MP4_NO_ACCESS;
	cred->security = new_label;
	pr_info("completed allocating blank credentials\n");
	return 0;
}


/**
 * mp4_cred_free - Free a created security label
 *
 * @cred: the credentials struct
 *
 */
static void mp4_cred_free(struct cred *cred)
{
	cred->security = NULL;
	kfree(cred->security);
}

/**
 * mp4_cred_prepare - Prepare new credentials for modification
 *
 * @new: the new credentials
 * @old: the old credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_prepare(struct cred *new, const struct cred *old,
			    gfp_t gfp)
{
	mp4_cred_alloc_blank(new, gfp);
	if (old->security) {
		new->security = old->security;
	}	
	return 0;
}

/**
 * mp4_inode_init_security - Set the security attribute of a newly created inode
 *
 * @inode: the newly created inode
 * @dir: the containing directory
 * @qstr: unused
 * @name: where to put the attribute name
 * @value: where to put the attribute value
 * @len: where to put the length of the attribute
 *
 * returns 0 if all goes well, -ENOMEM if no memory, -EOPNOTSUPP to skip
 *
 */
static int mp4_inode_init_security(struct inode *inode, struct inode *dir,
				   const struct qstr *qstr,
				   const char **name, void **value, size_t *len)
{
	int sid = get_inode_sid(inode);

	char *namep = NULL;
	char *valuep = NULL;

	if (!inode || !dir || !current_cred()) return -EOPNOTSUPP;
	
	if (!(struct mp4_security*)(current_cred()->security)) return -EOPNOTSUPP; 

	if (sid == MP4_TARGET_SID) {
		namep=kstrdup(XATTR_NAME_MP4, GFP_KERNEL);
		if (!namep) return -ENOMEM;
		*name = namep;
		
		if (S_ISDIR(inode->i_mode)) {
			valuep = kstrdup("dir-write", GFP_KERNEL);
		} else {
			valuep = kstrdup("read-write", GFP_KERNEL);
		}
	
		if (!valuep) return -ENOMEM;
		*value = valuep;

		*len = sizeof(XATTR_NAME_MP4);
	}
	return 0;
}

/**
 * mp4_has_permission - Check if subject has permission to an object
 *
 * @ssid: the subject's security id
 * @osid: the object's security id
 * @mask: the operation mask
 *
 * returns 0 is access granter, -EACCES otherwise
 *
 */
static int mp4_has_permission(int ssid, int osid, int mask)
{
	if (ssid == MP4_NO_ACCESS) {
		if (osid == 0){
			if (!(mask & MAY_ACCESS)) {
				//ACESS DENIED
				pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
				return -EACCES;
			}
		} else if (osid == 1 || osid == 2 || osid == 3) {
			if (!(mask & MAY_READ)) {
				//ACCESS DENIED
				pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
				return -EACCES;		
			}
		} else if (osid == 4) {
			if (!(mask & (MAY_READ | MAY_EXEC))) {
				//ACCESS DENIED
				pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
				return -EACCES;
			}
		} else if (!(osid == 5 || osid == 6)) {
			//ACCESS DENIED
			pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
			return -EACCES;
		}
	} else if (ssid == MP4_TARGET_SID) {
		if (osid == 0) {
			//ACCESS DENIED
			pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
			return -EACCES;
		} else if (osid==1) {
			if (!(mask & MAY_READ)){
				//ACESS DENIED
				pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
				return -EACCES;
			}
		} else if (osid==2) {
			if (!(mask & (MAY_READ | MAY_WRITE | MAY_APPEND))) {
				//ACCESS DENIED
				pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
				return -EACCES;
			}
		} else if (osid==3) {
			if (!(mask & (MAY_WRITE | MAY_APPEND))) {
				//ACCESS DENIED
				pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
				return -EACCES;
			}
		} else if (osid==4) {
			if (!(mask & (MAY_READ | MAY_EXEC))) {
				//ACCESS DENIED
				pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
				return -EACCES;
			}
		} else if (osid==5) {
			if (!(mask & (MAY_READ | MAY_EXEC | MAY_ACCESS))) {
				//ACCESS DENIED
				pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
				return -EACCES;
			}
		} else if (osid==6) {
			if (!(mask & (MAY_OPEN | MAY_READ | MAY_EXEC | MAY_ACCESS))) {
				// ACCESS DENIED
				pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
				return -EACCES;	
			}
		} else {
			// ACCESS DENIED
			pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
			return -EACCES;
		}
	} else {
		pr_info("Access denied for ssid %d, osid %d, mask %d\n", ssid, osid, mask);
		return -EACCES;
	}
	return 0;
}

/**
 * mp4_inode_permission - Check permission for an inode being opened
 *
 * @inode: the inode in question
 * @mask: the access requested
 *
 * This is the important access check hook
 *
 * returns 0 if access is granted, -EACCES otherwise
 *
 */
static int mp4_inode_permission(struct inode *inode, int mask)
{

	struct dentry *dentry;
	int ssid, osid, permission;
	char* path, raw;

	if (mask==0) {
		return -EACCES;
	}

        dentry = d_find_alias(inode);
	if (!dentry) {
		dput(dentry);
		return -EACCES;
	}

	path = kmalloc(4096, GFP_KERNEL);
	if (!path) {
		dput(dentry);
		return 0;
	}

	raw = dentry_path_raw(dentry, path, 4096);
	if (IS_ERR(raw)) {
		kfree(path);
		path = NULL;
		dput(dentry);
		return 0;
	}
	if (mp4_should_skip_path(raw)) {
		kfree(path);
		path = NULL;
		dput(dentry);
		return -EACCES;
	}
	
	if(!current_cred() || !(struct mp4_security*)(current_cred()->security)) {
		dput(dentry);
		return -EACCES;
	}

	dput(dentry);
	ssid = ((struct mp4_security*) current_cred()->security)->mp4_flags;
	osid = get_inode_sid(inode);
	
	if (ssid==MP4_TARGET_SID && S_ISDIR(inode->i_mode)) return 0;

	permission = mp4_has_permission(ssid, osid, mask);
	/*pr_info("SSID: %d\t OSID:%d\tmask:%d", ssid, osid, mask);*/ 
	kfree(path);
	path = NULL;	
	return 0;
}


/*
 * This is the list of hooks that we will using for our security module.
 */
static struct security_hook_list mp4_hooks[] = {
	/*
	 * inode function to assign a label and to check permission
	 */
	LSM_HOOK_INIT(inode_init_security, mp4_inode_init_security),
	LSM_HOOK_INIT(inode_permission, mp4_inode_permission),

	/*
	 * setting the credentials subjective security label when laucnhing a
	 * binary
	 */
	LSM_HOOK_INIT(bprm_set_creds, mp4_bprm_set_creds),

	/* credentials handling and preparation */
	LSM_HOOK_INIT(cred_alloc_blank, mp4_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, mp4_cred_free),
	LSM_HOOK_INIT(cred_prepare, mp4_cred_prepare)
};

static __init int mp4_init(void)
{
	/*
	 * check if mp4 lsm is enabled with boot parameters
	 */
	if (!security_module_enable("mp4"))
		return 0;

	pr_info("mp4 LSM initializing..");

	/*
	 * Register the mp4 hooks with lsm
	 */
	security_add_hooks(mp4_hooks, ARRAY_SIZE(mp4_hooks));

	return 0;
}

/*
 * early registration with the kernel
 */
security_initcall(mp4_init);
