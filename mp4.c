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

	pr_info("Inside get_inode_sid");

	if (!inode->i_op->getxattr) {
		return 0;
	}

	context = kmalloc(len, GFP_KERNEL);
	if (!context) {
		pr_err("context buffer not allocated");
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
		pr_err("rc bigger than range");
		return 0;
	}
	
	dput(dentry);
	context[rc] = '\0';
	sid = __cred_ctx_to_sid(context);
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
	
	new_label->mp4_flags = MP4_TARGET_SID;

	sid = get_inode_sid(inode);
	if (sid == MP4_TARGET_SID) {
		bprm->cred->security= new_label;
	}
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

	if (!inode || !dir) return -EOPNOTSUPP;

	if (sid == MP4_TARGET_SID) {
		namep=kstrdup(XATTR_NAME_MP4, GFP_KERNEL);
		if (!namep) return -ENOMEM;
		*name = namep;
		
		valuep = kstrdup("read-write", GFP_KERNEL);
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
	/*
	 * Add your code here
	 * ...
	 */
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

	if (mask==0) {
		return -EACCES;
	}

        dentry = d_find_alias(inode);
	dput(dentry);
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
