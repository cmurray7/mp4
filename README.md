# mp4

### Design Decisions
Design decisions for `mp4_cred_alloc_blank`, `mp4_cred_free`, and `mp4_cred_prepare` were inspired by the smack security module. In these, I opted to create local mp4_security structs and place them where they needed to be. The implementation for `mp4_brpm_set_creds` followed this. Given the initiation of a linux task, I placed a security label into the binprm security field that labelled it as target if it fit the bill. In `mp4_inode_init_security`, the newly created inodes get a security label in xattr. If the inode is the target, the name is set to indicate an MP4 target and the value is set to dir-write if the inode is a directory and read-write if the inode is a file. The mandatory access control logic is in `mp4_has_permission`. The additional logic of figure 3, that isn't apart of the MAC is in `mp4_inode_permission` (as well as other existence error-checking). mp4_inode_permission first checks to see if the inode is a part of a directory we want to skip and does if that is true and then continues with the flow that is in the figure. mp4_has_permission uses the OSID and SSID to determine whether the object has permission to do the intended operation to the subject. The behavior differs if the ssid is the target or not. 

### Code Issues
I was able to make all the additional changes in 5.1 of the assignment. I have included the Kconfig and Makefiles in the zip to demonstrate this. I reached a point where there were no compile time errors in my `mp4.c`. The package generation and depackage images/headers commands terminated sucessfully. I executed the grub command sequence multiple times as well. But, when I hit the `sudo reboot` point in the instructions, I was never able to connect to my VM before the grub menu timed out and generic/default linux was booted. 
Here are some screencaps of the process -- the piazza post according to this mentioned that redoing it fixed it, so that is what I tried.

##### deb-pkg and dpkg success
![three](./screencaps/deb_pkg.png?raw=true)
![four](./screencaps/dpkg.png?raw=true)
![five](./screencaps/dpkg_headers.png?raw=true)

##### grub success
![six](./screencaps/grub.png?raw=true)
![seven](./screencaps/update-grub.png?raw=true)

##### timeouts after sudo reboot keeping from choosing custom kernel
![eight](./screencaps/timeout_to_boot.png?raw=true)

### VirtualBox Attempts
When I was unable to reboot into my custom kernel, I tried to move the problem over to virtual box. I carried out the MP0 steps and ultimately hit the disk space capacity. I troubleshooted this for a while but the solutions that were presented on some forums did not work for my virtual box installation or vm setup. Below are some screencaps to the issues I ran into. 

##### Could not remove disk mount to add space
![one](./screencaps/irremovable_disk.png?raw=true "Could not remove disk mount to add space")

##### Commandline resize errors
![two](./screencaps/commandline_error.png?raw=true "Commandline resize errors")

### Test Cases
I have completed mp4_test.perm and mp4_test.perm.unload but was unable to use them due to my inability to boot into my custom kernel.

# After extension
I was able to boot into my custom kernel after VSphere was back online.
I tried debugging for a while more, but kept recieving the same message:
![nine](./screencaps/kernel_panic.png?raw=true "Kernel Panic")

the code in the zip is my final version, which still incurs kernel panic.
