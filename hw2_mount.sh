umount /tmp
umount /n/scratch
mount -t ext3 /dev/sdb1 /n/scratch -o user_xattr
mount -t wrapfs /n/scratch /tmp -o user_xattr
df
