cmd_fs/wrapfs/wrapfs.ko := ld -r -m elf_i386 -T /usr/src/hw2-skolli/scripts/module-common.lds   -o fs/wrapfs/wrapfs.ko fs/wrapfs/wrapfs.o fs/wrapfs/wrapfs.mod.o
