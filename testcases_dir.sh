dir=dir
filename=file.txt

rm -rf $dir
mkdir $dir



echo -e "\033[32m getfattr -n user.has_integrity $dir; \033[00m"
getfattr -n user.has_integrity $dir;


echo -e "\033[32m setfattr -n user.has_integrity -v "0" $dir; \033[00m"
setfattr -n user.has_integrity -v "0" $dir;
attr -l $dir;
getfattr -n user.has_integrity $dir;


echo -e "\033[32m touch $dir/$filename; \033[00m"
rm -rf $dir/$filename;
touch $dir/$filename;
attr -l $dir/$filename


echo -e "\033[32m setfattr -n user.has_integrity -v "1" $dir; \033[00m"
setfattr -n user.has_integrity -v "1" $dir;
attr -l $dir;
getfattr -n user.has_integrity $dir;

echo -e "\033[32m touch $dir/$filename; \033[00m"
rm -rf $dir/$filename;
touch $dir/$filename;
attr -l $dir/$filename

echo -e "\033[32m setfattr -n user.has_integrity -v "0" $dir/$filename; \033[00m"
setfattr -n user.has_integrity -v "0" $dir/$filename;
getfattr -n user.has_integrity $dir/$filename;
getfattr -n user.integrity_val $dir/$filename;

echo -e "\033[32m setfattr -n user.has_integrity -v "1" $dir/$filename; \033[00m"
setfattr -n user.has_integrity -v "1" $dir/$filename;
getfattr -n user.integrity_val $dir/$filename;

