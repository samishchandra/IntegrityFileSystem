filename=file.txt
rm -rf $filename;

touch $filename;
echo -e "\033[32m getfattr -n user.has_integrity $filename; \033[00m"
getfattr -n user.has_integrity $filename;

echo -e "\033[32m setfattr -n user.has_integrity -v "1" $filename; \033[00m"
setfattr -n user.has_integrity -v "1" $filename;
getfattr -n user.has_integrity $filename;
getfattr -n user.integrity_val $filename;

echo -e "\033[32m setfattr -n user.integrity_val -v "1" $filename; \033[00m"
setfattr -n user.integrity_val -v "1" $filename;

echo -e "\033[32m setfattr -n user.has_integrity -v "0" $filename; \033[00m"
setfattr -n user.has_integrity -v "0" $filename;
getfattr -n user.has_integrity $filename;
getfattr -n user.integrity_val $filename;

echo -e "\033[32m setfattr -n user.has_integrity -v "1" $filename; \033[00m"
setfattr -n user.has_integrity -v "1" $filename;
getfattr -n user.integrity_val $filename;

echo -e "\033[32m cat $filename; \033[00m"
cat $filename;

echo -e "\033[32m echo \"hello\" | cat >> $filename;; \033[00m"

echo "hello" | cat >> $filename;

echo -e "\033[32m cat $filename; \033[00m"
cat $filename;

echo -e "\033[32m setfattr -n user.has_integrity -v "1" $filename; \033[00m"
setfattr -n user.has_integrity -v "1" $filename;

echo -e "\033[32m cat $filename; \033[00m"
cat $filename;

