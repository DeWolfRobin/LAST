/etc/init.d/nessusd start
load="load nessus;"
connect="nessus_connect admin:admin@localhost:8834"
final=$load+$connect;
msfconsole -n -q -x $final
