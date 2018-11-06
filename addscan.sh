out=$(rpcclient -U '' -N 10.0.0.11 -c querydominfo | sed 's/\t//g' | sed '$!s/$/","/g' | sed 's/:/":"/g')
array=$(rpcclient -U '' -N 10.0.0.11 -c enumdomusers | sed 's/rid:\[.*$//g' | sed '$!s/$/,/g' | sed 's/user://g' | sed 's/ //g;s/\[//g;s/\]//g')
out="{\"${out}\",\"users\":\"[${array}]\"}"
echo $out
