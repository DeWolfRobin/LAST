# check if nessus is ready
ready=$(http --verify=no https://localhost:8834/scans \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624" | jq -r ".scans")
while [ "$ready" = null ]
do
	echo "waiting for nessus"
	sleep 1
	ready=$(http --verify=no https://localhost:8834/scans \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624" | jq -r ".scans")
done

# get hosts seperated by comma's
hosts=$(sed ':a;N;$!ba;s/\n/,/g' output/live-hosts.txt)

# create a new nessus scan using the predefined policy uuid
scanid=$(echo "{\"uuid\": \"ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66\",\"settings\": {\"name\": \"AutoScan\",\"description\": \"a scan created by the automated script\",\"scanner_id\": 1,\"enabled\": \"true\",\"starttime\": \"20170820T100500\",\"launch\": \"YEARLY\",\"text_targets\": \"${hosts}\"}}" | http --verify=no POST https://localhost:8834/scans \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624" | jq -r ".scan.id")

# start the scan
http -v --verify=no POST https://localhost:8834/scans/$scanid/launch \X-ApiKeys:"accessKey=cc052c8b010d0aa933ab8af73043d12d643e2db2953962a39e37b4af9875a150; secretKey=6ec8e1a103944e64a1f296afa005d9646637f9091d21016a9f07c66deb7f4624"

# check periodically if the scan is finished

# if the scan is finished create the export, then check if the export is done, then save the export
