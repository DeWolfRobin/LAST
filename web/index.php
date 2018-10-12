<html>
<head></head>
<body>
<div id="out"></div>
<script>
var nmap = <?php echo file_get_contents("../output/nmap-output.json") ?>;
console.log(nmap.nmaprun.host);
var a = document.getElementById("out");
var host = nmap.nmaprun.host;
var parsed = "<h1>"+host.address["@addr"]+"</h1><h2>"+host.os.osmatch["@name"]+"</h2><table border=1><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Extra</th></tr>";
for (var i = 0;i<  host.ports.port.length;i++){
var port = host.ports.port[i];
console.log(port);
parsed += "<tr><td>"+port["@portid"]+"</td><td>"+port["@protocol"]+"</td><td>"+port.service["@name"]+"</td><td>"+port.service["@product"]+" "+(port.service["@version"] ? "Version: "+port.service["@version"] : "")+"</td></tr>";
}
parsed += "</table>";
a.innerHTML = parsed;
</script>
</body>
</html>
