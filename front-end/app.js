const express = require('express')
const app = express()
const port = 8080

app.get('/', (req,res) => {
	res.sendFile(__dirname + '/index.html')
})

app.listen(port, (req,res) => {
	console.log("server listening on port: ", port)
})





