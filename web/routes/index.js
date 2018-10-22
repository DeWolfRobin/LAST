var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
var nmap = JSON.stringify(require("../../output/nmap-output.json")); 
res.render('index', { title: 'L.A.S.T.', out: nmap });
});

module.exports = router;
