var express = require('express');
var bodyParser = require('body-parser');
var app = express();
const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/fakeLogin');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
var index = require('./routes/index');
app.use('/', index);

var port = 3001;
app.listen(port, ()=> {
  console.log(`start port at ${port}`);
});
module.exports = app;
