var express = require('express');
var router = express.Router();
var User = require('../models/User');
var bcrypt = require('bcrypt');
var jwt = require('jwt-simple');
var secret = 'xxx';

var auth = function(req, res, next) {
   if (req.query.token) {
      var id = jwt.decode(req.query.token, secret);
      User.findById(id, function(err, user) {
        if (err) return res.status(500).json({message:err});
        if (!user) return res.status(404).json({message: `User not found`});
        req.user = user;
        next();
      });
   } else {
      return res.status(401).json({message:'token must be present'});
   }
}

router.post('/signup', function(req, res, next) {
  var user = new User(req.body);
  user.password = bcrypt.hashSync(req.body.password, 10);
  user.save((err)=> {
    if (err) return res.status(500).json({message:err});
    res.status(201).json({message:'User created'});
  });
})

router.post('/login', function(req, res, next) {
  if (req.body.email === undefined || req.body.password === undefined) {
    return res.status(400).json({message:`email and password are required`});
  }
  User.findOne({email:req.body.email}, function(err, user){
      if (err) return res.status(500).json({message:err});
      if (!user) return res.status(404).json({message: `User not found with email ${req.body.email}`});
      if (bcrypt.compareSync(req.body.password, user.password)) {
          return res.json({token: jwt.encode(user._id, secret)});
      } else {
        return res.status(401).json({message:`password incorrect`});
      }
  })
})

router.get('/me', auth, function(req, res, next) {
    res.json(req.user);
})

module.exports = router;
