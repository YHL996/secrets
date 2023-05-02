require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption")

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
    email:String,
    password:String
});
//
// Define a secret key to be used for encryption and decryption
secret = process.env.SECRET;

// Add the encrypt plugin to the user schema, passing in the secret key as an option;only the password field is to be encrypted
userSchema.plugin(encrypt, {secret: secret, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

app.get("/", function(req,res){
    res.render("home")
});

app.get("/login", function(req,res){
    res.render("login")
});

app.get("/register", function(req,res){
    res.render("register")
});

app.post("/register", function(req,res){
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    });
    newUser.save().then(function(){
        res.render("secrets");
    }).catch(function(err){
        console.log(err);
    });
});

app.post("/login", function(req,res){
    User.findOne({email: req.body.username}).then(function(foundUser){
        if(foundUser){
            if(foundUser.password === req.body.password){
                res.render("secrets")
            } else {
                res.send("Incorrect password")
            };
        } else {
            res.send("Incorrect information")
        };
    }).catch(function(err){
        console.log(err);
    });
});

app.listen(3000, function(){
    console.log("Successfully started on port 3000.")
});