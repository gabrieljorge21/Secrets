require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");
//const md5 =require("md5");
//const bcrypt = require("bcrypt");
//const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));


app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


app.listen(3000, function(){
    console.log("Server started on port 3000")
});

mongoose.set('strictQuery', true);
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

//mongoose schema for encrypt password
//before it was a simple javascript obj
// const userSchema = {
//      email: String,
//      password:  String   
// };
const userSchema = new mongoose.Schema ({
    email: String,
    password: String
});

//used to hash and salt passwords and save users in DB
userSchema.plugin(passportLocalMongoose);


//if it wasn't encryptedFiends it would encrypt all the DB
//now it only encrypts the password
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function(req, res){
    res.render("home");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

//this is created because if an user has an active session
//he can reach /secrets route
app.get("/secrets", function(req, res){
    if (req.isAuthenticated()){
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", function(req, res){
    req.logout(function(err){
        if (err){
            console.log(err);
        }else {
            res.redirect("/");
        }
    });
    
});

app.post("/register", function (req, res){

    //this method register comes from passport-local-mongoose package
    //which it is used to interact with the DB
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if (err){
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });

    // //returns hash with 10 saltRounds
    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     // Store hash in your password DB.
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash //md5(req.body.password), it was for md5 hashing
    //        });
        
    //        newUser.save(function(err){
    //         if (err){
    //             console.log(err);
    //         } else {
    //             res.render("secrets");
    //         }
    //        });
    //     });
 });

app.post("/login", function (req, res){

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    //this method login comes from passport-local-mongoose package
    req.login(user, function(err){
        if(err){
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("secrets");
            });
        }
    });
    // const username = req.body.username;
    // const password = req.body.password;//md5(req.body.password);

    // User.findOne({email: username}, function(err, foundUser){
    //     if (err){
    //         console.log(err)
    //     } else {
    //         if(foundUser){
    //             bcrypt.compare(password, foundUser.password, function(err, result) {
    //                 // result == true
    //                 if(result){
    //                     res.render("secrets");
    //                 }
    //             });
    //         }
    //     }
    // });
});