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
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

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
    password: String,
    googleId: String,
    secret: String
});

//used to hash and salt passwords and save users in DB
userSchema.plugin(passportLocalMongoose);
//used to find or create into google strategy
userSchema.plugin(findOrCreate);


//if it wasn't encryptedFiends it would encrypt all the DB
//now it only encrypts the password
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//passport.serializeUser(User.serializeUser());
//passport.deserializeUser(User.deserializeUser());

// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id); 
   // where is this user.id going? Are we supposed to access this anywhere?
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    //the ids you get from google api credentials
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    //the url configured in google api, on credentials
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    //this is the googleId in the schema
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
    res.render("home");
});

//this route is from the button sign in with Google
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
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
    // if (req.isAuthenticated()){
    //     res.render("secrets");
    // } else {
    //     res.redirect("/login");
    // }

    //finds every user with a secret field thait is not null
    //ne = not equal
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if (err){
            console.log(err);
        } else {
            //access by ejs in secrets.ejs by the field usersWithSecrets
            res.render("secrets", {usersWithSecrets: foundUsers} );
        }
    });
});

app.get("/submit", function(req, res){
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})

app.get("/logout", function(req, res){
    req.logout(function(err){
        if (err){
            console.log(err);
        }else {
            res.redirect("/");
        }
    });
    
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function (err, foundUser){
        if(err) {
            console.log(err)
        } else {
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets")
                });
            }
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