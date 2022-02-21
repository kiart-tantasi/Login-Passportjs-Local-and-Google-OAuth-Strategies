require("dotenv").config();
const express = require("express");
const app = express();
//PASSPORT AUTHENTICATION
const bcryptjs = require("bcryptjs")
const passport = require('passport');
const session = require("express-session");
const LocalStrategy = require('passport-local').Strategy;
const initializeGoogle = require("./oauth-google");

// Dummy Database
const users = [];

app.set('view-engine','ejs');
app.use(express.urlencoded({ extended: false}));
app.use(session({
    secret: process.env.SESSION_KEY,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
//Local Auth
passport.use(new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password'
  },
    async function (username, password, done) {
        const foundUser = users.find(x => x.username === username);
        if (!foundUser) {
            console.log("No matching username");
            return done(null, false, {message: "No matching username."});
        }
        if (await bcryptjs.compare(password,foundUser.password)) {
            console.log("Successfully Logged in.")
            return done(null, foundUser);
        } else {
            console.log("Wrong Password");
            return done(null, false, {message:"Wrong Password."})
        }
    }
  )
);
//Serialize-Deserialize
passport.serializeUser((user,done) => done(null, user.username));
passport.deserializeUser((username,done) => {
    const found = users.find(x => x.username === username);
    return done(null, found);
});
//Google-OAuth
initializeGoogle(passport,users);

//route
app.get("/", blockNotAuthen, (req,res) => {
    res.render("index.ejs", {fName: req.user.firstname, lName: req.user.lastname});
});

app.get("/register",blockAuthen,(req,res) => {
    res.render("register.ejs");
})

app.post("/register", async(req,res) => {
    const hashed = await bcryptjs.hash(req.body.password,10);
    users.push({
        firstname: req.body.firstname,
        lastname: req.body.lastname,
        username: req.body.username,
        password: hashed
    })
    res.redirect("/login");    
})

app.get("/login",blockAuthen, (req,res) => {
    res.render("login.ejs");
})

app.post("/login", passport.authenticate("local", 
    {
        successRedirect: "/",
        failureRedirect:"/login"
    })
);

//google route
app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/redirect', passport.authenticate('google',
{ failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/");
  });

app.get("/logout", (req,res) => {
    req.logOut();
    res.redirect("/login");
})

// Blocking people who are not and are authenticated already.
function blockNotAuthen(req,res,next) {
    if (req.isAuthenticated()) {
        next();
    } else {
        console.log("Not Logged in yet.")
        res.redirect("/login");
    }
}
function blockAuthen(req,res,next) {
    if (!req.isAuthenticated()) {
        next();
    } else {
        console.log("Already logged in.")
        res.redirect("/");
    }
}

const port = process.env.port || 3000;
app.listen(port, err => {
    if(err) {
        console.log(err);
    } else {
        console.log("..Running on port",port)
    }
})