require("dotenv").config();
const GoogleStrategy = require('passport-google-oauth20').Strategy;

function intializeGoogle(passport,users) {
    passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret:process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/redirect"
    },
    function(accessToken, refreshToken, profile, cb) {
        const user = users.find(x => x.googleId === profile.id);
        if (!user) {
            const random = Math.random();
            users.push({
                username: profile.name.givenName+random+profile.name.familyName,
                googleId: profile.id,
                firstname: profile.name.givenName,
                lastname: profile.name.familyName
            
            });
            console.log("New Google Account Registered.")
            return cb(null, {
                username: profile.name.givenName+random+profile.name.familyName,
                googleId: profile.id,
                firstname: profile.name.givenName,
                lastname: profile.name.familyName
            });
        } else {
            return cb(null, user);
        }
    }
    ))
}

module.exports = intializeGoogle;