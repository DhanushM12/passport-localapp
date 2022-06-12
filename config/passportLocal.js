const LocalStrategy = require('passport-local').Strategy;
const bcrypt =require('bcrypt');

function initialize(passport, getUserByEmail, geUserById){
    const authenticator = async (email, password, done) => {
        const user = getUserByEmail(email);
        if(user == null){
            return done(null, false, {'message' : 'No user with that email exists'});
        }
        try {
           if(await bcrypt.compare(password, user.password)){
            return done(null, user);
           }
           else{
            return done(null, false, {'message' : 'Email/Password is wrong'});
           }
        } catch (err) {
            return done(err);
        }
    }
    passport.use(new LocalStrategy({usernameField: 'email'}, authenticator));
    passport.serializeUser(function(user, done) {
        done(null, user.id);
      });
      
      passport.deserializeUser(function(id, done) {
       return done(null, geUserById(id));
      });
}

module.exports = initialize;
