const hash = require('object-hash');
require('dotenv').config();

// This function verfies that a user is logged in by checking if a user is stored in the session
function authUser(req, res, next) {
    if (req.session.user == null) {
        res.status(403);
        return res.send('<h1>You need to sign in</h1><a href="/home">Home</a>');
    }
    next();
}

// This function uses the spread syntax to include any number of roles
// This facilitates scaling with regards to the number of roles
function authRole(...roles) {
    return (req, res, next) => {

        // The includes funtion returns true if a match between thes "roles" array and the passed in argument is found
        if (!roles.includes(req.session.user.role)) {
            return res.send('<h1>You are not authorized to make this request</h1><a href="/home">Home</a>');
        }
        next();

    }
}

// This function verifies that the correct adminKey was passed in to the request
// Normally the adminKey woule be stored in the database rather that in environment variables
// An additional option would be to periodically change the adminKey since it is only single-factor authentication
function authKey(req, res, next) {

    // Hashes the user input key
    // I used object-hash instead of bcrypt 
    // because to my knowledge, single factor authentication is possible with bcrypt
    const hashedKey = hash({ key: req.body.key });

    // Compares the user's hashed key with the already hashed adminKey from the .env file
    if (hashedKey !== process.env.ADMIN_KEY) {
        res.status(401);
        return res.send('<h1>You are not authorized to make this request</h1><a href="/home">Home</a>');
    }
    next();
}


module.exports = { authKey, authUser, authRole };