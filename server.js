const express = require('express');
const app = express();
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const { ROLES } = require('./data.js')
const { authKey, authUser, authRole } = require('./auth.js');
require('dotenv').config();



//--------Express Setup Methods--------//
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(
    session({
        secret: process.env.SECRET,
        resave: false,
        saveUninitialized: true,
    })
);



//--------Artificial Database--------//
const users = [
    { username: "John", password: "$2b$10$4dqjeZZXpFmPUtcmkaQrqeA2MQXRXSs69iX62UbH/GPARc4qEbjMK", role: "user" },
    { username: "Sam", password: "$2b$10$NWzcYhzp4Gdzj7XQGd55t.fUh09Smttysfq8wKdilueVLQ1WSV.wW", role: "member" },
    { username: "Sue", password: "$2b$10$FyHFqliVnbPdL2Tq1A7nxOwfDzaz2MF43oitqrBSCLigIMi4/HL8a", role: "memberPlus" }];
const admins = [
    { username: "Adam", password: "$2b$10$V1niBApfvt0uSvifl7CZs.l8pg921L9oc/O9YtLOT9RbyYPy.5ltO", role: "admin" },
    { username: "Sarah", password: "$2b$10$b3TEvHpjoSizlGYBCxaVAOYYXntE/rBE6.yKMVZXbLnd3pxy1MN2C", role: "headAdmin" },
];



//--------Pages--------//

app.get('/home', (req, res) => {
    if (req.session.user) {
        username = req.session.user.username;
        role = req.session.user.role;
    } else {
        username = null;
        role = null;
    }
    res.render('home', { username, role })
})

app.get('/register', (req, res) => {
    res.render('register')
})

app.get('/registerAdmin', (req, res) => {
    res.render('registerAdmin')
})

app.get('/login', (req, res) => {
    res.render('login')
})

app.get('/loginAdmin', (req, res) => {
    res.render('loginAdmin')
})



//--------Registration--------//

//--------User
app.post('/register', async (req, res) => {

    // Hashes the user's password, adds a salt and pushes it onto the "users" array in the artificial database
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = { username: req.body.username, password: hashedPassword, role: ROLES.USER }
    users.push(user);

    // Adds the new user to the session so they don't have to enter the credentials a second time after registration
    req.session.user = user;

    // Redirects the user back to the home page
    res.redirect('/home');
})

//--------Admin

// In order to access this request, you must have been given the adminKey by the head admin
// This gives very basic, sever-side security to the admin registration
app.post('/registerAdmin', authKey, async (req, res) => {

    // Hashes the admin's password, adds a salt and pushes it onto the "admins" array in the artificial database
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const admin = { username: req.body.username, password: hashedPassword, role: ROLES.ADMIN }
    admins.push(admin);

    // Addds the new admin to the session so they don't have to enter the credentials a second time after registration
    req.session.user = admin;

    // Redirects the admin back to the home page
    res.redirect('/home');
})

//--------Login--------//

//--------User
app.post('/login', async (req, res) => {

    // Looks for a match between the entered username and a username in the artificial database
    const user = users.find(user => user.username === req.body.username)

    // This if statment runs if the above function did not find a match
    if (user == null) {
        res.send('<h1>Cannot Find User</h1><a href="/login">Login Page</a>')
    }

    // If the above function did find a match, this function compares
    // the hashed password of that match with the password entered by the user
    try {
        // This function will return a value of true if a match was found
        if (await bcrypt.compare(req.body.password, user.password)) {

            // Adds the verified user to the session
            req.session.user = user;
            res.send('<h1>Successfully Logged In!</h1><a href="/home">Home</a>')
        } else {
            // If the comparison returns false, this message is sent
            res.send('<h1>User Not Verified</h1><a href="/login">Login Page</a>')
        }
    } catch {
        res.status(500).send();
    }
})

//--------Admin
app.post('/loginAdmin', async (req, res) => {

    // Looks for a match between the entered username and a username in the artificial database
    const admin = admins.find(admin => admin.username === req.body.username);

    // This if statment runs if the above function did not find a match
    if (admin == null) {
        res.send('<h1>Cannot Find Admin</h1><a href="/login">Login Page</a>')
    }
    // If the above function did find a match, this function compares
    // the hashed password of that match with the password entered by the user
    try {
        // This function will return a value of true if a match was found
        if (await bcrypt.compare(req.body.password, admin.password)) {

            // Adds the verified user to the session
            req.session.user = admin;
            res.send('<h1>Successfully Logged In!</h1><a href="/home">Home</a>')
        } else {
            res.send('<h1>Admin Not Verified</h1><a href="/login">Login Page</a>')
        }
    } catch {
        res.status(500).send();
    }

})

//--------Actions on Site--------//

// Each request in the api has two middlewares.
// The first one verifies that there is a user or admin logged in
// The second one allows the request to be made if the logged in user 
// matches one of the roles passed into the argument list

//--------User Actions


// Roles allowed to make the following request: user, member, memberPlus
app.get('/rentMovie', authUser, authRole(ROLES.USER, ROLES.MEMBER, ROLES.MEMBER_PLUS), (req, res) => {
    res.send('<h1>Movie rented</h1><a href="/home">Home</a>');
})

// Roles allowed to make the following request: member, memberPlus
app.get('/rentShow', authUser, authRole(ROLES.MEMBER, ROLES.MEMBER_PLUS), (req, res) => {
    res.send('<h1>Show rented</h1><a href="/home">Home</a>');
})

// Role allowed to make the following requests: memberPlus,
app.get('/rentMovieHD', authUser, authRole(ROLES.MEMBER_PLUS), (req, res) => {
    res.send('<h1>Movie rented in HD</h1><a href="/home">Home</a>');
})
app.get('/rentShowHD', authUser, authRole(ROLES.MEMBER_PLUS), (req, res) => {
    res.send('<h1>Show rented in HD</h1><a href="/home">Home</a>');
})


//--------Admin Actions

// Roles allowed to make the following requests: admin, headAdmin
app.get('/editMovies', authUser, authRole(ROLES.ADMIN, ROLES.HEAD_ADMIN), (req, res) => {
    res.send('<h1>Movies Edited</h1><a href="/home">Home</a>');
})
app.get('/editShows', authUser, authRole(ROLES.ADMIN, ROLES.HEAD_ADMIN), (req, res) => {
    res.send('<h1>Shows Edited</h1><a href="/home">Home</a>');
})
app.get('/changeCustomerRoles', authUser, authRole(ROLES.ADMIN, ROLES.HEAD_ADMIN), (req, res) => {
    res.send('<h1>Customer Role Changed</h1><a href="/home">Home</a>');
})

// Role allowed to make the following request: headAdmin
app.get('/removeAdmin', authUser, authRole(ROLES.HEAD_ADMIN), (req, res) => {
    res.send('<h1>Admin Removed</h1><a href="/home">Home</a>');
})


app.listen(3000);