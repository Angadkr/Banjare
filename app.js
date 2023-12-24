if (process.env.NODE_ENV !== "production") {
    require('dotenv').config();
}

//use express becuase its un-opiniated framework give flexibilty to developer to structure code however they want ,scalable,simple,with a very nice community
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
//mongoose is a nodejs package that allows us to use mongoDb efficiently and easily in our express app.
const ejsMate = require('ejs-mate');
const session = require('express-session');
const flash = require('connect-flash');
const ExpressError = require('./utils/ExpressError');
const methodOverride = require('method-override');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const User = require('./models/user');


const userRoutes = require('./routes/users');
const campgroundRoutes = require('./routes/campgrounds');
const reviewRoutes = require('./routes/reviews');

mongoose.connect('mongodb://localhost:27017/camp-topia', {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true,
    useFindAndModify: false
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", () => {
    console.log("Database connected");
});

const app = express();

app.engine('ejs', ejsMate)

//view engine allows us to render template files..these files contain actual data which is send to client...most popular is ejs
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'))

//below code used to parse the incoming request with url encoded payload into a body object which will be present inside the req object of the incoming request,,,its a middleware
app.use(express.urlencoded({ extended: true }))
app.use(methodOverride('_method'));
//express.static tells that static files will be present is public folder.
app.use(express.static(path.join(__dirname, 'public')))

//below are configuration for session
//why we use session over cookies?...we use that because first of all cookies have a fixed size so you can't story heavy information like the users cart etc...plus session is more secure so what we do is we create and store infro is the session and the session sends a cookie back to the browser about that session id.
const sessionConfig = {
    secret: 'thisshouldbeabettersecret!',//this secret will be used to sign cookies that session sends back
    resave: false,//just some configuration
    saveUninitialized: true,//some configuration
    //below cookies are basically key value pairs that we store in the user's browser that contain some information about website specifically some user specific details,,once these cookies are set they are send on every subsequent request on that website...this helps make http stateful
    cookie: {
        httpOnly: true,
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}

app.use(session(sessionConfig))
app.use(flash());

//below code for auth...one thing in auth for a good **hashing function** 1)they should be irreversible...i.e. decrypt is not a thing...small change in input leads to large change in output...1 input leads to that particular output...slow to process

//bcrypt demo below...how things actually work before magic..
//await salt = bcrypt.genSalt(10) -> 10 is salt rounds like a difficulty for hash
// await hash = bcrypt.hash(pw,salt) // hash password with that salt added to that password.
// await bcrypt.compare(password,user.password) // for comparing incoming password for login
//finally to stay logged in we just use express session...we store the current users id in that session and when browser sends the cookie to unlock the session with session id,we just check if user exists or not.

app.use(passport.initialize());
app.use(passport.session());//passport using the session to store information about logged in user
passport.use(new LocalStrategy(User.authenticate()));//creating a local strategy to use for user auth

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.use((req, res, next) => {
    //this middleware is used to set local variables before we define routes because we will use them while responding
    res.locals.currentUser = req.user;
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
})


app.use('/', userRoutes);
app.use('/campgrounds', campgroundRoutes)
app.use('/campgrounds/:id/reviews', reviewRoutes)


app.get('/', (req, res) => {
    res.render('home')
});


app.all('*', (req, res, next) => {
    next(new ExpressError('Page Not Found', 404))
})

//below is the error handler
app.use((err, req, res, next) => {
    const { statusCode = 500 } = err;
    if (!err.message) err.message = 'Oh No, Something Went Wrong!'
    res.status(statusCode).render('error', { err })
})

//below method is used to make server listen on port 3000
app.listen(3000, () => {
    console.log('Serving on port 3000')
})



//Basic security:
//express mongo sanitize.
// validator to prevent xss
// third in session give it a name,,,give cookies httpOnly and secure
// don't show error stack message


//now before deployment
//upload on mongo atlas allows u to store in cloud ...create cluster..create user and whitelist ip address
//use mongo store ... connect-mongo...for session store and config new MongoDBStore with secret , expiry date etc.

