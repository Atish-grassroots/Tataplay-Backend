const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const passport = require('./middleware/passport');
const cors = require('cors');
const { connectToServer } = require('./config/connect');
const loginRoutes = require('./routes/loginroutes');
const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express')


//const express = require('express');
const app = express();

app.use(express.json()); 

const options = {
    definition: {
        openapi : '3.0.0',
        info : {
            title: "Tata Play",
            version: '1.0.0'
        },
        servers: [
            {
                url: 'http://localhost:3000/'
            }
        ]
    },
    apis: ['./routes/loginroutes.js']
}

const swaggerSpec = swaggerJSDoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use(cors({
    origin: '*', 
    methods: 'GET,POST,PUT', 
    credentials: true 
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true }
  }));
app.use(passport.initialize());
app.use(passport.session());

// app.use(session({
//     secret: 'your_secret_key',
//     resave: false,
//     saveUninitialized: false,
//     cookie: { secure: true }
//   }));

// Use the login routes
app.use('/', loginRoutes);

connectToServer().then(() => {
  app.listen(3000, function() {
    console.log('App is listening on port 3000 and connected to the database');
  });

}).catch(err => {
  console.error('Failed to connect to the database', err);
  process.exit(1);
});