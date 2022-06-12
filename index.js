const express = require('express');
const port = 8000;
const app = express();
const passport = require('passport');


const initialize = require('./config/passportLocal');
app.listen(port, function(err){
    if(err){
        console.log(`Error in running the server : ${err}`)
    }
    console.log(`Server is up and running on port: ${port}`)
})

