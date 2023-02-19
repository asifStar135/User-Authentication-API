const express = require("express")
const jwt = require("jsonwebtoken");
const { default: mongoose } = require("mongoose");
const User = require("./userModel")
const Router = require("./routes")
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");

const app = express();
dotenv.config({path:"./config.env"})
app.use(express.json({limit:"10mb"}))
app.use(express.urlencoded({extended : false}))
app.use(cookieParser())
app.use(Router)

const connect = async() =>{
    try {
        let {connection} = await mongoose.connect(process.env.MONGO_URL)
        console.log(`MongoDB connected... -> ${connection.host}`);
    } catch (error) {
        console.log(error)
    }
    }
connect();


app.listen(process.env.PORT, () =>{
    console.log(`Server is running at port ${process.env.PORT}...!`)
})

module.exports = app;