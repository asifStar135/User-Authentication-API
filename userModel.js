const mongoose = require("mongoose")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")

const User = new mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    email:{
        type:String, 
        required:true,
        unique:[true, "already there is an account with this email...!"]
    },
    password:{
        type:String,
        select:false,
        required:true
    },
    wAttempt:{
        type : Number,
        default : 0
    },
    lockDate:{
        type:Date
    }
})

User.pre("save", async function(next){
    if(this.isModified("password")){
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
})

User.methods.generateToken = function (){
    return jwt.sign({_id:this._id}, process.env.SECRET_KEY);
}

module.exports = mongoose.model("User", User);