const express = require("express")
const User = require("./userModel")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const Router = express.Router();

//   the fundtion to check if any user is logged in...
const authenticate = async(req, res, next) =>{
	try {
		const {token} = req.cookies;  //  token from cookies in browser...
		// console.log("token is - " + token);

		if(!token){ //  token not available, so not logged in !
			return res.status(401).json({
				message:"Please login first...!"
			})
		}
		
		const decoded = jwt.verify(token, process.env.SECRET_KEY);  //  verifying the token with jwt

		const user = await User.findById(decoded._id);  //  finding the user from that token..
		if(!user)
			return res.status(404).jsno({
				message:"User not found...!"
			})

		req.user = user;  //  setting the user in the request..
		next();  //  calling the next APIs
	} catch (error) {
		res.status(500).json({
			message:error.message
		})
	}
}

//  registering a new user...
Router.route("/register").post(async(req, res) =>{
	try {
		//  data of new user..
		const {name, email, password} = req.body;
		const newUser = await User.create({  //  creatiung user..
			name,
			email, 
			password
		})

		//  generating a new token for this user for login purpose...
		const token = await newUser.generateToken();
		const options = {
			expires: new Date(Date.now() + 20*24*60*60*1000),
			httponly:true
		}

		res.status(200).cookie("token", token, options).json({
			message:"User created...",
			newUser
		})
	} catch (error) {
		res.status(500).json({
			message:error.message
		})
	}
})

//  logging in with email & password..
Router.route("/login").post(async(req, res) =>{
	try {
		const {email, password} = req.body;
			
		const user = await User.findOne({email}).select("+password"); //  finding user with given email...
		if(!user){  //  usr not found with that email..
			return res.status(404).json({
				message:"User not found...!"
			})
		}

		//   if previous wrong attempt count is 3 then locked till 2hours...
		if(user.wAttempt == 3){
			const diff = new Date() - user.lockDate;  //  the time delay
			if(diff < 2*60*60*1000){  //  less than 2 hours...
				return res.status(401).json({
					message:"Your account is locked. Try again later...!"
				})
			}
			else{ //  it's long that 2 hours.. so reseting the count..
				user.wAttempt = 0;
			}
		}

		const isMatch = await bcrypt.compare(password, user.password); //  matching the password...

		if(isMatch){
			user.wAttempt = 0; //  reseting the wAttemp count..
			const token = await user.generateToken();
			const options = {
				expires:new Date(Date.now() + 20*24*60*60*1000),  //  valid for 20 days..
				httponly:true
			}
			res.status(200).cookie("token", token, options).json({ //  logged in
				message:"User logged in...!",
				user
			})
		}
		else{ //  wrong password..., so increase the wAttempt count
			user.wAttempt++;
			user.lockDate = new Date();  //  saving the current date as it's a wrong attempt..
			res.status(401).json({
				message:"Invalid login credentials...!"
			})
		}

		await user.save();  //  saving all the changes in user...
	} catch (error) {
		res.status(500).json({
			message:error.message
		})
	}
})

//  logging out..
Router.route("/logout").put(authenticate, async(req, res) =>{
	try {
		const options = { //  setting the option for the token...
			expires:new Date(Date.now()), //  expires just now...
			httponly:true
		}

		res.status(201).cookie("token", null, options).json({
			message:"User logged out...!"
		})
	} catch (error) {
		res.status(500).json({
			message:error.message
		})
	}
})


//  change the password...
Router.route("/change-password").put(authenticate, async(req, res) =>{
	try {
		const {prevPass, newPass} = req.body;  //  previous password and new password...
		if(!prevPass || !newPass)
			return res.status(401).json({
				message:"Please provide both old & new password...!"
			})

		const user = await User.findById(req.user._id).select("+password");  //  user fetching with selecting the password...
		const match = bcrypt.compare(prevPass, user.password);  //  matching

		if(!match){
			return res.status(401).json({
				message:"wrong password...!"
			})
		}

		user.password = newPass;  //  updating password..
		await user.save();
		res.status(201).json({
			message:"Password updated...!"
		})
	} catch (error) {
		res.status(500).json({
			message:error.message
		})
	}
})

//  request for forgot-password..
Router.route("/forgot-password").post(async (req, res) =>{
	try{
		const {email} = req.body;
		const user = await User.findOne({email}).select("+password");  //  fetching the user with password...

		if(!user){
			return res.status(404).json({
				message:"user not found...!"
			})
		}

		const secret = process.env.SECRET_KEY + user.password;  //  secret key for this user..
		const payload = {  //  payload token which is encoded with jwt
			email:user.email,
			id:user._id
		}

		const token = jwt.sign(payload,secret,{expiresIn:"5m"});
		const link = `http://localhost:${process.env.PORT}/reset-password/${user._id}/${token}`

		res.json({
			message:"here's ur link to reset password..",
			link
		})
	} catch (error) {
		res.status(500).json({
			message:error.message
		})
	}
}) 


Router.route("/reset-password/:id/:token").put(async (req, res) =>{
	try {
		const {id, token} = req.params;
		const user = await User.findById(id).select("+password");
		if(!user)
			return res.status(404).json({
				message:"User not found...!"
			})


		const secret = process.env.SECRET_KEY + user.password;
		const {email, id: _id} = jwt.verify(token, secret);
		
		console.log("This is the user -> "+user);
		console.log("This is the secret ->" +secret);
		console.log("This is the email -> ", email);
		console.log("This is the id -> ", _id);

		const {newPass} = req.body;
		user.password = newPass
		await user.save();

		res.status(201).json({
			message:"Password is reset...!"
		})
	} catch (error) {
		res.status(500).json({
			message:error.message
		})
	}
})


module.exports = Router