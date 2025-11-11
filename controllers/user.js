import jwt from "jsonwebtoken"
import nodemailer from 'nodemailer'
import crypto from 'crypto'
import bcrypt from 'bcryptjs'
import dotenv from 'dotenv'
import mongoose from 'mongoose'

import User from '../models/userModel.js'
import ProfileModel from '../models/ProfileModel.js'

dotenv.config()

const SECRET = process.env.SECRET
const HOST = process.env.SMTP_HOST
const PORT = process.env.SMTP_PORT
const USER = process.env.SMTP_USER
const PASS = process.env.SMTP_PASS

//---------------------------------- AUTH SECTION ----------------------------------//

export const signin = async (req, res)=> {
    const { email, password } = req.body

    try {
        const existingUser = await User.findOne({ email })
        if(!existingUser) return res.status(404).json({ message: "User doesn't exist" })

        const isPasswordCorrect  = await bcrypt.compare(password, existingUser.password)
        if(!isPasswordCorrect) return res.status(400).json({message: "Invalid credentials"})

        const userProfile = await ProfileModel.findOne({ userId: existingUser._id })
        const token = jwt.sign(
            { email: existingUser.email, id: existingUser._id, role: existingUser.role },
            SECRET,
            { expiresIn: "1h" }
        )

        res.status(200).json({ result: existingUser, userProfile, token })
    } catch (error) {
        console.error(error)
        res.status(500).json({ message: "Something went wrong" })
    }
}

export const signup = async (req, res)=> {
    const { email, password, confirmPassword, firstName, lastName, role } = req.body

    try {
        const existingUser = await User.findOne({ email })
        if(existingUser) return res.status(400).json({ message: "User already exist" })
        if(password !== confirmPassword) return res.status(400).json({ message: "Passwords don't match" })
        
        const hashedPassword = await bcrypt.hash(password, 12)
        const result = await User.create({ 
            email, 
            password: hashedPassword, 
            name: `${firstName} ${lastName}`, 
            role: role || 'Viewer'
        })

        const token = jwt.sign(
            { email: result.email, id: result._id, role: result.role },
            SECRET,
            { expiresIn: "1h" }
        )
        
        res.status(200).json({ result, token })
    } catch (error) {
        console.error(error)
        res.status(500).json({ message: "Something went wrong" }) 
    }
}

export const forgotPassword = (req,res)=>{
    const { email } = req.body

    const transporter = nodemailer.createTransport({
        host: HOST,
        port : PORT,
        auth: { user: USER, pass: PASS },
        tls: { rejectUnauthorized:false }
    })

    crypto.randomBytes(32,(err,buffer)=>{
        if(err) return console.log(err)

        const token = buffer.toString("hex")
        User.findOne({ email })
        .then(user=>{
            if(!user) return res.status(422).json({error:"User does not exist in our database"})
            user.resetToken = token
            user.expireToken = Date.now() + 3600000
            user.save().then(()=>{
                transporter.sendMail({
                    to:user.email,
                    from:"Accountill <hello@accountill.com>",
                    subject:"Password reset request",
                    html:`<p>You requested for password reset.</p>
                    <h5>Please click this <a href="https://accountill.com/reset/${token}">link</a> to reset your password</h5>`
                })
                res.json({message:"Check your email for reset link"})
            })
        })
    })
}

export const resetPassword = (req,res)=>{
    const { password, token } = req.body
    User.findOne({resetToken:token, expireToken:{$gt:Date.now()}})
    .then(user=>{
        if(!user) return res.status(422).json({error:"Try again session expired"})
        bcrypt.hash(password,12).then(hashedPassword=>{
            user.password = hashedPassword
            user.resetToken = undefined
            user.expireToken = undefined
            user.save().then(()=>res.json({message:"Password updated successfully"}))
        })
    }).catch(err=>console.log(err))
}


export const createUser = async (req, res) => {
    try {
        const { name, email, password, role } = req.body
        const existingUser = await User.findOne({ email })
        if(existingUser) return res.status(400).json({ message: "User already exists" })

        const hashedPassword = await bcrypt.hash(password, 12)
        const newUser = await User.create({ name, email, password: hashedPassword, role })
        res.status(201).json({ message: "User created successfully", user: newUser })
    } catch (error) {
        res.status(500).json({ message: "Error creating user", error })
    }
}

export const getUsers = async (req, res) => {
    try {
        const { role } = req.query;

        let users;
        if (role) {

            users = await User.find({ role });
        } else {

            users = await User.find();
        }

        res.status(200).json({ count: users.length, users });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error fetching users", error });
    }
};


export const updateUser = async (req, res) => {
    try {
        const { id } = req.params
        const updates = req.body

        if(!mongoose.Types.ObjectId.isValid(id)) return res.status(404).json({ message: "Invalid user ID" })
        const updatedUser = await User.findByIdAndUpdate(id, updates, { new: true })
        if(!updatedUser) return res.status(404).json({ message: "User not found" })

        res.status(200).json({ message: "User updated successfully", user: updatedUser })
    } catch (error) {
        res.status(500).json({ message: "Error updating user", error })
    }
}

export const deleteUser = async (req, res) => {
    try {
        const { id } = req.params
        if(!mongoose.Types.ObjectId.isValid(id)) return res.status(404).json({ message: "Invalid user ID" })

        const deletedUser = await User.findByIdAndDelete(id)
        if(!deletedUser) return res.status(404).json({ message: "User not found" })

        res.status(200).json({ message: "User deleted successfully" })
    } catch (error) {
        res.status(500).json({ message: "Error deleting user", error })
    }
}
