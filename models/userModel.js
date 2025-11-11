import mongoose from 'mongoose'

const userSchema = mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: {
        type: String,
        enum: ['Viewer', 'Admin', 'SuperAdmin'],
        default: 'Viewer'
    },
    resetToken: String,
    expireToken: Date,
})

const User = mongoose.model('User', userSchema)
export default User
