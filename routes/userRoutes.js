// routes/userRoutes.js
import express from 'express'
import { 
    signin, 
    signup, 
    forgotPassword, 
    resetPassword, 
    createUser, 
    updateUser, 
    deleteUser,
    getUsers
} from '../controllers/user.js'

const router = express.Router()


router.post('/signin', signin)
router.post('/signup', signup)
router.post('/forgot', forgotPassword)
router.post('/reset', resetPassword)


router.post('/', createUser)
router.put('/:id', updateUser)
router.delete('/:id', deleteUser)

router.get('/', getUsers);

export default router
