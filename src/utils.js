import {fileURLToPath} from 'url'
import { dirname } from 'path'
const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

import bcrypt from 'bcrypt'

export default __dirname

//helper function
export const createHash = password => bcrypt.hashSync(password, bcrypt.genSaltSync(10))

//helper function
export const isValidPassword = (user, password) => bcrypt.compareSync(password, user.password)
