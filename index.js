import express from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
const app = express()
const port = 5000

//url to use this api http://localhost:5000/hashMyPassword/123
app.get('/hashMyPassword/:password', (req, res) => {
    if (!req.params.password) {
        return res.send("<h1>please enter needed values</h1>")
    }
    //the hashsync takes 2 inputs the password to be encrypted and the salt number
    const hashResult = bcrypt.hashSync(req.params.password, 8) //8 here represents the salt number that indicates how many rounds of encryption the password is going to go through
    return res.status(200).json(hashResult)
})

//ur to use this api http://localhost:5000/checkMyPassword?password=123&hashValue=$2a$08$4MyYa3EBH.2SFEq64j7BdeIH1SdghBu9lpvG0/CsJVy1tt4dpb3ru
app.get('/checkMyPassword', (req, res) => {
    if (!req.query.password || !req.query.hashValue) {
        return res.send("<h1>please enter needed values</h1>")
    }
    const match = bcrypt.compareSync(req.query.password, req.query.hashValue)
    return res.status(200).json(match)
})

//url to use this api http://localhost:5000/giveMeAToken?name=ahmed&id=12
app.get('/giveMeAToken', (req, res) => {

    if (!req.query.id || !req.query.name) {
        return res.send("<h1>please enter needed values</h1>")
    }
    //the jwt.sign functuon takes 3 inputs 1st payload which is what is going to be encoded in the token
    //2nd signature which is the signature thats going to be used later to decode the token
    //and 3rd the expiry date of this token on which this token will no longer be valid
    const payload = {
        id: req.query.id,
        name: req.query.name
    }
    const token = jwt.sign(payload, "a123", { expiresIn: 60 * 60 }); //60*60 meaning it will last for an hour
    return res.status(200).json(token)
})

//url to use this api http://localhost:5000/decodeMyToken/
app.get('/decodeMyToken/:token', (req, res) => {
    if (!req.params.token) {
        return res.send("<h1>please enter needed values</h1>")
    }
    //jwt.verify function takes 2 inputs the token and the signature used to encode the token
    const decoded = jwt.verify(req.params.token, "a123");
    return res.status(200).json(decoded)
})

app.get('/',(req,res)=>{
    res.send("<div style='text-align:center'><h1>Hello World</h1></div>")
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`))