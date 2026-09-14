const express = require("express")
const mysql = require("mysql")
const app = express();
const port = 3000

var pool = mysql.createPool({
    connectionLimit: 10,
    host: "localhost",
    user: "root",
    password: "",
    port: 3307,
    database: "stepcounter"
});

app.use(express.urlencoded({extended: true})) //ettől működik a req.body


app.get('/', (req, res) => {
    res.send('Welcome to the Step Counter API!');
    
})


//USERS ENDPOINTS -------------------------------

//register
app.post('/users/register', (req, res) =>{
    const {name, email, password, confirm} = req.body; //elszedi a req.bodytól az adatokat
    
    //VALIDATE  
    //check for missing fields
    if(!name || ! email || !password ||!confirm){
        return res.status(400).json({error: '[REGISTER] Missing required fields'})
    }

    //check if pws match
    if(password !==confirm){
        return res.status(400).json({error: 'Passwords do not match'})
    }
    //check pw strength TODO <<<-----------


    //check if email already exists               ˇbehejettesíti az utána lévő tömböt
    pool.query('SELECT * FROM users WHERE email = ?', [email], (error, results) =>{
        if (error){
            return res.status(500).json({error: '[REGISTER email check] Database query error'})
        }
        if(results.length>0){
            return res.status(400).json({ error: '[REGISTER email check] This e-mail already exists'})
        }

        
    pool.query('INSERT INTO users (name, email, password, role) VALUES (?, ?, SHA1(?), "user")', [name, email, password], (error, results) => {
        if(error){
            return res.status(500).json({error: '[REGISTER DB INSERT] Database insertion error; msg: ' +error})
        }
        res.status(201).json({message: '[REGISTER DB INSERT] User registered successfully'})
    })
    })
})

//login

//logout

//pw change

//get profile

//update profile

//del profile

//STEPS ENDPOINTS -------------------------------
//CREATE step
//get steps
//update step
//delete step


//ADMIN ENDPOINTS -------------------------------
//get all users
app.get('/admin/users', (req, res) => {
    pool.query('SELECT * FROM users', (error, results) => {
        if (error) {
            console.error('Error fetching users:', error);
            res.status(500).json({ '[GET * users] Database query error: ': error });
        } else {
            res.status(200).json(results);
        }
    });
});
    
//stats
//deny user





app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});