const express = require("express")
const cors = require('cors')


const mysql = require("mysql")
const app = express();
const port = 3000
var sha1 = require('sha1')
var pool = mysql.createPool({
    connectionLimit: 10,
    host: "localhost",
    user: "root",
    password: "",
    port: 3307,
    database: "2026_stepcounter"
});
app.use(cors()) //Access-Control-Allow-Origin
app.use(express.urlencoded({extended: true})) //ettől működik a req.body
app.use(express.json()); //kommunikáció json formában

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
        return res.status(400).json({error: '[REGISTERMissingFields] Missing required fields'})
    }

    //check if pws match
    if(password !==confirm){
        return res.status(400).json({error: 'Passwords do not match'})
    }
    //TODO: check pw strength (with regular expression)


    //check if email already exists               ˇbehejettesíti az utána lévő tömböt ----- SQL injection!
    pool.query('SELECT * FROM users WHERE email = ?', [email], (error, results) =>{
        if (error){
            return res.status(500).json({error: '[REGISTEREmailCheckDBError] Database query error'})
        }
        if(results.length>0){
            return res.status(400).json({ error: '[REGISTEREmailCheckExistError] This e-mail already exists'})
        }

        
    pool.query('INSERT INTO users (name, email, password, role) VALUES (?, ?, SHA1(?), "user")', [name, email, password], (error, results) => {
        if(error){
            return res.status(500).json({error: '[REGISTERDBInsertError] Database insertion error; msg: ' +error})
        }
        
        
            
            return res.status(201).json({message: '[REGISTERDBInsertSuccess] User registered successfully'})
        
    });

   
    })
})

//login
//TODO: időzónák lekezelése
app.post('/users/login', (req, res) =>{
    const {email, passwd} = req.body
    //VALIDATION

    //CHECK FOR MISSING FIELDS
    if (!email || !passwd){
        return res.status(400).json({error: '[LOGINFieldError] Missing required fields'})
    }

    //LOGIN email+pw check
    pool.query('SELECT * FROM users WHERE email=? AND password=SHA1(?)', [email, passwd],(error, results)=>{
        if (error){
            return res.status(500).json({error: '[LOGINEmailPwCheckError] Database query error'+error})
        }
        // if user doesn't exists with this email and/or password  
        if(results.length == 0){
            return res.status(400).json({error: '[LOGINCredentialsError] Invalid credentials!'})
        }

        //LOGIN ban check
        if(results[0].is_active == 0){
            return res.status(400).json({error: '[LOGINUserHasBeenBanned] This user has been banned by admin!'})
        }       

        const loggedUser = {
            ID: results[0].id,
            name: results[0].name,
            email: results[0].email,
            role: results[0].role
        }
        //LOGIN UPDATE TIMESTAMP
        pool.query('UPDATE users SET last_login=CURRENT_TIMESTAMP, login_count=login_count+1 WHERE ID=?' , [loggedUser.ID], (error, results)=>{
            if (error){
            return res.status(500).json({error: '[LOGINUpdateTimestampError] Database query error'})
            }
            //LOGIN success
            return res.status(200).json({message: '[LOGINSuccess] You are successfully logged in! ', loggedUser})
        })
            
    })


})

//logout - elv nem kell rá endpoint

//pw change
app.post('/users/:uid/changepassword', (req, res)=>{
    const {oldpass, newpass, confirm} = req.body
    const uid =req.params.uid
    if(!oldpass || !newpass ||!confirm){
        return res.status(400).json({error: '[CHANGEPWDBError] Missing required fields'})
    }
    if (newpass != confirm){
        return res.status(400).json({error: '[CHANGEPWConfirmMatchError] The new password and the confirm does not match!'})
    }
    if (oldpass == newpass){
        return res.status(400).json({error: '[CHANGEPWOldMatchError] The new and old password cannot match!'})
    }

    //TODO: newpassword strength check with regular expression


    pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results)=>{
        if(error){
            return res.status(500).json({error: '[UIDDBError] Database Query Error'+error})
        }
        if(results.length ==0){
            return res.status(400).json({error: '[UIDNonExistent] There\'s no user with this UID in database'})
        }


        const oldpassHash = sha1(oldpass)

        console.log(results[0].passwd == oldpassHash)

        if(results[0].password != oldpassHash){
            return res.status(400).json({error: '[CHANGEPWOldIncorrect] The old password is not correct ' })
        }
    
        //update password
        pool.query('UPDATE users SET password=SHA1(?) WHERE ID=?', [newpass ,uid], (error, results)=>{
            if(error){
                return res.status(500).json({error: '[PWUpdateError] Database Query Error'})
            }
            res.status(200).json({message:'[PWUpdateSuccess] The password has been succesfully changed'})
        })
    })


});



//get profile
app.get('/users/:uid', (req, res)=>{
    const uid =req.params.uid
    if(!uid){
        return res.status(400).json({error: '[GETProfileMissingIDError] Missing user identifier'})
    }

    pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results) =>{
        if(error){
            return res.status(500).json({error: '[GETProfileDBError] Database query error'})
        }
        //ha nincs ilyen id a táblában
        if(results.length==0){
            return res.status(400).json({error: '[GETProfileError] There is no user that exists with this ID'})
        }
let user={
    "name": results[0].name,
    "email": results[0].email,
    "role": results[0].role,
    "created_at": results[0].created_at,
}


        //ha van ilyen user a táblában:
        return res.status(200).json({results: user})
    })


})




//update profile
//TODO: update profile


//del profile
app.delete('/users/:uid', (req, res)=>{
    const uid = req.params.uid
    const loggedUserId = req.body.luid

    if(!uid || !loggedUserId){
        return res.status(400).json({error: '[DELETEProfileMissingIDError] Missing user identifier'})
    }
    if(uid != loggedUserId){
        
        return res.status(400).json({error: '[DELETEUserProfilePermissionError] You don\'t have permission to delete this user'})
    
    }
    pool.query('DELETE FROM users WHERE ID=?', [uid], (error, results)=>{
        if(error){
            return res.status(500).json({error: '[DELETEUserError] Database query error '+error})

        }
        if(results.affectedRows ==1){
            return res.status(200).json({message: '[DELETEUserSuccess] User deleted successfully'})
        }
        
        return res.status(200).json({message: '[DELETENoDeletion] No deletion occured'})
    })
})



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