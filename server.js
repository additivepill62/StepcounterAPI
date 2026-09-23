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
    database: "2026_stepcounter",
    timezone:'Europe/Budapest'
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




//update profile (un email (lehetne még phone address description, picture.....))
//TODO: update profile

//patch: reszleges modositas
app.patch('/users/:uid', (req, res)=>{
    const uid = req.params.uid;
    const {username, email, luid} = req.body

    if(!uid || !username || !email || !luid){
        return res.status(400).json({error: '[PATCHUserUpdateFieldError] Missing required fields'})
    }

    if(uid != luid){
        return res.status(400).json({error: '[PATCHUserProfilePermissionError] You don\'t have permission to update this user\'s data'})
    }

    pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results)=>{
        if(error){
            return res.status(500).json({error: '[PATCHUserError] Database query error '})
        }
        if(results.length ==0){
            return res.status(400).json({error: '[PATCHUserMissingError] There is no user with this ID in the Database!'})
        }

        if((username == results[0].name) && (email == results[0].email)){   
            return res.status(200).json({message: '[PATCHUserDataUnchanged] No update occured! '})

        }

        pool.query('SELECT * FROM users WHERE email=? AND ID<>?', [email, uid], (error2, results2)=>{
            if(error2){
            return res.status(500).json({error: '[PATCHUserEmailCheck] Database query error '})
            }
            if (results2.length >0){
                return res.status(400).json({error: '[PATCHEmailInUse] This email address is already in use '})
            }



            pool.query('UPDATE users SET name=?, email=?, updated_at=CURRENT_TIMESTAMP WHERE ID=?', [username, email, uid], (error3, results3)=>{
                if(error3){
                    return res.status(500).json({error: '[PATCHUserUpdateError] Database query error '})
                }
                return res.status(200).json({message: '[PATCHUserUpdateSuccess] User\'s data has been updated successfully '})
            })
        })
    })


})

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
            return res.status(500).json({error: '[DELETEUserError] Database query error '})

        }
        if(results.affectedRows ==1){
            return res.status(200).json({message: '[DELETEUserSuccess] User deleted successfully'})
        }
        
        return res.status(200).json({message: '[DELETENoDeletion] No deletion occured'})
    })
})



//STEPS ENDPOINTS -------------------------------
//CREATE step
app.post('/steps/:uid', (req,res)=>{
    const uid = req.params.uid
    const {luid, step_count, date} = req.body
    let currentDate = new Date()
    if(!uid || !luid || !step_count || !date){
        return res.status(400).json({error: '[CREATESteps] Missing user params'})
    }

    if(uid != luid){
        return res.status(400).json({error: '[CREATEStepsPermissionError] You don\'t have permission to add steps to this user'})
    }
    if(step_count <=0){
        return res.status(400).json({error: '[CREATEStepsStepCountError] You can\'t input steps that are less then or equal to 0'})
    }/*
    if(date <=0){
        return res.status(400).json({error: '[CREATEStepsDateError] You can\'t input date that are less then or equal to 0'})
    }*/
    if(new Date(date)>currentDate){
        return res.status(400).json({error: '[CREATEStepsDateError] You can\'t input date from the future'})
    }   


        pool.query('SELECT * FROM steps WHERE user_id=?', [uid], (error, results)=>{
        if(error){
            return res.status(500).json({error: '[INSERTStepsUIDCheckError] Database query error '+error})
        }
        if(results.length ==0){
            return res.status(400).json({error: '[INSERTStepsUIDMissingError] There is no user with this ID in the Database!'})
        }

            pool.query('SELECT * FROM steps WHERE user_id=? AND date=?', [uid, date], (error2, results2)=>{
                if(error2){
                return res.status(500).json({error: '[INSERTStepsDateExistsError] Database query error '+error2})
                }
                if(results2.length > 0 && results2[0].date == date){
                    return res.status(400).json({error: '[CREATEStepsCheckIfExists] This date is already in DB '})
                }  



                pool.query('INSERT INTO steps (user_id, step_count, date) VALUES (?,?,?)', [uid, step_count, date], (error, results)=>{
                if(error){
                    return res.status(500).json({error: '[INSERTSteps] Database insert error '})
                }
                    return res.status(200).json({message: '[INSERTStepsSuccess] Step has been successfully added'})
                })
            })
  })


})
//get steps
app.get('/steps/:uid', (req, res)=>{
    const uid = req.params.uid
    const {luid} = req.body
    if(!uid || !luid){
        return res.status(400).json({error: '[CREATESteps] Missing user params'})
    }

    if(uid != luid){
        return res.status(400).json({error: '[CREATEStepsPermissionError] You don\'t have permission to access this users\s step data!'})
    }

    pool.query('SELECT * FROM STEPS WHERE user_id=?', [uid], (error, results)=>{
        if(error){
            return res.status(500).json({error: '[GETALLSteps] Database select error '})

        }
        if(results.length==0){
            return res.status(400).json({error: '[GETALLStepsError] There is no steps that exists with this ID'})
        }
    


        //ha van ilyen user a táblában:
        return res.status(200).json({results: results})
    })
})



//update step
app.patch('/steps/:uid', (req,res)=>{
    const uid = req.params.uid
    const {luid, step_count, date} = req.body
    let currentDate = new Date()
    if(!uid || !luid || !step_count || !date){
        return res.status(400).json({error: '[UPDATESteps] Missing user params'})
    }
    //TODO:negative date
    /*
    if(date[0]=='-'){
        date.trim[0]
    }*/
    if(uid != luid){
        return res.status(400).json({error: '[UPDATEStepsPermissionError] You don\'t have permission to delete this user'})
    }
    /*if(step_count <=0){
        return res.status(400).json({error: '[CREATEStepsStepCountError] You can\'t input steps that are less then or equal to 0'})
    }*/
    if(date <= new Date('0000-00-00')){
        return res.status(400).json({error: '[CREATEStepsDateError] You can\'t input date that are less then or equal to 0'})
    }
    if(new Date(date)>currentDate){
        return res.status(400).json({error: '[CREATEStepsDateError] You can\'t input date from the future'})
    }   

    
    pool.query('SELECT * FROM STEPS WHERE id=?',[uid], (error, results)=>{
        if(error){
            return res.status(500).json({error: '[UPDATEStepsSelectError] Database get error '})
            
        }
        if(results[0].step_count ==step_count && results[0].date == date){
            return res.status(400).json({error: '[UPDATEStepsCheckError] You didn\'t change any values! '})
        } 
         pool.query('SELECT * FROM steps WHERE user_id=? AND date=?', [uid, date], (error2, results2)=>{
                if(error2){
                return res.status(500).json({error: '[INSERTStepsDateExistsError] Database query error '+error2})
                }
                if(results2.length > 0 && results2[0].date == date){
                    return res.status(400).json({error: '[CREATEStepsCheckIfExists] This date is already in DB '})
                }  
                pool.query('UPDATE steps SET step_count=?, date=?, updated_at=CURRENT_TIMESTAMP WHERE ID=?', [step_count, date, uid], (error, results2)=>{
                    if(error){
                        return res.status(500).json({error: '[UPDATESteps] Database insert error '})
                        
                    }
                    return res.status(200).json({message: '[UPDATEStepssSuccess] Step has been successfully modified'})
                });
            })
    })
})
//delete step
app.delete('/steps/:uid/:sid', (req,res)=>{
    const uid = req.params.uid
    const sid = req.params.sid
    const luid = req.body.luid
    if(!uid || !luid || !sid){
        return res.status(400).json({error: '[DELETEStep] Missing user params'})
    }

    if(uid != luid){
        return res.status(400).json({error: '[DELETEStepPermissionError] You don\'t have permission to delete this step'})
    }


    pool.query('SELECT * FROM STEPS WHERE user_id=?',[uid], (error, results)=>{
        if(error){
            return res.status(500).json({error: '[DELETEStepUIDSelectError] Database get error '})
            
        }
        pool.query('SELECT * FROM STEPS WHERE ID=?',[sid], (error, results)=>{
        if(error){
            return res.status(500).json({error: '[DELETEStepSIDSelectError] Database get error '})
            
        }
        if(results.length==0){
            return res.status(400).json({error: '[DELETEStepSIDExistCheck] There is no step with this ID! '})
        }
    
        
            pool.query('DELETE FROM steps WHERE ID=?', [sid], (error, results2)=>{
                if(error){
                    return res.status(500).json({error: '[DELETEStep] Database delete error '})
                
                }
                return res.status(200).json({message: '[DELETEStepsSuccess] Step has been successfully deleted'})
            });
        })
    })

})

//ADMIN ENDPOINTS -------------------------------
// get all users
app.post('/admin/users', (req, res) =>{
    const luid = req.body. luid;

    if (!luid) {
        return res.status(400).json({ error: '[POSTUsersFieldError] Missing required fields!' });
    }
    // megnézzük, hogy aki hívja ezt az endpointot, az admin-e?
    pool.query('SELECT * FROM users WHERE ID =? ', [luid], (error, results1) => {
        if (error) {
            return res.status(500).json({ error:'[POSTUsersDBIDError] Database query error ' });
        }
        if (results1.length == 0) {
            return res.status(400).json({ error: '[POSTUsersIDNonexistent] User with this ID doesn\'t exist!' });
        }
        if (results1[0].role != 'admin') {
            return res.status(400).json({ error: '[POSTUsersPermissionDenied] You don\t have permission to change this user status!' });
        }
        pool.query('SELECT * FROM users', (error, results) => {
        if (error) {
        return res.status(500).json({ error: '[POSTUsersDBError] Database query error' });

        }

        return res.status(200).json(results);

        });
    });
});

    
//stats
//deny user
app.post('/admin/status', (req, res)=>{
    const {uid, luid} = req.body

    

    if(!uid || !luid){
         return res.status(400).json({error: '[POSTDenyUser] Missing required fields '})
    }


    pool.query('SELECT * FROM users WHERE ID =? ', [luid], (error, results1)=>{
        if (error) {
            return res.status(500).json({ error: '[POSTDenyUserRoleCheck] Database query error' });
        }
        if (results1.length == 0){
            return res.status(400).json({ error: '[POSTDenyUserRoleExistCheck] User with this ID doesn\'t exist!' });
        }
        if (results1[0].role != 'admin'){
            return res.status(400).json({ error: '[POSTDenyUserRoleEditCheck] You don\t have permission to edit this role!' });
        }
    
         pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results)=>{
            if(error){
                return res.status(500).json({error2: '[POSTDenyUser] Database query error '})
            }

            if(results.length==0){
                 return res.status(400).json({error2: '[POSTDenyUserUIDNonexistent] No user exists with this ID '})
            }

            pool.query('UPDATE users SET is_active=not is_active WHERE ID=?', [uid], (error, results2) =>{
            if(error){
                return res.status(500).json({error2: '[POSTDenyUserBan] Database query error '})
            }

            return res.status(200).json({message: '[POSTUserBanSuccess] User has been banned'})
            })
        })
    })


   


})




app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});