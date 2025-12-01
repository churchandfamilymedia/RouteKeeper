const bcrypt = require('bcryptjs');

// !!! REPLACE THIS STRING WITH YOUR DESIRED ADMIN PASSWORD !!!
const adminPassword = 'Church1973'; 

const saltRounds = 10;

bcrypt.hash(adminPassword, saltRounds, function(err, hash) {
    if (err) {
        console.error("Error generating hash:", err);
        return;
    }
    console.log("-----------------------------------------------------------------");
    console.log("Your Hashed Password (Copy this ENTIRE string for MongoDB):");
    console.log(hash);
    console.log("-----------------------------------------------------------------");
});