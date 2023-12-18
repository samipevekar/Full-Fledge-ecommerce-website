const express = require("express");
const path = require("path");
const collection = require("./mongo");
const bcrypt = require("bcrypt");

const app = express();

app.use(express.static("public"));
app.use(express.urlencoded());
app.use(express.json());

app.set("view engine", "ejs");

app.get("/", (req, res) => {
    res.render("login", { errorMessage: null });
});

app.get("/signup", (req, res) => {
    res.render("signup", { errorMessage: null });
});

// Registered users
app.post("/signup", async (req, res) => {
    const data = {
        name: req.body.username,
        email: req.body.email,
        tel: req.body.tel,
        password: req.body.password,
    };

    try {
        // Validate the phone number
        if (!isValidPhoneNumber(data.tel)) {
            const errorMessage = "Invalid phone number";
            return res.render("signup", { errorMessage });
        }

        const existingUserEmail = await collection.findOne({ email: data.email });
        const existingUserTel = await collection.findOne({ tel: data.tel });

        if (existingUserEmail || existingUserTel) {
            const errorMessage = "User already exists";
            return res.render("signup", { errorMessage });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(data.password, saltRounds);
        data.password = hashedPassword;

        await collection.insertMany(data);
        res.render("login", { errorMessage: null });
    } catch (error) {
        console.error(error);
        const errorMessage = "Error during signup";
        res.render("signup", { errorMessage });
    }
});

// Login users
app.post("/login", async (req, res) => {
    try {
        const emailOrTel = req.body.emailOrTel;
        const password = req.body.password;

        // Check if the provided input is an email or phone number
        const user = await collection.findOne({
            $or: [{ email: emailOrTel }, { tel: emailOrTel }],
        });

        if (!user) {
            const errorMessage = "Username not found";
            return res.render("login", { errorMessage });
        }

        // Compare the hashed password from the database with the plain text
        const isPasswordMatch = await bcrypt.compare(password, user.password);

        if (isPasswordMatch) {
            res.render("index");
        } else {
            const errorMessage = "Wrong password";
            res.render("login", { errorMessage });
        }
    } catch (error) {
        console.error(error);
        const errorMessage = "Error during login";
        res.render("login", { errorMessage });
    }
});

// Function to validate phone number
function isValidPhoneNumber(phoneNumber) {
    // Check if the phone number does not start with 0 and has exactly 10 digits
    return /^[1-9]\d{9}$/.test(phoneNumber);
}

app.listen(80, () => {
    console.log("server is listening on port 80");
});
