import express from "express"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv"

dotenv.config()

const app = express();
const port = 4000;
app.use(cookieParser())
app.use(express.json())	

let users = []

app.post("/signup", async (req, res) => {
	const { user, pass } = req.body;
	if (!user || !pass) {
		return res.status(400).json({ err: "No pass or user given" })
	}
	const hashedPass = await bcrypt.hash(pass, 10);
	const newUser = { user, pass : hashedPass };
	users.push(newUser)
	const token = await jwt.sign({id: newUser.user}, process.env.JWT_SECRET);
	res.cookie("token", token, {
		httpOnly: true
	})
	res.status(201).json({ "Token" : token });
})

app.get("/signin", async (req, res) => {
	const { user, pass } = req.body;
	if (!user || !pass) return res.status(400).json({ err: "No password or user given" });
	const userFound = await users.find((e) => e.user == user);
	if (!userFound ) return res.status(404).json({ err: "No user found" });
	const passwordMatch = await bcrypt.compare(pass, userFound.pass);
	if (!passwordMatch) return res.status(404).json({ err: "Invalid Credentials" })
	res.status(200).send("Auth Suceessful")
})

app.get("/token", async (req, res) => {
	const token = req.cookies.token;
	if (!token) return res.status(404).json({
		message: "cookie not found"
	})
	const validateToken = await jwt.verify(token, process.env.JWT_SECRET);
	if (!validateToken) return res.status(404).json({
		message: "Invalid token"
	})
	return res.status(200).json({
		data: validateToken
	})
})

app.get("/users", async (req, res) => {
	return res.status(200).send(users)
})

app.get("/", (req, res) => {
	return res.send("App is running");
})


app.listen(port, () => {
	console.log(`http://localhost:${port}`)
})
