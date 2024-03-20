"use server"
import { getIronSession } from "iron-session"
import { sessionOptions, SessionData, defaultSession } from "./lib"
import { cookies } from 'next/headers'
import mariadb from 'mariadb';
import bcrypt from 'bcrypt';
import { redirect } from "next/navigation";

// Database pool for connection

const pool = mariadb.createPool({
    host: 'localhost',
    user: 'maria-woman',
    password: 'oui',
    database: 'website'
});

// Authentication system

export const getSession = async () => {
    const session = await getIronSession<SessionData>(cookies(), sessionOptions);

    if (!session.isLoggedIn) {
        session.isLoggedIn = defaultSession.isLoggedIn;
    }

    return session;
}

export const login = async (prevState: { error: undefined | string }, formData: FormData) => {
    const session = await getSession();

    const formUsername = formData.get("username") as string;
    if (formUsername.length > 24) {
        return {error:"Username must have less than 24 characters"};
    }

    // TODO - SANITIZE the username
    // const regex = new RegExp('^[A-Za-z][A-Za-z0-9_]{0,23}$'); 
    const sanitizedUsername = formUsername;

    const formPassword = formData.get("password") as string;

    const userFound: boolean = await userExists(formUsername);

    if (!userFound) {
        return {error:"User doesn't exist"};
    }

    const [userHashedPassword, salt] = await getUserHashedPasswordAndSalt(formUsername) as [string, string];

    if (!userHashedPassword || !salt) {
        return {error:"Error retrieving password"};
    }

    const formHashedPassword: string = await bcrypt.hash(formPassword, salt);

    if (formHashedPassword != userHashedPassword) {
        return {error:"Passwords not matching"};
    }

    const [userId, isAdmin] = await getUserInfo(sanitizedUsername) as [string, boolean];

    session.userId = userId;
    session.username = sanitizedUsername;
    session.isAdmin = isAdmin;
    session.isLoggedIn = true;

    await session.save();
    redirect('/');
}

export const logout = async () => {
    const session = await getSession();
    session.destroy();
    redirect('/')
}

export const register = async (prevState: { error: undefined | string }, formData: FormData) => {
    const formUsername = formData.get("username") as string;
    const formPassword1 = formData.get("password1") as string;
    const formPassword2 = formData.get("password2") as string;

    if (formPassword1 !== formPassword2) {
        return {error:"Passwords not matching"};
    }

    const [hashedPassword, salt] = await hashPassword(formPassword1)

    createNewUser(formUsername, hashedPassword, salt);

    redirect('/login');
}

// Password Hasher (bcrypt used)

async function hashPassword(plainTextPassword: string): Promise<[string, string]> {
    const saltRounds = 10; // You can adjust the number of rounds based on your security requirements
    const salt = await bcrypt.genSalt(saltRounds);
  
    const hashedPassword = await bcrypt.hash(plainTextPassword, salt);
  
    return [hashedPassword, salt];
}

// Database functions

async function createNewUser(username: string, hashedPassword: string, salt: string) {
    let conn;
    try {    
        conn = await pool.getConnection();
        const query = await conn.prepare("INSERT INTO users (username, hashed_password, salt, is_admin) VALUES (?, ?, ?, FALSE)");
        await query.execute([username, hashedPassword, salt]);
    } finally {
        if (conn) conn.release(); // release to pool
    }
}

async function userExists(username: string): Promise<boolean> {
    let conn;
    let user;
    try {    
        conn = await pool.getConnection();
        const query =  await conn.prepare("SELECT * FROM users WHERE username = ?");
        user = await query.execute([username]);
    } catch (error) {
        if (conn) conn.release();
        return false
    } finally {
        if (conn) conn.release();
        return user.length === 0 ? false : true
    }
}

async function getUserHashedPasswordAndSalt(username: string): Promise<[string, string]> {
    let userHashedPassword, salt;
    let conn;
    try {    
        conn = await pool.getConnection();
        const query =  await conn.prepare("SELECT hashed_password, salt FROM users WHERE username = ?");
        const result = await query.execute([username]);
        userHashedPassword = result[0]["hashed_password"]
        salt = result[0]["salt"]
    } finally {
        if (conn) conn.release(); // release to pool
        return [userHashedPassword, salt];
    }
}

async function getUserInfo(username: string): Promise<[string, boolean]> {
    // Return the userId, username and isAdmin values
    let userId, isAdmin;
    let conn;
    try {    
        conn = await pool.getConnection();
        const query =  await conn.prepare("SELECT user_id, is_admin FROM users WHERE username = ?");
        const result = await query.execute([username]);

        userId = result[0]["user_id"];
        isAdmin = result[0]["is_admin"];
    } finally {
        if (conn) conn.release(); // release to pool
        return [userId, isAdmin];
    }
}