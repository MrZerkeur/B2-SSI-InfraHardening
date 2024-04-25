"use server"
import { getIronSession } from "iron-session"
import { sessionOptions, SessionData, defaultSession } from "./lib"
import { cookies } from 'next/headers'
import mariadb from 'mariadb';
import bcrypt from 'bcrypt';
import path from "path";
import { redirect } from "next/navigation";
import { writeFile } from "fs/promises";

// * Database pool for connection

const pool = mariadb.createPool({
    host: 'localhost',
    user: 'maria-woman',
    password: 'oui',
    database: 'website'
});

// * Authentication system

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
    
    const [sanitizedUsername, error] = sanitizeUsername(formUsername);
    if (!sanitizedUsername) {
        return error;
    }

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

    const [sanitizedUsername, error] = sanitizeUsername(formUsername);
    if (!sanitizedUsername) {
        return error;
    }

    const formPassword1 = formData.get("password1") as string;
    const formPassword2 = formData.get("password2") as string;

    if (formPassword1 !== formPassword2) {
        return {error:"Passwords not matching"};
    }

    const [hashedPassword, salt] = await hashPassword(formPassword1)

    createNewUser(formUsername, hashedPassword, salt);

    redirect('/login');
}

// * Password Hasher (bcrypt used)

async function hashPassword(plainTextPassword: string): Promise<[string, string]> {
    const saltRounds = 10; // You can adjust the number of rounds based on your security requirements
    const salt = await bcrypt.genSalt(saltRounds);
  
    const hashedPassword = await bcrypt.hash(plainTextPassword, salt);
  
    return [hashedPassword, salt];
}

// * Sanitize function

function sanitizeUsername(username: string): [undefined | string, { error: undefined | string }] {
    const trimmedUsername = username.trim().replace(/\s+/g, ''); // remove all spaces

    if (trimmedUsername.length > 24) {
        return [undefined, { error: "Username must have less than 25 characters" }];
    }

    const regex = new RegExp('^[A-Za-z][A-Za-z0-9]{0,23}$');
    const usernameValid: boolean = regex.test(trimmedUsername);

    if (!usernameValid) {
        return [undefined, { error: "Username must have less than 25 characters, start with a letter and only contain letters or numbers" }];
    }
    return [trimmedUsername, { error: undefined }]
}

// * Database functions

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

// * Contact form

export const contact = async(formData: FormData) => {
  console.log(formData);
  const firstName = formData.get('firstName') as string;
  const lastName = formData.get('lastName') as string;
  const email = formData.get('email') as string;
  const tel = formData.get('tel') as string | null;
  const message = formData.get('message') as string;
  const file = formData.get('file') as File;
  let filePath = null
  if (file) {
    filePath = await uploadFile(file);
  }
  await addNewContactForm(firstName, lastName, email, message, tel, filePath)
}

async function addNewContactForm(firstName : string, lastName : string, email : string, message : string, tel : string | null, file_path: string | null) {
  let conn;
    try {
        conn = await pool.getConnection();
        const query = await conn.prepare("INSERT INTO contact_forms (first_name, last_name, email, message, tel, file_path) VALUES (?, ?, ?, ?, ?, ?)");
        await query.execute([firstName, lastName, email, message, tel, file_path]);
    } finally {
        if (conn) conn.release(); // release to pool
    }
}

async function uploadFile(file: File): Promise<string> {
  const buffer = Buffer.from(await file.arrayBuffer());
  const filename =  file.name.replaceAll(" ", "_");
  const filePath = path.join(process.cwd(), "public/assets/" + filename);
  await writeFile(
    path.join(filePath),
    buffer
  );
  return filePath;
}

export interface ContactForm {
  firstName: string;
  lastName: string;
  email: string;
  message: string;
  tel: string;
  filePath: string;
}

export async function getAllContactForms(): Promise<ContactForm[]> {
  const contactForms: ContactForm[] = [];
  let conn;
  try {    
    conn = await pool.getConnection();
    const query =  await conn.prepare("SELECT first_name, last_name, email, message, tel, file_path FROM contact_forms");
    const rows = await query.execute();
    for (const row of rows) {
      const contactForm: ContactForm = {
        firstName: row["first_name"],
        lastName: row["last_name"],
        email: row["email"],
        message: row["message"],
        tel: row["tel"],
        filePath: row["file_path"],
      };
      contactForms.push(contactForm)
    }
  } finally {
    if (conn) conn.release(); // release to pool
    return contactForms;
  }
}