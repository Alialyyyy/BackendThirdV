import mysql from 'mysql2/promise';
import dotenv from "dotenv";

dotenv.config();

const pool = mysql.createPool({
    host: 'sql12.freesqldatabase.com',
    user: 'sql12761774',
    password: 'gW8LxG3Hgk',
    database: 'sql12761774',
    port: 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

export default pool;
