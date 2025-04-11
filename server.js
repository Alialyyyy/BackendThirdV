import express from 'express';
import cors from 'cors';
import pool from './db.js';
import http from 'http';

import { Server } from 'socket.io';

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*",
        methods: ["GET", "POST"]
     }
});

app.use(express.json());
app.use(cors());



// 🛠 LOGIN API STOC
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const [results] = await pool.execute(
            'SELECT * FROM STOC_ACCOUNTS WHERE username = ? AND password = ?',
            [username, password]
        );

        if (results.length > 0) {
            res.json({ message: 'Login successful' });
        } else {
            res.status(401).json({ message: 'Invalid username or password' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Database error', error: error.message });
    }
});

// 🛠 LOGIN API STORE
app.post('/api/login2', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and Password are required' });
    }

    try {
        const [results] = await pool.execute(
            'SELECT * FROM STORE_ACCOUNTS WHERE username = ? AND password = ?',
            [username, password]
        );

        if (results.length > 0) {
            res.json({ message: 'Login successful', store_ID: results[0].store_ID });
        } else {
            res.status(401).json({ message: 'Invalid username or password' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Database error', error: error.message });
    }
});

//REGISTER STORE    
app.post('/api/register', async (req, res) => {
    const { username, password, store_name, store_location, store_contact, store_address } = req.body;

    try {
        const [existingStore] = await pool.execute(
            `SELECT * FROM STORE_ACCOUNTS 
             WHERE LOWER(username) = LOWER(?) 
             AND LOWER(store_name) = LOWER(?) 
             AND LOWER(store_address) = LOWER(?)`,
            [username, store_name, store_address]
        );

        if (existingStore.length > 0) {
            return res.status(400).json({ message: 'Store with the same username, store name, and store address already exists!' });
        }

        // 🛠 Insert new account if no duplicate
        await pool.execute(
            `INSERT INTO STORE_ACCOUNTS (username, password, store_name, store_location, store_contact, store_address)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [username, password, store_name, store_location, store_contact, store_address]
        );

        res.status(201).json({ message: 'Account registered successfully!' });
    } catch (error) {
        console.error('Error inserting data:', error);
        res.status(500).json({ message: 'Database error', error: error.message });
    }
});

// 🛠 REGISTER A POLICE ACCOUNT
app.post("/register-police", async (req, res) => {
    const { username, password, stoc_contact, stoc_email, stoc_location } = req.body;

    if (!username || !password || !stoc_contact || !stoc_email || !stoc_location) {
        return res.status(400).json({ error: "All fields are required." });
    }

    try {
        const [existingUser] = await pool.query(
            "SELECT * FROM STOC_ACCOUNTS WHERE username = ? OR stoc_email = ?",
            [username, stoc_email]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({ error: "Username or email already exists." });
        }

        await pool.query(
            "INSERT INTO STOC_ACCOUNTS (username, password, stoc_contact, stoc_email, stoc_location) VALUES (?, ?, ?, ?, ?)",
            [username, password, stoc_contact, stoc_email, stoc_location]
        );

        res.status(201).json({ message: "Police account registered successfully!" });
    } catch (err) {
        console.error("❌ Error registering police account:", err);
        res.status(500).json({ error: "Database error occurred." });
    }
});

// 🛠 GET STOC INCIDENT HISTORY
app.get('/api/detection-history', async (req, res) => {
    const { search, searchLocations, searchThreatLevels, searchType } = req.query;
    
    try {
        let query = 'SELECT * FROM STOC_DETECTION_HISTORY WHERE 1=1'; 
        const params = [];

        // ✅ Search Filter
        if (search) {
            query += ` AND (store_name LIKE ? OR store_location LIKE ? OR store_contact LIKE ? OR 
                             threat_level LIKE ? OR detection_type LIKE ? OR shared_detection_id LIKE ?)`;
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
        }

        // ✅ Location Filter
        if (searchLocations) {
            const locationsArray = searchLocations.split(",");
            query += ` AND store_location IN (${locationsArray.map(() => "?").join(",")})`;
            params.push(...locationsArray);
        }

        // ✅ Threat Level Filter
        if (searchThreatLevels) {
            const threatArray = searchThreatLevels.split(",");
            query += ` AND threat_level IN (${threatArray.map(() => "?").join(",")})`;
            params.push(...threatArray);
        }

        // ✅ Type Filter
        if (searchType) {
            const typeArray = searchType.split(",");
            query += ` AND detection_type IN (${typeArray.map(() => "?").join(",")})`;
            params.push(...typeArray);
        }

        console.log("Executing query:", query, "with params:", params); 

        const [results] = await pool.execute(query, params);
        res.json(results);
    } catch (error) {
        console.error("Database error:", error);
        res.status(500).json({ message: "Error retrieving history" });
    }
});

// ✅ GET REPORT COUNT BY MONTH (Bar Chart)
app.get('/api/reports-by-month', async (req, res) => {
    try {
        const query = `
            SELECT DATE_FORMAT(date, '%M') AS monthName,
                   MONTH(date) AS monthNumber,
                   COUNT(*) AS count
            FROM STOC_DETECTION_HISTORY
            WHERE YEAR(date) = YEAR(CURDATE())
            GROUP BY monthName, monthNumber
            ORDER BY monthNumber;
        `;
        const [rows] = await pool.execute(query);
        res.json(rows);
    } catch (err) {
        console.error("❌ Error fetching reports by month:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// ✅ GET REPORT COUNT BY LOCATION (Pie Chart)
app.get('/api/reports-by-location', async (req, res) => {
    try {
        const query = `
            SELECT store_location AS name, COUNT(*) AS value
            FROM STOC_DETECTION_HISTORY
            WHERE YEAR(date) = YEAR(CURDATE())
            GROUP BY store_location
            ORDER BY value DESC;
        `;
        const [rows] = await pool.execute(query);
        res.json(rows);
    } catch (err) {
        console.error("❌ Error fetching reports by location:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// 🛠 STORE INCIDENT HISTORY
app.get('/api/incident-history/:storeID', async (req, res) => {
    const { storeID } = req.params;
    const { search } = req.query;

    try {
        let query = `SELECT * FROM STORE_DETECTION_HISTORY WHERE store_ID = ? AND threat_level != 'Low'`;  // Exclude 'Low' threat level
        const params = [storeID];

        if (search) {
            query += ' AND (date LIKE ? OR time LIKE ? OR threat_level LIKE ? OR detection_type LIKE ? OR shared_detection_id LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
        }

        console.log('Executing query:', query, 'with params:', params);

        const [rows] = await pool.execute(query, params);
        res.json(rows);
    } catch (error) {
        console.error('Error fetching incident history:', error);
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
});

// 🛠 EDIT STORE INCIDENT RECORD
app.put('/api/edit-incident/:id', async (req, res) => {
    const { id } = req.params;
    const { date, time, threat_level, detection_type } = req.body;

    try {
        console.log(`📝 Edit Request for detection_ID=${id}`);

        // ✅ Check if the record exists in STORE_DETECTION_HISTORY
        const [existingRecord] = await pool.query('SELECT * FROM STORE_DETECTION_HISTORY WHERE detection_ID = ?', [id]);
        if (existingRecord.length === 0) {
            console.log(`❌ No record found with detection_ID=${id}`);
            return res.status(404).json({ message: "Incident not found." });
        }

        console.log("✅ Found Record:", existingRecord[0]);

        // ✅ Update the record
        const updateQuery = `
            UPDATE STORE_DETECTION_HISTORY 
            SET date = ?, time = ?, threat_level = ?, detection_type = ? 
            WHERE detection_ID = ?
        `;
        const [updateResult] = await pool.query(updateQuery, [date, time, threat_level, detection_type, id]);

        if (updateResult.affectedRows === 0) {
            console.log(`⚠️ No changes made to detection_ID=${id}`);
            return res.status(400).json({ message: "No changes made to the record." });
        }

        console.log(`✅ detection_ID=${id} updated successfully.`);

        // ✅ Log changes in STORE_EDIT_HISTORY
        const currentDate = new Date();
        const dateEdited = currentDate.toISOString().split('T')[0]; // YYYY-MM-DD
        const timeEdited = currentDate.toTimeString().split(' ')[0]; // HH:MM:SS

        const insertHistoryQuery = `
            INSERT INTO STORE_EDIT_HISTORY (detection_ID, date, time, threat_level, detection_type, date_edited, time_edited)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        await pool.query(insertHistoryQuery, [id, existingRecord[0].date, existingRecord[0].time, existingRecord[0].threat_level, existingRecord[0].detection_type, dateEdited, timeEdited]);

        res.json({ message: "Incident updated successfully and logged!", affectedRows: updateResult.affectedRows });
    } catch (error) {
        console.error("❌ Error updating incident:", error);
        res.status(500).json({ message: "Internal server error", error: error.message });
    }
});

//EDITED ROWS HISTORY RECORD STORE
app.get('/api/edit-history', async (req, res) => {
    try {
        const query = 'SELECT * FROM STORE_EDIT_HISTORY ORDER BY date_edited DESC, time_edited DESC';
        const [results] = await pool.query(query);
        res.json(results);
    } catch (error) {
        console.error('❌ Error fetching edit history:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

// 🛠 DELETE STORE ACCOUNT
app.delete('/api/delete-store/:id', async (req, res) => {
    const { id } = req.params;
    console.log("Deleting store ID:", id);
    try {
        const [result] = await pool.execute('DELETE FROM STORE_ACCOUNTS WHERE store_ID = ?', [id]);

        if (result.affectedRows > 0) {
            res.json({ message: 'Account deleted successfully' });
        } else {
            res.status(404).json({ message: 'Account not found' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Database error', error: error.message });
    }
});

//DELETE POLICE ACCOUNT
app.delete('/api/delete-police/:id', async (req, res) => {
    const { id } = req.params;
    console.log("Deleting stoc ID:", id);
    try {
        const [result] = await pool.execute('DELETE FROM STOC_ACCOUNTS WHERE stoc_ID = ?', [id]);

        if (result.affectedRows > 0) {
            res.json({ message: 'Account deleted successfully' });
        } else {
            res.status(404).json({ message: 'Account not found' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Database error', error: error.message });
    }
});

// 🛠 GET STORE ACCOUNTS
app.get('/api/store-accounts', async (req, res) => {
    try {
        const [results] = await pool.execute('SELECT * FROM STORE_ACCOUNTS');
        res.json(results);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Error retrieving store accounts' });
    }
});

// 🛠 GET POLICE ACCOUNTS
app.get('/api/police-accounts', async (req, res) => {
    try {
        const [results] = await pool.execute('SELECT * FROM STOC_ACCOUNTS');
        res.json(results);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Error retrieving store accounts' });
    }
});

// 🛠 REPORT COUNT STOC 
app.get('/api/history-count', async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT COUNT(*) AS total_rows FROM STOC_DETECTION_HISTORY');
        res.json({ count: rows[0].total_rows });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Database error', error: error.message });
    }
});

// 🛠 REPORT COUNT STORE
app.get('/api/history-count2/:storeID', async (req, res) => {
    try {
        const storeID = req.params.storeID; 
        console.log("Received storeID:", storeID); 

        if (!storeID) {
            return res.status(400).json({ message: "Missing storeID parameter" });
        }

        const [rows] = await pool.execute(
            'SELECT COUNT(*) AS total_rows FROM STORE_DETECTION_HISTORY WHERE store_ID = ?',
            [storeID]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: "No records found for this store" });
        }

        res.json({ count: rows[0].total_rows });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Database error', error: error.message });
    }
});

// 🛠 REPORT COUNT STORE (MONTH)
app.get('/api/report-count-per-month/:storeID', async (req, res) => {
    try {
        const storeID = req.params.storeID;
        console.log("📡 Received storeID:", storeID);

        if (!storeID) {
            return res.status(400).json({ message: "❌ Missing storeID parameter" });
        }

        const query = `
            SELECT 
                MONTHNAME(date) AS month, 
                COUNT(*) AS count 
            FROM STORE_DETECTION_HISTORY  
            WHERE store_ID = ? 
              AND YEAR(date) = YEAR(CURDATE())  
            GROUP BY MONTH(date) 
            ORDER BY MONTH(date) ASC
        `;

        const [rows] = await pool.execute(query, [storeID]);

        if (rows.length === 0) {
            return res.status(404).json({ message: "❌ No records found for this store" });
        }

        console.log("✅ Report Data Retrieved:", rows);
        res.json(rows);
    } catch (error) {
        console.error("❌ Database error:", error);
        res.status(500).json({ message: "Database error", error: error.message });
    }
});

// 🛠 GET LIVE STREAM URL BY STORE_ID
app.get('/api/live-stream/:storeID', async (req, res) => {
    const { storeID } = req.params;  

    if (!storeID) {
        return res.status(400).json({ message: "Missing store ID" });
    }

    try {
        const [rows] = await pool.execute(
            'SELECT live_url FROM STORE_ACCOUNTS WHERE store_ID = ? LIMIT 1',
            [storeID]
        );

        if (rows.length > 0) {
            res.json({ live_url: rows[0].live_url });
        } else {
            res.status(404).json({ message: "Live stream not found" });
        }
    } catch (error) {
        console.error("Error fetching live stream URL:", error);
        res.status(500).json({ message: "Database error", error: error.message });
    }
});

// 🛠 LOG DELETE STOC INCIDENT RECORD
app.get('/api/delete-history', async (req, res) => {
    try {
        const query = 'SELECT * FROM STOC_EDIT_HISTORY ORDER BY date_deleted DESC, time_deleted DESC';
        const [results] = await pool.query(query);
        res.json(results);
    } catch (error) {
        console.error('Error fetching delete history:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

// 🛠 DELETE STOC INCIDENT RECORD
app.delete('/api/delete-detection/:id', async (req, res) => {
    const detectionId = req.params.id;

    try {
        const query = 'SELECT * FROM STOC_DETECTION_HISTORY WHERE detection_ID = ?';
        const [result] = await pool.query(query, [detectionId]);

        if (result.length === 0) {
            return res.status(404).json({ message: 'Record not found' });
        }

        const { store_ID, date, time } = result[0];
        const currentDate = new Date();
        const dateDeleted = currentDate.toISOString().split('T')[0];  
        const timeDeleted = currentDate.toTimeString().split(' ')[0]; 

        const insertQuery = `
            INSERT INTO STOC_EDIT_HISTORY (date_deleted, time_deleted, detection_ID, date, time, store_ID)
            VALUES (?, ?, ?, ?, ?, ?)`;
        await pool.query(insertQuery, [dateDeleted, timeDeleted, detectionId, date, time, store_ID]);

        const deleteQuery = 'DELETE FROM STOC_DETECTION_HISTORY WHERE detection_ID = ?';
        await pool.query(deleteQuery, [detectionId]);

        res.json({ message: 'Record deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

// 🛠 LOG DELETE STORE INCIDENT RECORD
app.get('/api/delete-history-store', async (req, res) => {
    try {
        const query = 'SELECT * FROM STORE_DELETE_HISTORY ORDER BY date_deleted DESC, time_deleted DESC';
        const [results] = await pool.query(query);
        res.json(results);
    } catch (error) {
        console.error('Error fetching delete history:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

// 🛠 DELETE STORE INCIDENT RECORD
app.delete('/api/delete-detection-store/:id', async (req, res) => {
    const detectionId = req.params.id;

    try {
        const query = 'SELECT * FROM STORE_DETECTION_HISTORY WHERE detection_ID = ?';
        const [result] = await pool.query(query, [detectionId]);

        if (result.length === 0) {
            return res.status(404).json({ message: 'Record not found' });
        }

        const { store_ID, date, time } = result[0];
        const currentDate = new Date();
        const dateDeleted = currentDate.toISOString().split('T')[0];  
        const timeDeleted = currentDate.toTimeString().split(' ')[0]; 

        const insertQuery = `
            INSERT INTO STORE_DELETE_HISTORY (date_deleted, time_deleted, detection_ID, date, time, store_ID)
            VALUES (?, ?, ?, ?, ?, ?)`;
        await pool.query(insertQuery, [dateDeleted, timeDeleted, detectionId, date, time, store_ID]);

        const deleteQuery = 'DELETE FROM STORE_DETECTION_HISTORY WHERE detection_ID = ?';
        await pool.query(deleteQuery, [detectionId]);

        res.json({ message: 'Record deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
});

//AUTODELETE FUNCTION
const deleteOldRecords = async () => {
    try {
        const query = `
            DELETE FROM STOC_EDIT_HISTORY 
            WHERE date_deleted < DATE_SUB(NOW(), INTERVAL 3 DAY)
        `;
        const [result] = await pool.query(query);
        console.log(`Auto-deleted ${result.affectedRows} records from STOC_EDIT_HISTORY`);
    } catch (error) {
        console.error("Error deleting old records:", error);
    }
};
    setInterval(deleteOldRecords, 24 * 60 * 60 * 1000);
    deleteOldRecords();

//AUTODELETE FUNCTION
const deleteOldRecordsStore = async () => {
    try {
        const query = `
            DELETE FROM STORE_DELETE_HISTORY 
            WHERE date_deleted < DATE_SUB(NOW(), INTERVAL 3 DAY)
        `;
        const [result] = await pool.query(query);
        console.log(`Auto-deleted ${result.affectedRows} records from STORE_DELETE_HISTORY`);
    } catch (error) {
        console.error("Error deleting old records:", error);
    }
};
    setInterval(deleteOldRecords, 24 * 60 * 60 * 1000);
    deleteOldRecords();

// CLEAR TABLE STORE DELETE HISTORY
app.delete('/api/clear-delete-history', async (req, res) => {
    try {
        const deleteQuery = 'DELETE FROM STORE_DELETE_HISTORY';
        await pool.query(deleteQuery);

        res.json({ message: 'All deleted incident history records have been permanently removed.' });
    } catch (error) {
        console.error('Error clearing delete history:', error);
        res.status(500).json({ message: 'Failed to clear delete history.', error: error.message });
    }
});

// CLEAR TABLE STORE DELETE HISTORY
app.delete('/api/clear-delete-history2', async (req, res) => {
    try {
        const deleteQuery = 'DELETE FROM STOC_EDIT_HISTORY';
        await pool.query(deleteQuery);

        res.json({ message: 'All deleted incident history records have been permanently removed.' });
    } catch (error) {
        console.error('Error clearing delete history:', error);
        res.status(500).json({ message: 'Failed to clear delete history.', error: error.message });
    }
});

// ✅ API to Fetch Incident Report (STOC) with Filters
app.get('/api/incident-history', async (req, res) => {
    try {
        const { searchLocations, searchThreatLevels, searchType } = req.query;

        let query = "SELECT * FROM STOC_DETECTION_HISTORY WHERE 1=1";
        let queryParams = [];

        if (searchLocations) {
            const locationsArray = searchLocations.split(",");
            query += ` AND store_location IN (${locationsArray.map(() => "?").join(",")})`;
            queryParams.push(...locationsArray);
        }

        if (searchThreatLevels) {
            const threatArray = searchThreatLevels.split(",");
            query += ` AND threat_level IN (${threatArray.map(() => "?").join(",")})`;
            queryParams.push(...threatArray);
        }

        if (searchType) {
            const typeArray = searchType.split(",");
            query += ` AND detection_type IN (${typeArray.map(() => "?").join(",")})`;
            queryParams.push(...typeArray);
        }

        const [rows] = await pool.query(query, queryParams);

        res.json(rows);
    } catch (error) {
        console.error("Error fetching incident history:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});


// ✅ API to Fetch Incident Report (STORE) with Filters
app.get('/api/incident-history', async (req, res) => {
    try {
        const { searchLocations, searchThreatLevels, searchType } = req.query;

        let query = "SELECT * FROM STORE_DETECTION_HISTORY WHERE 1=1";
        let queryParams = [];

        if (searchThreatLevels) {
            const threatArray = searchThreatLevels.split(",");
            query += ` AND threat_level IN (${threatArray.map(() => "?").join(",")})`;
            queryParams.push(...threatArray);
        }

        if (searchType) {
            const typeArray = searchType.split(",");
            query += ` AND detection_type IN (${typeArray.map(() => "?").join(",")})`;
            queryParams.push(...typeArray);
        }

        const [rows] = await pool.query(query, queryParams);

        res.json(rows);
    } catch (error) {
        console.error("Error fetching incident history:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

//WATCHING NEW INCOMING DETECTION (STOC)
app.get('/latest-reports', async (req, res) => {
    const query = `
        SELECT * FROM STOC_DETECTION_HISTORY
        ORDER BY date DESC, time DESC
        LIMIT 2
    `;

    try {
        const [results] = await pool.query(query);
        if (results.length === 0) {
            return res.status(404).json({ message: "No reports found" });
        }
        console.log("✅ Latest Reports Retrieved:", results);
        res.json(results);
    } catch (err) {
        console.error("❌ Database Query Error:", err.message);
        res.status(500).json({ error: `Database query failed: ${err.message}` });
    }
});

// WATCHING NEW INCOMING DETECTION (STORE)
app.get('/latest-reports2', async (req, res) => {
    const { storeID } = req.query;  // Get the storeID from the query string

    // If storeID is not provided, return an error
    if (!storeID) {
        return res.status(400).json({ error: "storeID is required" });
    }

    // Update the query to filter by storeID
    const query = `
        SELECT * FROM STORE_DETECTION_HISTORY
        WHERE store_id = ?  -- Assuming 'store_id' is the column in the database
        ORDER BY date DESC, time DESC
        LIMIT 2
    `;

    try {
        const [results] = await pool.query(query, [storeID]);  // Use the storeID in the query
        if (results.length === 0) {
            return res.status(404).json({ message: "No reports found" });
        }
        console.log("✅ Latest Reports Retrieved:", results);
        res.json(results);
    } catch (err) {
        console.error("❌ Database Query Error:", err.message);
        res.status(500).json({ error: `Database query failed: ${err.message}` });
    }
});

// WATCHING NEW INCOMING DETECTION (STORE) — Now with filtering for "Cover"
app.get('/cover-reports/:storeID', async (req, res) => {
    const { storeID } = req.params;

    const query = `
        SELECT * FROM STORE_DETECTION_HISTORY
        WHERE store_ID = ?
        AND detection_type LIKE '%Cover%'  -- Filter for detection type containing 'Cover'
        ORDER BY date DESC, time DESC
        LIMIT 1  -- Adjust number of reports as needed
    `;

    try {
        const [results] = await pool.query(query, [storeID]);
        if (results.length === 0) {
            return res.status(404).json({ message: "No 'Cover' reports found for this store." });
        }
        console.log(`✅ Cover report(s) retrieved for store ${storeID}:`, results);
        res.json(results);
    } catch (err) {
        console.error("❌ Database Query Error:", err.message);
        res.status(500).json({ error: `Database query failed: ${err.message}` });
    }
});

// VERIFY ADMIN PASSWORD STOC
app.post('/api/verify-admin-password', async (req, res) => {
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ valid: false, message: 'Password required' });
    }

    try {
        const [rows] = await pool.execute('SELECT * FROM STOC_ACCOUNTS WHERE password = ?', [password]);

        if (rows.length > 0) {
            res.json({ valid: true });
        } else {
            res.status(401).json({ valid: false, message: 'Incorrect password' });
        }
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ valid: false, message: 'Server error', error: error.message });
    }
});

// VERIFY ADMIN PASSWORD STORE
app.post('/api/verify-admin-password-store', async (req, res) => {
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ valid: false, message: 'Password required' });
    }

    try {
        const [rows] = await pool.execute('SELECT * FROM STORE_ACCOUNTS WHERE password = ?', [password]);

        if (rows.length > 0) {
            res.json({ valid: true });
        } else {
            res.status(401).json({ valid: false, message: 'Incorrect password' });
        }
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ valid: false, message: 'Server error', error: error.message });
    }
});

//STORE PROFILE
app.get('/api/store-profile/:storeID', async (req, res) => {
    const { storeID } = req.params;

    try {
        const result = await pool.query(
            `SELECT store_ID, username, password, store_name, store_location, store_contact, store_address 
             FROM STORE_ACCOUNTS 
             WHERE store_ID = $1`,
            [storeID]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Store not found' });
        }

        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error fetching store:', err.message);
        res.status(500).json({ message: 'Server error' });
    }
});

// Socket.IO: Handle Client Connection
io.on("connection", (socket) => {
    console.log("🟢 User Connected to WebSocket");

    socket.on("disconnect", () => {
        console.log("🔴 User Disconnected from WebSocket");
    });
});

// 🛠 START SERVER
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
