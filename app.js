const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const dotenv = require("dotenv");
const path = require("path");
const cors = require("cors"); // For cross-origin support if needed
const helmet = require("helmet"); // For added security
const morgan = require("morgan"); // For logging
const rateLimit = require("express-rate-limit"); // For rate-limiting
const { resolveNaptr } = require("dns/promises");
const multer = require("multer");
const fs = require("fs");
const crypto = require("crypto");
const mysql = require("mysql2/promise");
const { check, validationResult } = require("express-validator"); // For input validation

require("dotenv").config();

const app = express();
const PORT = process.env.PORT;

// Ensure required environment variables are set
if (!process.env.DB_HOST || !process.env.DB_USER || !process.env.DB_PASSWORD || !process.env.DB_NAME || !process.env.SESSION_SECRET) {
  throw new Error("Missing required environment variables. Please check your .env file.");
}

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(morgan("combined")); // Logs HTTP requests in a combined format
app.use(helmet()); // Adds security headers

const SequelizeStore = require("connect-session-sequelize")(session.Store);
const { Sequelize } = require("sequelize");

// Initialize Sequelize
const sequelize = new Sequelize(process.env.DATABASE_URL);

// Create a Session Store
const sessionStore = new SequelizeStore({
  db: sequelize,
});

// Sync the database
sessionStore.sync();

// Session Middleware
app.use(
  session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || "your-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

// Enable CORS for frontend
const whitelist = ["https://growsphere.ip-ddns.com", "http://localhost:3000"];
const corsOptions = {
  origin: function (origin, callback) {
    if (whitelist.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};
app.use(cors(corsOptions));

app.set("view engine", "ejs");
app.set('views', __dirname + '/views');
// Database connection
// Create a connection pool
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: true, // Ensure a secure SSL connection
    ca: fs.readFileSync(path.resolve(__dirname, './ca.pem')), // Path to CA certificate
  },
  waitForConnections: true,
  connectionLimit: 20,
  queueLimit: 0
});

(async () => {
  try {
    // Get a connection from the pool
    const connection = await db.getConnection();
    console.log("Database connected successfully");

    // Release the connection back to the pool
    connection.release();
  } catch (err) {
    console.error("Error connecting to the database:", err);
    if (err.stack) {
      console.error("Error stack:", err.stack);
    }
  }
})();

process.on('SIGINT', async () => {
  try {
    await db.end();
    console.log("Database pool closed on application exit");
    process.exit(0);
  } catch (err) {
    console.error("Error closing the database pool:", err);
    process.exit(1);
  }
});

// Routes
app.get("/check-session", (req, res) => {
  res.json({ active: !!req.session.userId });
});

app.post('/validate-coupon', async (req, res) => {
  const { coupon } = req.body;

  // Validate input
  if (!coupon || typeof coupon !== 'string') {
    return res.status(400).json({ success: false, message: "Coupon code is required and must be a valid string." });
  }

  try {
    // Query to check coupon validity
    const query = "SELECT * FROM couponcode WHERE coupon_code = ? AND is_used = 0";
    const [results] = await db.query(query, [coupon.trim()]);

    if (results.length > 0) {
      return res.status(200).json({ success: true, message: "Coupon code is valid." });
    } else {
      return res.status(200).json({ success: false, message: "Invalid or already used coupon code." });
    }
  } catch (error) {
    console.error("Error validating coupon code:", error);
    return res.status(500).json({ success: false, message: "An error occurred during validation." });
  }
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "signup.html")); // Serve static HTML
});

app.post("/signup", [
  check("first_name").notEmpty().withMessage("First name is required."),
  check("last_name").notEmpty().withMessage("Last name is required."),
  check("username").isAlphanumeric().withMessage("Username must be alphanumeric.").notEmpty(),
  check("user_email").isEmail().withMessage("Valid email is required."),
  check("user_phone").isMobilePhone().withMessage("Valid phone number is required."),
  check("country").notEmpty().withMessage("Country is required."),
  check("user_password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters."),
  check("confirm_password").custom((value, { req }) => value === req.body.user_password).withMessage("Passwords do not match."),
  check("coupon").notEmpty().withMessage("Coupon code is required."),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const {
    first_name,
    last_name,
    username,
    user_email,
    user_phone,
    country,
    user_password,
    coupon,
    active_package,
    terms,
  } = req.body;

  let connection;

  try {
    connection = await db.promise().getConnection();
    await connection.beginTransaction();

    // Validate coupon
    const [couponResult] = await connection.query(
      "SELECT * FROM coupons WHERE coupon_code = ? AND is_used = 0 FOR UPDATE",
      [coupon]
    );
    if (couponResult.length === 0) {
      throw new Error("Invalid or already used coupon code.");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(user_password, 10);

    // Insert new user
    const [userResult] = await connection.query(
      `
      INSERT INTO users (first_name, last_name, username, email, phone_number, country, password_hash, coupon_code, active_package, terms_accepted)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
      [
        first_name,
        last_name,
        username,
        user_email,
        user_phone,
        country,
        hashedPassword,
        coupon,
        active_package,
        terms,
      ]
    );

    const newUserId = userResult.insertId;

    // Mark coupon as used
    await connection.query("UPDATE couponcode SET is_used = 1, used_at = NOW() WHERE coupon_code = ?", [coupon]);

    // Handle referral logic
    const referralUsername = req.query.ref || null;
    if (referralUsername) {
      const [referrer] = await connection.query("SELECT id FROM users WHERE username = ?", [referralUsername]);

      if (referrer.length > 0) {
        const referrerId = referrer[0].id;
        await connection.query(
          `
          UPDATE users 
          SET total_referrals = total_referrals + 1, todays_referrals = todays_referrals + 1, sale_commission = sale_commission + 7
          WHERE id = ?
        `,
          [referrerId]
        );
      }
    }

    await connection.commit();
    res.status(201).json({ success: true, message: "Signup successful!" });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Error during signup:", error);
    res.status(500).json({ success: false, message: error.message || "An error occurred during signup." });
  } finally {
    if (connection) connection.release();
  }
});

// Middleware for authenticated routes
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next(); // Proceed if authenticated
  }
  res.status(401).json({ error: "Unauthorized. Please log in." });
}

// Serve dashboard page
app.get("/dashboard", isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html")); // Use static HTML for the dashboard
});

// Check if the user session is active
app.get("/check-session", (req, res) => {
  res.json({ active: !!req.session.userId });
});

// Handle user login
app.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required." });
  }

  try {
    const [results] = await db.promise().query("SELECT * FROM users WHERE username = ?", [username]);

    if (results.length === 0) {
      return res.status(400).json({ message: "Invalid username or password." });
    }

    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid username or password." });
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    res.status(200).json({ message: "Login successful.", redirect: "/dashboard" });
  } catch (error) {
    console.error("Error during signin:", error);
    res.status(500).json({ message: "An error occurred during signin." });
  }
});

// Generate referral link
app.post("/generate-referral-link", isAuthenticated, async (req, res) => {
  try {
    const [results] = await db.promise().query("SELECT username FROM users WHERE id = ?", [req.session.userId]);

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    const username = results[0].username;
    const baseUrl = process.env.BASE_URL || "https://growsphere.ip-ddns.com";
    const referralLink = `${baseUrl}/signup?ref=${encodeURIComponent(username)}`;

    res.json({ referralLink });
  } catch (err) {
    console.error("Error generating referral link:", err);
    res.status(500).json({ error: "Unable to generate referral link. Please try again later." });
  }
});

// Fetch user data
app.get("/user-data", isAuthenticated, async (req, res) => {
  try {
    const [results] = await db.promise().query("SELECT username FROM users WHERE id = ?", [req.session.userId]);

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({ username: results[0].username });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "An error occurred while fetching user data." });
  }
});

app.get("/all-time-earnings", async (req, res) => {
  if (!req.session?.userId) {
    return res.status(401).json({ error: "Unauthorized. Please log in." });
  }

  const userId = req.session.userId;

  const query = `
    SELECT 
      (sale_commission + gsp_cash) AS total_earnings 
    FROM dashboard
    WHERE user_id = ?
  `;

  try {
    // Use promise-based query for async handling
    const [results] = await db.promise().query(query, [userId]);

    if (results.length === 0) {
      return res.status(404).json({ error: "No earnings data found." });
    }

    const totalEarnings = results[0]?.total_earnings || 0;
    res.json({ totalEarnings });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "An error occurred while fetching earnings." });
  }
});

app.post("/claim-daily-task", async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userId = req.session.userId;
  const { rewardAmount } = req.body;

  const updateQuery = `
    UPDATE dashboard
    SET gsp_cash = gsp_cash + ?
    WHERE user_id = ?;
  `;

  const fetchQuery = `
    SELECT gsp_cash
    FROM dashboard
    WHERE user_id = ?;
  `;

  try {
    // Use promise-based query for async handling
    await db.promise().query(updateQuery, [rewardAmount, userId]);

    // Fetch the updated gsp_cash value
    const [results] = await db.promise().query(fetchQuery, [userId]);

    const gspCash = results[0]?.gsp_cash || 0;
    res.json({ gspCash });
  } catch (err) {
    console.error("Error processing daily task:", err);
    return res.status(500).json({ error: "Failed to process daily task" });
  }
});

const dashboardRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests, please try again later.',
});

app.use('/dashboard', dashboardRateLimiter);

app.get("/dashboard", async (req, res) => {
  const userId = req.session.userId;

  if (!userId) {
    return res.redirect("/signin");
  }

  const query = `
    SELECT active_package, sale_commission, todays_referrals, total_referrals, gsp_cash
    FROM dashboard
    WHERE user_id = ?
  `;

  try {
    const [results] = await db.promise().query(query, [userId]);

    if (results.length > 0) {
      const {
        active_package,
        sale_commission,
        todays_referrals,
        total_referrals,
        gsp_cash,
      } = results[0];

      res.json({
        activePackage: active_package || "--",
        gspCash: gsp_cash || 0,
        saleCommission: sale_commission || 0,
        todaysReferrals: todays_referrals || 0,
        totalReferrals: total_referrals || 0,
      });
    } else {
      res.status(404).send("User not found.");
    }
  } catch (err) {
    console.error("Error fetching dashboard data:", err);
    res.status(500).send("Server error.");
  }
});

const cron = require("node-cron");

cron.schedule("0 0 * * *", async () => {
  try {
    await db.promise().query("UPDATE dashboard SET todays_referrals = 0");
    console.log("Daily referrals reset successfully at midnight.");
  } catch (err) {
    console.error("Error resetting daily referrals:", err);
  }
});


app.get("/dashboard-data", async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userId = req.session.userId;

  // Define queries
  const referralsQuery = `
    SELECT 
      WEEK(referral_date, 1) AS week_number,
      COUNT(*) AS referral_count
    FROM total_referrals
    WHERE user_id = ?
    GROUP BY week_number
    ORDER BY week_number ASC;
  `;

  const dailyEarningsQuery = `
    SELECT 
      WEEK(transaction_date, 1) AS week_number,
      SUM(amount) AS daily_earning
    FROM sale_commission
    WHERE user_id = ?
    GROUP BY week_number
    ORDER BY week_number ASC;
  `;

  const allTimeEarningsQuery = `
    SELECT 
      WEEK(earning_date, 1) AS week_number,
      SUM(amount) AS all_time_earning
    FROM all_time_earnings
    WHERE user_id = ?
    GROUP BY week_number
    ORDER BY week_number ASC;
  `;

  try {
    // Execute all queries concurrently
    const [referrals, dailyEarnings, allTimeEarnings] = await Promise.all([
      db.promise().query(referralsQuery, [userId]),
      db.promise().query(dailyEarningsQuery, [userId]),
      db.promise().query(allTimeEarningsQuery, [userId])
    ]);

    // Combine data into response
    const data = {
      referralCount: referrals[0].map((row) => row.referral_count),
      dailyEarning: dailyEarnings[0].map((row) => row.daily_earning),
      allTimeEarning: allTimeEarnings[0].map((row) => row.all_time_earning),
      weeks: referrals[0].map((row) => `Week ${row.week_number}`)
    };

    res.json(data);

  } catch (err) {
    console.error('Error fetching dashboard data for user ${req.session.userId}:', err);
    res.status(500).json({ error: "Error fetching dashboard data." });
  }
});

const profileRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests, please try again later.',
});

app.use('/profile', profileRateLimiter);

app.get("/profile", async (req, res) => {
  const userId = req.session.userId;
if (!Number.isInteger(userId)) {
  return res.status(400).json({ error: "Invalid user ID" });
}

  if (!req.session.userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const query = `
    SELECT first_name, last_name, username, email, phone_number, country, active_package, coupon_code
    FROM users
    WHERE id = ?
  `;

  try {
    const [results] = await db.promise().query(query, [req.session.userId]);

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(results[0]); // Send user data as JSON
  } catch (err) {
    console.error(`Error fetching profile data for user ${req.session.userId}:`, err);
    res.status(500).json({ error: "Error fetching profile data" });
  }
});


// emailHandler.js
const sendWithdrawalEmail = async (user, type, withdrawalAmount) => {
  const emailjs = await import("emailjs"); // Dynamic import for emailjs

  const emailServer = emailjs.server.connect({
    host: "smtp.gmail.com",
    port: 587,
    user: process.env.EMAIL_USER,
    password: process.env.EMAIL_PASSWORD,
    ssl: false,
    tls: { ciphers: "SSLv3" },
  });

  const message = {
    text: ` 
      Withdrawal Request:
      - Name: ${user.first_name} ${user.last_name}
      - Username: ${user.username}
      - Email: ${user.email}
      - Phone: ${user.phone_number}
      - Country: ${user.country}
      - Active Package: ${user.active_package}
      - Coupon Code: ${user.coupon_code}
      - Withdrawal Amount: $${withdrawalAmount}
    `,
    from: process.env.EMAIL_USER,
    to: process.env.EMAIL_RECEIVER,
    subject: `${type} Withdrawal Request`,
  };

  return new Promise((resolve, reject) => {
    emailServer.send(message, (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
};

module.exports = sendWithdrawalEmail;

// Rate limit for withdrawals to prevent abuse
const withdrawalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per window
  message: "Too many withdrawal attempts, please try again later.",
});

// Route to get user balances
app.get("/get-balances", isAuthenticated, async (req, res) => {
  const query = `
    SELECT sale_commission, gsp_cash
    FROM users
    WHERE id = ?`;

  try {
    const [results] = await db.query(query, [req.session.userId]);

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    const { sale_commission, gsp_cash } = results[0];
    res.json({ sale_commission, gsp_cash });
  } catch (err) {
    console.error(`Error fetching balances for user ${req.session.userId}:`, err);
    res.status(500).json({ error: "Error fetching balances." });
  }
});

// Route to handle withdrawal requests
app.post("/withdraw", isAuthenticated, withdrawalRateLimiter, async (req, res) => {
  const { type } = req.body;

  if (typeof type !== 'string' || !['sale_commission', 'gsp_cash'].includes(type)) {
    return res.status(400).send("Invalid withdrawal type.");
  }

  const query = `
    SELECT first_name, last_name, username, email, phone_number, country, active_package, coupon_code, sale_commission, gsp_cash
    FROM users
    WHERE id = ?`;

  try {
    const [results] = await db.query(query, [req.session.userId]);

    if (results.length === 0) {
      return res.status(404).send("User not found.");
    }

    const user = results[0];
    let withdrawalAmount;

    if (type === "sale_commission") {
      if (isNaN(user.sale_commission) || user.sale_commission < 20) {
        return res.status(400).send("Sale commission must be greater than $20 for withdrawal.");
      }
      withdrawalAmount = user.sale_commission;

      // Reset sale commission in a transaction
      const connection = await db.promise().getConnection();
      try {
        await connection.beginTransaction();
        await connection.query("UPDATE users SET sale_commission = 0 WHERE id = ?", [req.session.userId]);
        await connection.commit();
      } catch (err) {
        await connection.rollback();
        throw err;
      } finally {
        connection.release();
      }
    } else if (type === "gsp_cash") {
      if (isNaN(user.gsp_cash) || user.gsp_cash < 50) {
        return res.status(400).send("GSP Cash must be greater than $50 for withdrawal.");
      }
      withdrawalAmount = user.gsp_cash;

      // Reset GSP Cash in a transaction
      const connection = await db.promise().getConnection();
      try {
        await connection.beginTransaction();
        await connection.query("UPDATE users SET gsp_cash = 0 WHERE id = ?", [req.session.userId]);
        await connection.commit();
      } catch (err) {
        await connection.rollback();
        throw err;
      } finally {
        connection.release();
      }
    }

    // Send withdrawal email
    await sendWithdrawalEmail(user, type, withdrawalAmount);

    res.json({ message: "Withdrawal successful! Payment will be made in less than 24 hours." });
  } catch (err) {
    console.error(`Error processing withdrawal for user ${req.session.userId}:`, err);
    res.status(500).send("Error processing withdrawal.");
  }
});

// Example of route to fetch profile data (unchanged)
app.get("/profile", isAuthenticated, async (req, res) => {
  const query = `
    SELECT first_name, last_name, username, email, phone_number, country, active_package, coupon_code
    FROM users
    WHERE id = ?`;

  try {
    const [results] = await db.promise().query(query, [req.session.userId]);

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(results[0]);
  } catch (err) {
    console.error("Error fetching profile data:", err);
    res.status(500).json({ error: "Error fetching profile data" });
  }
});

// Function to log activities
async function logActivity(userId, activityType, description, relatedUsername = null) {
  const query = `
    INSERT INTO activities (user_id, activity_type, activity_description, related_username) 
    VALUES (?, ?, ?, ?)
  `;
  
  try {
    // Await the query and wait for it to complete
    await db.query(query, [userId, activityType, description, relatedUsername]);
    console.log("Activity logged successfully.");
  } catch (err) {
    console.error("Error logging activity:", err);
  }
}

// Route to fetch activities for a user
app.get("/activity", async (req, res) => {
  const userId = req.session?.userId; // Use optional chaining to avoid errors if session is undefined

  if (!userId) {
    return res.status(401).json({ error: "Unauthorized: User not logged in" });
  }

  const query = `
    SELECT activity_type, activity_description, related_username, created_at 
    FROM activities 
    WHERE user_id = ? 
    ORDER BY created_at DESC
  `;

  try {
    const [results] = await db.query(query, [userId]);
    res.json(results);
  } catch (err) {
    console.error("Error fetching activities:", err);
    res.status(500).json({ error: "Error fetching activities." });
  }
});


const archiver = require("archiver");

const secureDir = "./secure_coupons"; // Directory for exported coupon files

// Ensure the secure directory exists
if (!fs.existsSync(secureDir)) {
    fs.mkdirSync(secureDir, { recursive: true });
    console.log(`Secure directory created: ${secureDir}`);
}

// Generate a single coupon
function generateCouponCode() {
    const randomPart = crypto.randomBytes(4).toString("hex").toUpperCase();
    return `GS/EF/24-${randomPart}`;
}

// Generate multiple coupons and save to the database
async function generateCoupons(count) {
    const coupons = [];
    try {
        for (let i = 0; i < count; i++) {
            const coupon = generateCouponCode();
            await db.query(
                "INSERT INTO couponcode (coupon_code, is_used, generated_at) VALUES (?, 0, NOW())",
                [coupon]
            );
            coupons.push(coupon);
        }
        console.log(`${count} coupons generated successfully.`);
    } catch (err) {
        console.error("Error generating coupons:", err.message);
    }
    return coupons;
}

// Export coupons to a file
function exportCouponsToFile(coupons) {
    if (!coupons || coupons.length === 0) {
        console.error("No coupons to export.");
        return null;
    }

    const filePath = path.join(secureDir, `coupons_${Date.now()}.txt`);
    try {
        fs.writeFileSync(filePath, coupons.join("\n"), "utf8");
        console.log(`Coupons exported to file: ${filePath}`);
        return filePath;
    } catch (err) {
        console.error("Error exporting coupons to file:", err.message);
        return null;
    }
}

// Encrypt the coupon file by compressing it into a ZIP
function encryptFile(filePath) {
    if (!fs.existsSync(filePath)) {
        console.error("File to encrypt does not exist:", filePath);
        return null;
    }

    const encryptedFilePath = `${filePath}.zip`; // Change to ZIP extension
    const output = fs.createWriteStream(encryptedFilePath);
    const archive = archiver("zip", {
        zlib: { level: 9 }, // Maximum compression
    });

    return new Promise((resolve, reject) => {
        output.on("close", () => {
            console.log(`Encrypted file created: ${encryptedFilePath}`);
            fs.unlinkSync(filePath); // Remove plaintext file
            resolve(encryptedFilePath);
        });

        archive.on("error", (err) => {
            console.error("Error encrypting file:", err.message);
            reject(err);
        });

        archive.pipe(output);

        // Add the file to the archive
        archive.file(filePath, { name: path.basename(filePath) });

        // Finalize the archive
        archive.finalize();
    });
}

// Check if all coupons are used and regenerate if necessary
async function checkAndRegenerateCoupons() {
    try {
        const [results] = await db.query(
            "SELECT COUNT(*) AS unused_count FROM couponcode WHERE is_used = 0"
        );
        const unusedCount = results[0].unused_count;

        if (unusedCount === 0) {
            console.log("All coupons are used. Generating new coupons...");
            const newCoupons = await generateCoupons(200); // Generate 200 new coupons
            const filePath = exportCouponsToFile(newCoupons);
            if (filePath) {
                await encryptFile(filePath);
                console.log("File encryption completed successfully.");
            }
        } else {
            console.log(`Unused coupons remaining: ${unusedCount}`);
        }
    } catch (err) {
        console.error("Error checking and regenerating coupons:", err.message);
    }
}

checkAndRegenerateCoupons();

app.get("/logout", (req, res) => {
  // Destroy the session
  req.session.destroy((err) => {
    if (err) {
      console.error("Error during session destruction:", err);
      return res.status(500).send("Error during logout.");
    }
    // Redirect to index.html
    res.redirect("/index.html");
  });
});

const router = express.Router();
const uploadDir = "./uploads/marketplace";

// Ensure the secure directory exists
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure Multer for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({
  storage,
  limits: {
    fileSize: 20 * 1024 * 1024, // 20 MB file size limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/gif"];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Invalid file type. Only JPEG, PNG, and GIF are allowed."));
    }
    cb(null, true);
  },
});

// Function to wrap db.query in a promise
function queryAsync(query, params) {
  return new Promise((resolve, reject) => {
    db.query(query, params, (err, results) => {
      if (err) {
        reject(err);
      } else {
        resolve(results);
      }
    });
  });
}

// Upload an item to the marketplace
router.post("/upload-item", upload.single("item_image"), async (req, res) => {
  const { item_name, item_description, item_price, uploader_contact } = req.body;
  const uploader_id = req.session?.user?.id;

  if (!uploader_id) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const item_image = req.file ? `/uploads/marketplace/${req.file.filename}` : null;

  const query = `
    INSERT INTO marketplace (uploader_id, item_name, item_description, item_price, item_image, uploader_contact)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  try {
    await queryAsync(query, [uploader_id, item_name, item_description, item_price, item_image, uploader_contact]);
    res.status(200).json({ message: "Item uploaded successfully" });
  } catch (err) {
    console.error("Error uploading item:", err);
    res.status(500).json({ message: "Error uploading item" });
  }
}, (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: err.message });
  } else if (err) {
    return res.status(500).json({ message: "An unexpected error occurred." });
  }
});

// Fetch all marketplace items
router.get("/get-items", async (req, res) => {
  const query = `
    SELECT m.*, u.username AS uploader_name
    FROM marketplace m
    JOIN users u ON m.uploader_id = u.id
    ORDER BY m.upload_date DESC
  `;

  try {
    const results = await queryAsync(query);
    res.status(200).json(results);
  } catch (err) {
    console.error("Error fetching items:", err);
    res.status(500).json({ message: "Error fetching items" });
  }
});

// Post a comment
router.post("/add-comment", async (req, res) => {
  const { item_id, comment } = req.body;
  const commenter_id = req.session.user.id;

  const query = `
    INSERT INTO marketplace_comments (item_id, commenter_id, comment)
    VALUES (?, ?, ?)
  `;

  try {
    await queryAsync(query, [item_id, commenter_id, comment]);
    res.status(200).json({ message: "Comment posted successfully" });
  } catch (err) {
    console.error("Error posting comment:", err);
    res.status(500).json({ message: "Error posting comment" });
  }
});

// Fetch comments for an item
router.get("/get-comments/:itemId", async (req, res) => {
  const { itemId } = req.params;

  const query = `
    SELECT mc.*, u.username AS commenter_name
    FROM marketplace_comments mc
    JOIN users u ON mc.commenter_id = u.id
    WHERE mc.item_id = ?
    ORDER BY mc.comment_date DESC
  `;

  try {
    const results = await queryAsync(query, [itemId]);
    res.status(200).json(results);
  } catch (err) {
    console.error("Error fetching comments:", err);
    res.status(500).json({ message: "Error fetching comments" });
  }
});

module.exports = router;

// Custom error handling
app.use((req, res) => {
  res.status(404).render("404");
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render("500");
});

app.listen(PORT, () => {
  if (process.env.NODE_ENV !== "production") {
    console.log(`Server running on http://localhost:${PORT}`);
  } else {
    console.log(`Server running on port ${PORT}`);
  }
});
