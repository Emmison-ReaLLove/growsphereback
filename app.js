const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const dotenv = require("dotenv");
const path = require("path");
const cors = require("cors"); // For cross-origin support if needed
const helmet = require("helmet"); // For added security
const morgan = require("morgan"); // For logging
const { resolveNaptr } = require("dns/promises");
const multer = require("multer");
const fs = require("fs");
const crypto = require("crypto");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(morgan("combined")); // Logs HTTP requests in a combined format
app.use(helmet()); // Adds security headers

const connectRedis = require('connect-redis');
const { createClient } = require('redis');

// Create Redis client
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379',
  legacyMode: true, // Enable legacy mode if necessary for compatibility
});

redisClient.connect().catch(console.error);

// Initialize RedisStore
const RedisStore = connectRedis(session);

// Session middleware setup
app.use(
  session({
    store: new RedisStore({ client: redisClient }), // Use the store with the client
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production', // Secure cookies in production
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

// Simple route
app.get('/', (req, res) => {
  res.send('Hello, world!');
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});


// Enable CORS for frontend
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "https://growsphere.ip-ddns.com", // Update for your frontend domain
    credentials: true,
  })
);

app.set("view engine", "ejs");

// Database connection
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: true,
  },
});

(async () => {
  try {
    const connection = await db.getConnection();

    // Load your SQL file
    const sqlScript = fs.readFileSync(path.resolve(__dirname, 'dashboard_schema.sql'), 'utf8');

    // Execute the script
    await connection.query(sqlScript);
    console.log('SQL script executed successfully');
    
    connection.release();
  } catch (err) {
    console.error('Error executing SQL script:', err.message);
  } finally {
    db.end();
  }
})();


// Routes
app.get("/signin", (req, res) => {
  res.redirect("/signin");
});

app.get("/signup", (req, res) => {
  res.render("signup");
});
app.post('/validate-coupon', async (req, res) => {
  const { coupon } = req.body;

  if (!coupon) {
      return res.status(400).json({ success: false, message: "Coupon code is required." });
  }

  try {
      // Check if coupon exists and is not used
      const [results] = await db.query(
          "SELECT * FROM coupons WHERE coupon_code = ? AND is_used = 0",
          [coupon]
      );

      if (results.length > 0) {
          res.json({ success: true, message: "Coupon code is valid." });
      } else {
          res.json({ success: false, message: "Invalid or already used coupon code." });
      }
  } catch (error) {
      console.error("Error validating coupon code:", error);
      res.status(500).json({ success: false, message: "An error occurred during validation." });
  }
});

app.post("/signup", async (req, res) => {
  const {
    first_name,
    last_name,
    username,
    user_email,
    user_phone,
    country,
    user_password,
    confirm_password,
    coupon,
    active_package,
    terms,
  } = req.body;

  // Validate input
  if (!terms) return res.status(400).send("You must agree to the terms and conditions.");
  if (user_password !== confirm_password) return res.status(400).send("Passwords do not match.");

  // Hash the password
  const hashedPassword = await bcrypt.hash(user_password, 10);

  // Check if there's a referral
  const referralUsername = req.query.ref || null;
  let referrerId = null;

  if (referralUsername) {
    try {
      const [referrer] = await db.promise().query(
        "SELECT id FROM users WHERE username = ?",
        [referralUsername]
      );
      if (referrer.length > 0) referrerId = referrer[0].id;
    } catch (err) {
      console.error("Error finding referrer:", err);
      return res.status(500).send("Error processing referral.");
    }
  }

  // Validate the coupon code
  try {
    const [couponResult] = await db.promise().query(
      "SELECT * FROM coupons WHERE coupon_code = ? AND is_used = 0",
      [coupon]
    );

    if (couponResult.length === 0) {
      return res.status(400).send("Invalid or already used coupon code.");
    }
  } catch (err) {
    console.error("Error validating coupon code:", err);
    return res.status(500).send("Error validating coupon code.");
  }

  // SQL query to insert the new user
  const query = `
    INSERT INTO users 
    (first_name, last_name, username, email, phone_number, country, password_hash, coupon_code, active_package, terms_accepted) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
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
      terms ? true : false,
    ],
    async (err, result) => {
      if (err) {
        console.error("Error during registration:", err);
        return res.status(500).send("Error: Username or email already exists.");
      }

      const newUserId = result.insertId;

      // Mark the coupon as used
      try {
        await db.promise().query(
          "UPDATE coupons SET is_used = 1, used_at = NOW() WHERE coupon_code = ?",
          [coupon]
        );
      } catch (err) {
        console.error("Error marking coupon as used:", err);
        return res.status(500).send("Error processing coupon.");
      }

      // If there's a referrer, update their stats
      if (referrerId) {
        try {
          await db.promise().query(
            `
            INSERT INTO total_referrals (user_id, referral_date)
            VALUES (?, CURRENT_DATE)
            ON DUPLICATE KEY UPDATE referral_date = referral_date;

            UPDATE dashboard
            SET 
              total_referrals = total_referrals + 1,
              todays_referrals = todays_referrals + 1,
              sale_commission = sale_commission + 7
            WHERE user_id = ?;
            `,
            [referrerId, referrerId]
          );
          console.log(`Referral stats updated for user ID ${referrerId}`);
        } catch (err) {
          console.error("Error updating referral stats:", err);
        }
      }

      res.redirect("/signin");
    }
  );
});

app.get("/signin", (req, res) => {
  res.render("signin");
});
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next(); // Proceed if the user is authenticated
  }
  res.redirect("/index.html"); // Redirect to login or homepage if not authenticated
}
app.get("/dashboard", isAuthenticated, (req, res) => {
  res.render("dashboard"); // Render the dashboard for authenticated users
});
app.get("/check-session", (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({ active: true });
  }
  res.json({ active: false });
});

app.post("/signin", (req, res) => {
  const { username, password } = req.body;

  const query = "SELECT * FROM users WHERE username = ?";
  db.query(query, [username], async (err, results) => {
    if (err || results.length === 0 || !(await bcrypt.compare(password, results[0].password_hash))) {
      return res.status(400).send("Invalid username or password.");
    }
    req.session.userId = results[0].id;
    req.session.username = results[0].username;
    res.redirect("/dashboard");
  });
});

app.get("/dashboard", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/signin");
  }
  res.render("dashboard", { username: req.session.username });
});

app.post("/generate-referral-link", (req, res) => {
  const userId = req.session.userId;

  // Fetch the username of the logged-in user
  db.query("SELECT username FROM users WHERE id = ?", [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).json({ error: "Unable to generate referral link" });
    }

    const username = results[0].username;
    const referralLink = `https://growsphere.ip-ddns.com/signup?ref=${username}`;

    res.json({ referralLink });
  });
});


app.get("/user-data", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Unauthorized" });

  const userId = req.session.userId;
  const query = "SELECT username FROM users WHERE id = ?";

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Database error" });
    }

    if (results.length > 0) {
      res.json({ username: results[0].username });
    } else {
      res.status(404).json({ error: "User not found" });
    }
  });
});

app.get("/all-time-earnings", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Unauthorized" });

  const userId = req.session.userId;

  const query = `
    SELECT 
      (sale_commission + gsp_cash) AS total_earnings 
    FROM dashboard
    WHERE user_id = ?
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    const totalEarnings = results[0]?.total_earnings || 0;
    res.json({ totalEarnings });
  });
});
app.post("/claim-daily-task", (req, res) => {
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

  db.query(updateQuery, [rewardAmount, userId], (err) => {
    if (err) {
      console.error("Error updating GSP Cash:", err);
      return res.status(500).json({ error: "Failed to update GSP Cash" });
    }

    db.query(fetchQuery, [userId], (err, results) => {
      if (err) {
        console.error("Error fetching GSP Cash:", err);
        return res.status(500).json({ error: "Failed to fetch GSP Cash" });
      }

      const gspCash = results[0]?.gsp_cash || 0;
      res.json({ gspCash });
    });
  });
});

app.get("/dashboard", async (req, res) => {
  const userId = req.session.userId; // Assuming session holds user ID

  if (!userId) {
    return res.redirect("/signin");
  }

  const query = `
    SELECT active_package, sale_commission, todays_referrals, total_referrals
    FROM users
    WHERE id = ?
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching dashboard data:", err);
      return res.status(500).send("Server error.");
    }

    if (results.length > 0) {
      const {
        active_package,
        sale_commission,
        todays_referrals,
        total_referrals,
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
  });
});
const cron = require("node-cron");

// Reset "today's referrals" for all users at midnight
cron.schedule("0 0 * * *", () => {
  db.query("UPDATE dashboard SET todays_referrals = 0", (err) => {
    if (err) console.error("Error resetting daily referrals:", err);
    else console.log("Daily referrals reset successfully");
  });
});


app.get("/dashboard-data", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Unauthorized" });

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

  // Execute queries sequentially
  db.query(referralsQuery, [userId], (err, referrals) => {
    if (err) return res.status(500).json({ error: "Database error during referrals query." });

    db.query(dailyEarningsQuery, [userId], (err, dailyEarnings) => {
      if (err) return res.status(500).json({ error: "Database error during daily earnings query." });

      db.query(allTimeEarningsQuery, [userId], (err, allTimeEarnings) => {
        if (err) return res.status(500).json({ error: "Database error during all-time earnings query." });

        // Combine data into response
        const data = {
          referralCount: referrals.map((row) => row.referral_count),
          dailyEarning: dailyEarnings.map((row) => row.daily_earning),
          allTimeEarning: allTimeEarnings.map((row) => row.all_time_earning),
          weeks: referrals.map((row) => `Week ${row.week_number}`),
        };

        res.json(data);
      });
    });
  });
});
app.get("/profile", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/signin");
  }

  // Serve the static HTML file
  res.sendFile(path.join(__dirname, "public", "profile.html"));
});

// API to fetch user data
app.get("/api/profile", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const query = `
    SELECT first_name, last_name, username, email, phone_number, country, active_package, coupon_code
    FROM users
    WHERE id = ?
  `;

  db.query(query, [req.session.userId], (err, results) => {
    if (err) {
      console.error("Error fetching profile data:", err);
      return res.status(500).json({ error: "An error occurred while fetching profile data." });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json(results[0]);
  });
});

app.get("/profile", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).redirect("/signin");
  }

  const query = `
    SELECT first_name, last_name, username, email, phone_number, country, active_package, coupon_code
    FROM users
    WHERE id = ?
  `;

  db.query(query, [req.session.userId], (err, results) => {
    if (err) {
      console.error("Error fetching profile data:", err);
      return res.status(500).send("Error fetching profile data.");
    }

    if (results.length === 0) {
      return res.status(404).send("User not found.");
    }

    res.render("profile", { user: results[0] }); // Pass data to the profile template
  });
});
const Email = require("emailjs"); // Import emailjs
const emailServer = emailjs.server.connect({
  host: "smtp.gmail.com", // Gmail SMTP server
  port: 587, // Standard SMTP port
  user: "growspherewithdrawal@gmail.com", // Your Gmail address
  password: "oywaglztgfybrddd", // Your Gmail App Password   Go to Google Account Security. Enable 2-Step Verification if not already enabled. Under "Signing in to Google," click App Passwords. Generate an app password and use it in the password field.
  ssl: false, // Use STARTTLS (recommended for Gmail on port 587)
  tls: { ciphers: "SSLv3" }, // Ensure secure TLS connection
});


app.post("/withdraw", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).send("Unauthorized");
  }

  const { type } = req.body; // Type can be 'sale_commission' or 'gsp_cash'
  const query = `
    SELECT first_name, last_name, username, email, phone_number, country, active_package, coupon_code, sale_commission, gsp_cash 
    FROM users 
    WHERE id = ?
  `;

  db.query(query, [req.session.userId], (err, results) => {
    if (err) {
      console.error("Error fetching user data:", err);
      return res.status(500).send("Error processing withdrawal.");
    }

    if (results.length === 0) {
      return res.status(404).send("User not found.");
    }

    const user = results[0];
    if (type === "sale_commission") {
      if (user.sale_commission < 20) {
        return res.status(400).send("Sale commission must be greater than $20 for withdrawal.");
      }

      // Send withdrawal email
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
          - Withdrawal Amount: $${user.sale_commission}
        `,
        from: "growspherewithdrawal@gmail.com",
        to: "growspherewithdrawal@gmail.com",
        subject: "Sale Commission Withdrawal Request",
      };

      emailServer.send(message, (emailErr) => {
        if (emailErr) {
          console.error("Error sending email:", emailErr);
          return res.status(500).send("Error sending withdrawal email.");
        }

        // Reset sale commission
        db.query(
          "UPDATE users SET sale_commission = 0 WHERE id = ?",
          [req.session.userId],
          (updateErr) => {
            if (updateErr) {
              console.error("Error resetting sale commission:", updateErr);
              return res.status(500).send("Error updating sale commission.");
            }

            res.send("Withdrawal successful! Payment will be made in less than 24 hours.");
          }
        );
      });
    } else if (type === "gsp_cash") {
      if (user.gsp_cash < 50) {
        return res.status(400).send("GSP Cash must be greater than $50 for withdrawal.");
      }

      // Send withdrawal email
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
          - Withdrawal Amount: $${user.gsp_cash}
        `,
        from: "growspherewithdrawal@gmail.com",
        to: "growspherewithdrawal@gmail.com",
        subject: "GSP Cash Withdrawal Request",
      };

      emailServer.send(message, (emailErr) => {
        if (emailErr) {
          console.error("Error sending email:", emailErr);
          return res.status(500).send("Error sending withdrawal email.");
        }

        // Reset GSP Cash
        db.query(
          "UPDATE users SET gsp_cash = 0 WHERE id = ?",
          [req.session.userId],
          (updateErr) => {
            if (updateErr) {
              console.error("Error resetting GSP Cash:", updateErr);
              return res.status(500).send("Error updating GSP Cash.");
            }

            res.send("Withdrawal successful! Payment will be made in less than 24 hours.");
          }
        );
      });
    } else {
      res.status(400).send("Invalid withdrawal type.");
    }
  });
});
app.get("/get-balances", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).send("Unauthorized");
  }

  const query = `
    SELECT sale_commission, gsp_cash
    FROM users
    WHERE id = ?
  `;

  db.query(query, [req.session.userId], (err, results) => {
    if (err) {
      console.error("Error fetching balances:", err);
      return res.status(500).send("Error fetching balances.");
    }

    res.json(results[0]);
  });
});

function logActivity(userId, activityType, description, relatedUsername = null) {
  const query = `
    INSERT INTO activities (user_id, activity_type, activity_description, related_username) 
    VALUES (?, ?, ?, ?)
  `;
  db.query(query, [userId, activityType, description, relatedUsername], (err) => {
    if (err) console.error("Error logging activity:", err);
  });
}
// After inserting the referral into the database
logActivity(userId, "Referral", "Referred a new user.", referredUsername);
// After updating the GSP Cash in the database
logActivity(userId, "Task Completion", `Completed a task and earned $${rewardAmount.toFixed(2)}.`);
// After processing the withdrawal and resetting the amount in the database
logActivity(userId, "Withdrawal", `Withdrew $${amount} from ${type}.`);

app.get("/activity", (req, res) => {
  const userId = req.session.userId; // Replace with session logic
  const query = `
    SELECT activity_type, activity_description, related_username, created_at 
    FROM activities 
    WHERE user_id = ? 
    ORDER BY created_at DESC
  `;
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching activities:", err);
      return res.status(500).send("Error fetching activities.");
    }
    res.json(results);
  });
});

const secureDir = "./secure_coupons"; // Directory for exported coupon files
// Ensure secure directory exists
if (!fs.existsSync(secureDir)) {
    fs.mkdirSync(secureDir, { recursive: true });
    console.log(`Secure directory created: ${secureDir}`);
}

// Generate a single coupon
function generateCouponCode() {
    const randomPart = crypto.randomBytes(4).toString("hex").toUpperCase();
    return `GS/EF/24-${randomPart}`;
}

// Generate multiple coupons and save to database
async function generateCoupons(count) {
    const coupons = [];
    for (let i = 0; i < count; i++) {
        const coupon = generateCouponCode();
        await db.query(
            "INSERT INTO coupons (coupon_code, is_used, generated_at) VALUES (?, 0, NOW())",
            [coupon]
        );
        coupons.push(coupon);
    }
    console.log(`${count} coupons generated successfully.`);
    return coupons;
}

// Export coupons to a file
async function exportCouponsToFile(coupons) {
    const filePath = path.join(secureDir, `coupons_${Date.now()}.txt`);
    fs.writeFileSync(filePath, coupons.join("\n"), "utf8");
    console.log(`Coupons exported to file: ${filePath}`);
    return filePath;
}

// Encrypt the coupon file with a password
function encryptFile(filePath, password) {
    const { execSync } = require("child_process");
    const encryptedFilePath = `${filePath}.encrypted`;
    execSync(
        `zip --password ${password} ${encryptedFilePath} ${filePath}`,
        { stdio: "inherit" }
    );
    fs.unlinkSync(filePath); // Remove plaintext file
    console.log(`Encrypted file created: ${encryptedFilePath}`);
}

// Check if all coupons are used and regenerate if necessary
async function checkAndRegenerateCoupons() {
    const [results] = await db.query(
        "SELECT COUNT(*) AS unused_count FROM coupons WHERE is_used = 0"
    );
    const unusedCount = results[0].unused_count;

    if (unusedCount === 0) {
        console.log("All coupons are used. Generating new coupons...");
        const newCoupons = await generateCoupons(200); // Generate 10 new coupons
        const filePath = await exportCouponsToFile(newCoupons);
        encryptFile(filePath, "@Awesomedude2465"); // Encrypt file with a password
    } else {
        console.log(`Unused coupons remaining: ${unusedCount}`);
    }
}

// Execute the script
checkAndRegenerateCoupons()
    .catch((err) => console.error("Error:", err))
    .finally(() => db.end());


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

// Configure Multer for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    },
});
const upload = multer({ storage });

// Upload an item to the marketplace
router.post("/upload-item", upload.single("item_image"), (req, res) => {
    const { item_name, item_description, item_price, uploader_contact } = req.body;
    const uploader_id = req.session.user.id; // Assuming session stores user info
    const item_image = req.file ? `/uploads/marketplace/${req.file.filename}` : null;

    const query = `
        INSERT INTO marketplace (uploader_id, item_name, item_description, item_price, item_image, uploader_contact)
        VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.query(query, [uploader_id, item_name, item_description, item_price, item_image, uploader_contact], (err) => {
        if (err) {
            console.error("Error uploading item:", err);
            return res.status(500).json({ message: "Error uploading item" });
        }
        res.status(200).json({ message: "Item uploaded successfully" });
    });
});

// Fetch all marketplace items
router.get("/get-items", (req, res) => {
    const query = `
        SELECT m.*, u.username AS uploader_name
        FROM marketplace m
        JOIN users u ON m.uploader_id = u.id
        ORDER BY m.upload_date DESC
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching items:", err);
            return res.status(500).json({ message: "Error fetching items" });
        }
        res.status(200).json(results);
    });
});

// Post a comment
router.post("/add-comment", (req, res) => {
    const { item_id, comment } = req.body;
    const commenter_id = req.session.user.id;

    const query = `
        INSERT INTO marketplace_comments (item_id, commenter_id, comment)
        VALUES (?, ?, ?)
    `;

    db.query(query, [item_id, commenter_id, comment], (err) => {
        if (err) {
            console.error("Error posting comment:", err);
            return res.status(500).json({ message: "Error posting comment" });
        }
        res.status(200).json({ message: "Comment posted successfully" });
    });
});

// Fetch comments for an item
router.get("/get-comments/:itemId", (req, res) => {
    const { itemId } = req.params;

    const query = `
        SELECT mc.*, u.username AS commenter_name
        FROM marketplace_comments mc
        JOIN users u ON mc.commenter_id = u.id
        WHERE mc.item_id = ?
        ORDER BY mc.comment_date DESC
    `;

    db.query(query, [itemId], (err, results) => {
        if (err) {
            console.error("Error fetching comments:", err);
            return res.status(500).json({ message: "Error fetching comments" });
        }
        res.status(200).json(results);
    });
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
