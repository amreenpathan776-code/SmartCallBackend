require("dotenv").config();

process.on("uncaughtException", err => {
  console.error("UNCAUGHT EXCEPTION:", err);
});

process.on("unhandledRejection", err => {
  console.error("UNHANDLED REJECTION:", err);
});

const express = require("express");

// ✅ Backend Logger (same style)
const logInfo = (msg, data) =>
  console.log(`📡 ${msg}`, data || "");

const logSuccess = (msg, data) =>
  console.log(`✅ ${msg}`, data || "");

const logError = (msg, data) =>
  console.error(`❌ ${msg}`, data || "");

const logWarn = (msg, data) =>
  console.warn(`⚠️ ${msg}`, data || "");

const sql = require("mssql");
const cors = require("cors");

const app = express();
const PORT = 5001;
const fs = require("fs");
const https = require("https");

const httpsOptions = {
  key: fs.readFileSync(process.env.SSL_KEY),
  cert: fs.readFileSync(process.env.SSL_CERT),
  ca: fs.readFileSync(process.env.SSL_CA)
};
const axios = require("axios");
const getAddressFromCoords = async (lat, lng) => {
  try {
    const res = await axios.get(
      "https://maps.googleapis.com/maps/api/geocode/json",
      {
        params: {
          latlng: `${lat},${lng}`,
          key: process.env.GOOGLE_API_KEY, // same key you already use
        },
      }
    );


    if (res.data.results.length > 0) {
      return res.data.results[0].formatted_address;
    }

    return `${lat}, ${lng}`;
  } catch (err) {
    console.log("Reverse geocode error:", err.message);
    return `${lat}, ${lng}`;
  }
};

const writeDailyLog = require("./logger");

function formatMessage(args) {
  return args.map(a =>
    typeof a === "object" ? JSON.stringify(a) : a
  ).join(" ");
}

const originalLog = console.log;
const originalWarn = console.warn;
const originalError = console.error;

console.log = (...args) => {
  writeDailyLog("backend", formatMessage(args));
  originalLog(...args);
};

console.warn = (...args) => {
  writeDailyLog("backend", formatMessage(args));
  originalWarn(...args);
};

console.error = (...args) => {
  writeDailyLog("backend", formatMessage(args));
  originalError(...args);
};


async function getRoadDistanceKm(startLat, startLng, stopLat, stopLng) {
  try {
    const response = await axios.get(
      "https://maps.googleapis.com/maps/api/directions/json",
      {
        params: {
          origin: `${startLat},${startLng}`,
          destination: `${stopLat},${stopLng}`,
key: process.env.GOOGLE_API_KEY,      
},
      }
    );

    if (
      response.data.routes &&
      response.data.routes.length > 0 &&
      response.data.routes[0].legs.length > 0
    ) {
      const distanceMeters =
        response.data.routes[0].legs[0].distance.value;

      const distanceKm = distanceMeters / 1000;

      return distanceKm;
    } else {
      throw new Error("No route found");
    }
  } catch (error) {
    console.error("Google Distance Error:", error.message);
    throw error;
  }
}
// ======================
// MIDDLEWARE
// ======================
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// ======================
// MSSQL CONFIG
// ======================
const dbConfig = {
  user: "AdministratorDev",
  password: "Clab@@230830",
  server: "10.0.0.4",
  database: "smart_call",
options: {
  encrypt: false,
  trustServerCertificate: true,
  requestTimeout: 60000
}
};

// ======================
// MSSQL CONNECTION POOL
// ======================
const poolPromise = new sql.ConnectionPool(dbConfig)
  .connect()
  .then((pool) => {
    console.log("✅ Connected to MSSQL Database");
    return pool;
  })
  .catch((err) => {
    console.error("❌ MSSQL Connection Failed:", err);
    process.exit(1);
  });

// ======================
// HEALTH CHECK
// ======================
app.get("/health", (req, res) => {
  res.send("Smart Recovery backend is running");
});

// =======================================================
// ✅ REGISTER
// =======================================================
app.post("/register", async (req, res) => {
console.log("📥 [REGISTER_API] request", {
  userId: req.body?.userId,
  deviceId: req.body?.deviceId
});
  const { userId, password, mpin, securityQ, securityA, deviceId } = req.body;

  try {
	  
    if (!userId || !password || !mpin || !securityQ || !securityA || !deviceId) {
		console.log("⚠️ [REGISTER_API] Missing fields", { userId });
      return res.status(400).json({ message: "All fields are mandatory" });
    }

    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,20}$/;

    if (!passwordRegex.test(password)) {
		console.log("⚠️ [REGISTER_API] Password format invalid", { userId });
      return res.status(400).json({
        message:
          "Password must be 6–20 characters with uppercase, lowercase, number and special character",
      });
    }

    if (!/^\d{4}$/.test(String(mpin))) {
		console.log("⚠️ [REGISTER_API] MPIN invalid", { userId });
      return res.status(400).json({
        message: "MPIN must be exactly 4 numeric digits",
      });
    }

    const pool = await poolPromise;
console.log("🔍 [REGISTER_API] Checking authorized user", { userId });
    // ✅ check authorized user in UsersInfo
    const userCheck = await pool
      .request()
      .input("UserId", sql.VarChar(50), String(userId).trim())
      .query(`
        SELECT UserId
        FROM UsersInfo
        WHERE UserId = @UserId
      `);
console.log("📦 [REGISTER_API] authorized user fetched", {
  userId,
  count: userCheck.recordset?.length || 0,
  data: userCheck.recordset
});
if (userCheck.recordset.length === 0) {
  console.log("❌ [REGISTER_API] User not authorized", { userId });
  return res.status(403).json({
    message: "User not authorized. Contact admin.",
  });
}
    // ✅ already registered?
    const authCheck = await pool
      .request()
      .input("UserId", sql.VarChar(50), String(userId).trim())
      .query(`
        SELECT UserId
        FROM UserAuth
        WHERE UserId = @UserId
      `);
console.log("📦 [REGISTER_API] existing auth check", {
  userId,
  count: authCheck.recordset?.length || 0,
  data: authCheck.recordset
});
    if (authCheck.recordset.length > 0) {
      return res.status(409).json({
        message: "User already registered. Please login.",
      });
    }
console.log("💾 [REGISTER_API] Creating auth record", { userId });
    await pool
      .request()
      .input("UserId", sql.VarChar(50), String(userId).trim())
      .input("AppPassword", sql.VarChar(255), String(password))
      .input("AppMPIN", sql.VarChar(10), String(mpin).trim())
      .input("SecurityQuestion", sql.VarChar(50), String(securityQ))
      .input("SecurityAnswer", sql.VarChar(255), String(securityA))
      .input("DeviceId", sql.VarChar(200), String(deviceId).trim())
      .query(`
        INSERT INTO UserAuth (
          UserId,
          AppPassword,
          AppMPIN,
          SecurityQuestion,
          SecurityAnswer,
          DeviceId
        )
        VALUES (
          @UserId,
          @AppPassword,
          @AppMPIN,
          @SecurityQuestion,
          @SecurityAnswer,
          @DeviceId
        )
      `);
console.log("📦 [REGISTER_API] auth record inserted", {
  userId,
  deviceId
});

console.log("✅ [REGISTER_API] Registration success", {
  userId
});
console.log("📤 [REGISTER_API] response sent", {
  userId
});
return res.status(200).json({ message: "Registration successful" });
  } catch (err) {
    console.error("❌ [REGISTER_API] Error:", {
  userId,
  message: err.message,
  stack: err.stack,
});
    return res.status(500).json({ message: "Internal server error" });
  }
});

// =======================================================
// ✅ LOGIN (UserId + MPIN + DEVICE)
// =======================================================
app.post("/login", async (req, res) => {
console.log("📥 [LOGIN_API] Request received", {
  deviceId: req.body?.deviceId
});

  const { mpin, deviceId } = req.body;

  try {
    if (!mpin || !deviceId) {
      console.log("⚠️ [LOGIN_API] Missing MPIN or deviceId");
      return res.status(400).json({ message: "MPIN and Device ID are required" });
    }

    const cleanMPIN = String(mpin).trim();
    const cleanDeviceId = String(deviceId).trim();

    if (!/^\d{4}$/.test(cleanMPIN)) {
      console.log("⚠️ [LOGIN_API] Invalid MPIN format");
      return res.status(400).json({ message: "MPIN must be exactly 4 digits" });
    }

    const pool = await poolPromise;

    // 🔍 Find user by MPIN
    const mpinUser = await pool.request()
      .input("AppMPIN", sql.VarChar(10), cleanMPIN)
      .query(`
        SELECT TOP 1 UserId, DeviceId
        FROM UserAuth
        WHERE AppMPIN = @AppMPIN
      `);

    if (mpinUser.recordset.length === 0) {
      console.log("❌ [LOGIN_API] Invalid MPIN");
      return res.status(401).json({ message: "Invalid MPIN" });
    }

    const dbUser = mpinUser.recordset[0];
	console.log("📦 [LOGIN_API] MPIN user fetched", {
  userId: dbUser.UserId,
  deviceId: dbUser.DeviceId
});

    // ⚠️ Device mismatch → rebind
    if (String(dbUser.DeviceId).trim() !== cleanDeviceId) {
      console.log("⚠️ [LOGIN_API] Device mismatch - rebinding");

      await pool.request()
        .input("UserId", sql.VarChar(50), dbUser.UserId)
        .input("DeviceId", sql.VarChar(200), cleanDeviceId)
        .query(`
          UPDATE UserAuth
          SET DeviceId = @DeviceId
          WHERE UserId = @UserId
        `);
    }

    console.log("👤 [LOGIN_API] Fetching user profile");

    // 👤 Fetch profile
    const result = await pool.request()

      .input("UserId", sql.VarChar(50), dbUser.UserId)
      .query(`
        SELECT TOP 1
          UA.UserId,
          UI.UserName,
          UI.Role,
          UI.BranchCode,
          UI.BranchName,
          UI.ClusterName
        FROM UserAuth UA
        INNER JOIN UsersInfo UI ON UI.UserId = UA.UserId
        WHERE UA.UserId = @UserId
      `);
console.log("📦 [LOGIN_API] user profile fetched", {
  userId: dbUser.UserId,
  user: result.recordset[0]
});
    console.log("🕒 [LOGIN_API] Updating last login time");

    // 🕒 update last login
    await pool.request()
      .input("UserId", sql.VarChar(50), dbUser.UserId)
      .query(`
        UPDATE UserAuth
        SET LastLoginAt = GETDATE()
        WHERE UserId = @UserId
      `);
console.log("✅ [LOGIN_API] Login success", {
  userId: result.recordset[0]?.UserId,
  userName: result.recordset[0]?.UserName
});

console.log("📤 [LOGIN_API] response sent", {
  user: result.recordset[0]
});

    return res.status(200).json({
      message: "Login successful",
      user: result.recordset[0],
    });

  } catch (err) {
    console.error("❌ [LOGIN_API] Error:", {
      message: err.message,
      stack: err.stack
    });

    return res.status(500).json({ message: "Internal server error" });
  }
});
//============================================================================================
//                                DPD LIST (DATABASE CONNECTED)
//============================================================================================
app.post("/api/dpd-list", async (req, res) => {

  const { dpdQueue, userId, userName } = req.body;

  console.log("📥 /api/dpd-list request", {
    userId,
    userName,
    dpdQueue
  });

console.log("⚠️ Validation check", {
  userId,
  userName,
  dpdQueue
});

  if (!dpdQueue || !userId) {
    console.log("❌ Missing dpdQueue or userId");
    return res.status(400).json({
      message: "dpdQueue and userId are required",
    });
  }

  let dpdList = [];

if (dpdQueue === "ALL") {
  dpdList = []; // means no filter
} else {
  dpdList = dpdQueue.split(",").map((d) => d.trim());
}
  console.log("📊 Parsed DPD list", dpdList);

  try {

    const pool = await poolPromise;
    const request = pool.request();

    request.input("userId", sql.VarChar(50), String(userId));

    dpdList.forEach((dpd, index) => {
      request.input(`dpd${index}`, sql.VarChar(10), String(dpd));
    });

    const placeholders = dpdList
      .map((_, index) => `@dpd${index}`)
      .join(",");

    console.log("📊 Executing DPD query");
    const query = `
      SELECT TOP 10000
        R.firstname,
        R.loanAccountNumber,
        R.mobileNumber,
        R.OVERDUEAMT AS overdueAmount,
        R.dpdQueue,

        -- ⭐ ATTEMPT COUNT
        ISNULL(ATT.AttemptCount,0) AS AttemptCount,

        ISNULL(CRS.PendingFlag, 0) AS PendingFlag,
        ISNULL(CRS.InProcessFlag, 0) AS InProcessFlag,
        ISNULL(CRS.CompleteFlag, 0) AS CompleteFlag,

        CRS.UpdatedAt AS CompletedAt,

        -- ⭐ IMPORTANT (DATE CHECK)
        CRS.ScheduleCallTimestamp,
        CRS.ScheduleVisitTimestamp,

        ISNULL(CRS.ScheduleCallPendingFlag, 0) AS ScheduleCallPendingFlag,
        ISNULL(CRS.ScheduleVisitPendingFlag, 0) AS ScheduleVisitPendingFlag,

        CASE
          WHEN ISNULL(CRS.CompleteFlag,0) = 1 THEN 'COMPLETED'

          WHEN ISNULL(CRS.InProcessFlag,0) = 1
            OR ISNULL(CRS.ScheduleCallPendingFlag,0) = 1
            OR ISNULL(CRS.ScheduleVisitPendingFlag,0) = 1
          THEN 'IN PROCESS'

          ELSE 'PENDING'
        END AS AccountStatus

      FROM Recovery_Raw_Data R

      INNER JOIN Account_Assignments A
        ON A.LoanAccountNumber = R.loanAccountNumber

      LEFT JOIN CallRecovery_Status CRS
        ON CRS.LoanAccountNumber = R.loanAccountNumber
       AND CRS.UserId = @userId

      -- ⭐ COUNT CALL ATTEMPTS
      OUTER APPLY (
          SELECT COUNT(*) AS AttemptCount
          FROM Activity_Logs
          WHERE SourceType = 'NPA'
            AND SourceId = R.loanAccountNumber
            AND ActionCode IN (
                'CALL_BUSY',
                'CALL_NOT_REACHABLE',
                'INVALID_NUMBER'
            )
      ) ATT

      WHERE
        A.AssignedToUserId = @userId
        AND A.AssignmentStatus = 'Assigned'
       ${dpdList.length > 0 ? `AND RIGHT('00' + R.dpdQueue, 2) IN (${placeholders})` : ""}

      ORDER BY TRY_CAST(R.currentOutstandingBalance AS DECIMAL(18,2)) DESC
    `;
 const result = await request.query(query);
console.log("📦 DPD fetched data", {
  userId,
  userName,
  records: result.recordset
});
console.log("✅ DPD list success", {
  userId,
  userName,
  count: result.recordset.length
});
console.log("📤 /api/dpd-list response sent", result.recordset.length);
    return res.json({ records: result.recordset });

  } catch (error) {
console.log("❌ /api/dpd-list error", error);
    console.error("❌ DPD LIST ERROR:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

//============================================================================================
//                                ACCOUNT DETAILS
//============================================================================================
app.post("/api/account-details", async (req, res) => {
  const { loanAccountNumber } = req.body;

  try {
    const pool = await poolPromise;

    const result = await pool.request()
      .input("loanAccountNumber", sql.VarChar(50), loanAccountNumber)
      .query(`
        SELECT
          R.firstname,
          R.fathersName,
          R.village,
          R.gp,
          R.pincode,
          R.mobileNumber,
          R.loanAccountNumber,
          R.product,
          R.dpdQueue,
          R.currentOutstandingBalance,
          R.principleDue,
          R.interestDue,
          R.interestRate,
          CAST(R.lastInterestAppliedDate AS VARCHAR(20)) AS lastInterestAppliedDate,
          R.EMIAMOUNT,
          R.OVERDUEAMT,

          A.AlternateNumber,

          CASE 
            WHEN M.Address IS NOT NULL THEN M.Address
            ELSE CONCAT(R.village, ', ', R.gp, ', ', R.pincode)
          END AS FullAddress,

          CASE 
            WHEN M.Address IS NOT NULL THEN 'MANUAL'
            ELSE 'DB'
          END AS AddressSource

        FROM dbo.Recovery_Raw_Data R

        LEFT JOIN dbo.Recovery_Alternate_Number A
          ON R.loanAccountNumber = A.LoanAccountNumber

        LEFT JOIN dbo.Customer_Manual_Address M
          ON R.loanAccountNumber = M.LoanAccountNumber

        WHERE R.loanAccountNumber = @loanAccountNumber
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: "Account not found" });
    }

    res.json({ account: result.recordset[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// =======================================================
// SAVE ALTERNATE NUMBER (WITH HISTORY)
// =======================================================
app.post("/api/account/save-alternate", async (req, res) => {

console.log("📥 [SAVE_ALTERNATE_API] request", {
  userId: req.body?.userId,
  userName: req.body?.addedBy,
  loanAccountNumber: req.body?.loanAccountNumber,
  alternateNumber: req.body?.alternateNumber,
  payload: req.body
});

  const { loanAccountNumber, alternateNumber, addedBy } = req.body;

console.log("⚠️ [SAVE_ALTERNATE_API] validation", {
  loanAccountNumber,
  alternateNumber,
  addedBy
});

  if (!loanAccountNumber || !alternateNumber) {
console.log("❌ Missing required fields");
    return res.status(400).json({
      message: "Loan account and alternate number required"
    });
  }

  if (!/^\d{10}$/.test(String(alternateNumber))) {
console.log("❌ Invalid alternate number format", alternateNumber);
    return res.status(400).json({
      message: "Alternate number must be 10 digits"
    });
  }

  try {
const { userId } = req.body;

console.log("📊 [SAVE_ALTERNATE_API] processing", {
  userId,
  userName: addedBy,
  loanAccountNumber,
  alternateNumber
});
    const pool = await poolPromise;

console.log("📊 [SAVE_ALTERNATE_API] executing insert", {
  loanAccountNumber,
  alternateNumber
});

    await pool.request()
      .input("LoanAccountNumber", sql.VarChar(50), loanAccountNumber)
      .input("AlternateNumber", sql.VarChar(15), alternateNumber)
      .input("AddedBy", sql.VarChar(100), addedBy || "UNKNOWN")
      .query(`

        -- INSERT INTO HISTORY
        INSERT INTO dbo.Recovery_Alternate_Number_History
        (LoanAccountNumber, AlternateNumber, ActionType, ActionBy, ActionAt)
        VALUES
        (@LoanAccountNumber, @AlternateNumber, 'INSERT', @AddedBy, GETDATE());

        -- INSERT INTO MAIN TABLE
        INSERT INTO dbo.Recovery_Alternate_Number
        (LoanAccountNumber, AlternateNumber, AddedBy, AddedAt)
        VALUES
        (@LoanAccountNumber, @AlternateNumber, @AddedBy, GETDATE());

      `);
console.log("📦 [SAVE_ALTERNATE_API] inserted", {
  userId,
  userName: addedBy,
  loanAccountNumber,
  alternateNumber
});
console.log("✅ [SAVE_ALTERNATE_API] success", {
  loanAccountNumber,
  alternateNumber
});

console.log("📤 [SAVE_ALTERNATE_API] response sent", {
  loanAccountNumber,
  alternateNumber
});

    res.json({ success: true });

  } catch (err) {

console.log("❌ [SAVE_ALTERNATE_API] error", {
  message: err.message,
  stack: err.stack,
  loanAccountNumber,
  alternateNumber,
  addedBy
});

    res.status(500).json({ message: "Server error" });
  }
});


//================================== DELETE ALTERNATE NUMBER ==================================
app.post("/api/account/delete-alternate", async (req, res) => {

console.log("📥 [DELETE_ALTERNATE_API] request", {
  userId: req.body?.userId,
  userName: req.body?.deletedBy,
  loanAccountNumber: req.body?.loanAccountNumber,
  alternateNumber: req.body?.alternateNumber,
  payload: req.body
});

  const { loanAccountNumber, alternateNumber, deletedBy } = req.body;

console.log("⚠️ [DELETE_ALTERNATE_API] validation", {
  loanAccountNumber,
  alternateNumber,
  deletedBy
});

  try {

const { userId } = req.body;

console.log("📊 [DELETE_ALTERNATE_API] processing", {
  userId,
  userName: deletedBy,
  loanAccountNumber,
  alternateNumber
});
    const pool = await poolPromise;

console.log("📊 [DELETE_ALTERNATE_API] executing delete", {
  loanAccountNumber,
  alternateNumber
});

    await pool.request()
      .input("LoanAccountNumber", sql.VarChar(50), loanAccountNumber)
      .input("AlternateNumber", sql.VarChar(15), alternateNumber)
      .input("DeletedBy", sql.VarChar(100), deletedBy || "SYSTEM")
      .query(`

        -- INSERT INTO HISTORY
        INSERT INTO dbo.Recovery_Alternate_Number_History
        (LoanAccountNumber, AlternateNumber, ActionType, ActionBy, ActionAt)
        VALUES
        (@LoanAccountNumber, @AlternateNumber, 'DELETE', @DeletedBy, GETDATE());

        -- DELETE FROM MAIN
        DELETE FROM dbo.Recovery_Alternate_Number
        WHERE LoanAccountNumber = @LoanAccountNumber
        AND AlternateNumber = @AlternateNumber;

      `);
console.log("📦 [DELETE_ALTERNATE_API] deleted", {
  userId,
  userName: deletedBy,
  loanAccountNumber,
  alternateNumber
});
console.log("✅ [DELETE_ALTERNATE_API] success", {
  loanAccountNumber,
  alternateNumber
});

console.log("📤 [DELETE_ALTERNATE_API] response sent", {
  loanAccountNumber,
  alternateNumber
});

    res.json({ success: true });

  } catch (err) {

console.log("❌ [DELETE_ALTERNATE_API] error", {
  message: err.message,
  stack: err.stack,
  loanAccountNumber,
  alternateNumber,
  deletedBy
});

    res.status(500).json({ message: "Server error" });
  }
});

//================================== MANUAL ADDRESS ==================================
app.post("/api/account/save-manual-address", async (req, res) => {
console.log("📥 [SAVE_ADDRESS_API] request", {
  userId: req.body?.userId,
  userName: req.body?.userName,
  loanAccountNumber: req.body?.loanAccountNumber,
  address: req.body?.address
});
  try {
    const { loanAccountNumber, address, userId, userName } = req.body;
console.log("📊 [SAVE_ADDRESS_API] saving", {
  userId,
  userName,
  loanAccountNumber,
  address
});
    if (!loanAccountNumber || !address) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const pool = await poolPromise;

    await pool.request()
      .input("LoanAccountNumber", sql.VarChar(50), loanAccountNumber)
      .input("Address", sql.NVarChar(sql.MAX), address)
      .input("UserId", sql.VarChar(100), userId)
      .query(`

        -- SAVE OLD ADDRESS INTO HISTORY (IF EXISTS)
        INSERT INTO dbo.Customer_Manual_Address_History
        (LoanAccountNumber, Address, ActionType, ActionBy, ActionAt)
        SELECT
            LoanAccountNumber,
            Address,
            'DELETE',
            @UserId,
            GETDATE()
        FROM dbo.Customer_Manual_Address
        WHERE LoanAccountNumber = @LoanAccountNumber;

        -- DELETE OLD
        DELETE FROM dbo.Customer_Manual_Address
        WHERE LoanAccountNumber = @LoanAccountNumber;

        -- INSERT NEW ADDRESS
        INSERT INTO dbo.Customer_Manual_Address
        (LoanAccountNumber, Address, CreatedBy, CreatedAt)
        VALUES
        (@LoanAccountNumber, @Address, @UserId, GETDATE());

        -- INSERT NEW INTO HISTORY
        INSERT INTO dbo.Customer_Manual_Address_History
        (LoanAccountNumber, Address, ActionType, ActionBy, ActionAt)
        VALUES
        (@LoanAccountNumber, @Address, 'INSERT', @UserId, GETDATE());

      `);
console.log("📦 [SAVE_ADDRESS_API] saved", {
  userId,
  userName,
  loanAccountNumber,
  address
});
    res.json({ success: true });

  } catch (err) {
    console.log("Save address error:", err);
    res.status(500).json({ message: "Server error" });
  }
});
// =====================================================================
// HOME → MEMBERS SUMMARY (ASSIGNMENT BASED)
// =====================================================================

app.post("/api/home/members-summary", async (req, res) => {

console.log("📥 [HOME_API] members-summary request", {
  userId: req.body?.userId
});

const { userId } = req.body;

if (!userId) {
  console.log("⚠️ [HOME_API] userId missing");
  return res.status(400).json({ message: "userId is required" });
}

try {
  const pool = await poolPromise;

  console.log("📊 [HOME_API] fetching members summary", { userId });

  const result = await pool.request()
    .input("userId", sql.VarChar(50), userId)
    .query(`
      SELECT
        SUM(CASE 
              WHEN R.dpdQueue IN ('01','02','03','04','05','06','07')
              THEN 1 ELSE 0
            END) AS npa,

        SUM(CASE
              WHEN R.dpdQueue = '00'
              THEN 1 ELSE 0
            END) AS marketing,

        SUM(CASE
              WHEN R.dpdQueue IS NULL
              THEN 1 ELSE 0
            END) AS welcome

      FROM Account_Assignments A
      INNER JOIN Recovery_Raw_Data R
        ON A.LoanAccountNumber = R.loanAccountNumber
      WHERE
        A.AssignedToUserId = @userId
        AND A.AssignmentStatus = 'Assigned'
    `);

  const row = result.recordset[0] || {};

  const npa = row.npa || 0;
  const marketing = row.marketing || 0;
  const welcome = row.welcome || 0;

  const totalPending = npa + marketing + welcome;

  const response = {
    members: {
      pending: totalPending,
      inProcess: 0,
      completed: 0,
    },
    npa: {
      pending: npa,
      inProcess: 0,
      completed: 0,
    },
    marketing: {
      pending: marketing,
      inProcess: 0,
      completed: 0,
    },
    welcome: {
      pending: welcome,
      inProcess: 0,
      completed: 0,
    }
  };

  console.log("📦 [HOME_API] members-summary fetched", {
    userId,
    response
  });

  console.log("📤 [HOME_API] response sent", { userId });

  return res.json(response);

} catch (err) {
  console.error("❌ MEMBERS SUMMARY ERROR:", {
    message: err.message,
    stack: err.stack,
    userId
  });

  return res.status(500).json({ message: "Failed to load members summary" });
}
});

// =====================================================================
// NPA → DPD SUMMARY V2 (Pending / InProcess / Completed from CallRecovery_Status)
// =====================================================================
app.post("/api/npa/dpd-summary-v2", async (req, res) => {
console.log("📥 [NPA_API] dpd-summary request", {
  userId: req.body?.userId,
  userName: req.body?.userName,
  payload: req.body
});
  const { userId, userName } = req.body;

if (!userId) {
  console.log("⚠️ [NPA_API] userId missing");
  return res.status(400).json({ message: "userId is required" });
}
  try {
    const pool = await poolPromise;
console.log("📊 [NPA_API] Fetching DPD summary", {
  userId,
  userName
});
    const result = await pool.request()
	
      .input("UserId", sql.VarChar(50), String(userId))
      .query(`
        ;WITH NPA_Assigned AS (
          SELECT 
            A.LoanAccountNumber,
            RIGHT('00' + ISNULL(R.dpdQueue,''), 2) AS dpdQueue
          FROM Account_Assignments A
          INNER JOIN Recovery_Raw_Data R
            ON A.LoanAccountNumber = R.loanAccountNumber
          WHERE A.AssignedToUserId = @UserId
            AND A.AssignmentStatus = 'Assigned'
            AND RIGHT('00' + ISNULL(R.dpdQueue,''), 2) IN ('01','02','03','04','05','06','07')
        )

        SELECT
          -- ===========================
          -- 0_30 (01)
          -- ===========================
          SUM(CASE WHEN NA.dpdQueue='01'
                    AND ISNULL(CRS.InProcessFlag,0)=0
                    AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS pending_0_30,

          SUM(CASE WHEN NA.dpdQueue='01'
                    AND ISNULL(CRS.InProcessFlag,0)=1
                    AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS inprocess_0_30,

         SUM(CASE WHEN NA.dpdQueue='01'
          AND ISNULL(CRS.CompleteFlag,0)=1
          AND CAST(CRS.UpdatedAt AS DATE) = CAST(GETDATE() AS DATE)
    THEN 1 ELSE 0 END) AS completed_0_30,

          -- ===========================
          -- 31_60 (02)
          -- ===========================
          SUM(CASE WHEN NA.dpdQueue='02'
                    AND ISNULL(CRS.InProcessFlag,0)=0
                    AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS pending_31_60,

          SUM(CASE WHEN NA.dpdQueue='02'
                    AND ISNULL(CRS.InProcessFlag,0)=1
                    AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS inprocess_31_60,

         SUM(CASE WHEN NA.dpdQueue='02'
          AND ISNULL(CRS.CompleteFlag,0)=1
          AND CAST(CRS.UpdatedAt AS DATE) = CAST(GETDATE() AS DATE)
    THEN 1 ELSE 0 END) AS completed_31_60,

          -- ===========================
          -- 61_90 (03)
          -- ===========================
          SUM(CASE WHEN NA.dpdQueue='03'
                    AND ISNULL(CRS.InProcessFlag,0)=0
                    AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS pending_61_90,

          SUM(CASE WHEN NA.dpdQueue='03'
                    AND ISNULL(CRS.InProcessFlag,0)=1
                    AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS inprocess_61_90,

        SUM(CASE WHEN NA.dpdQueue='03'
          AND ISNULL(CRS.CompleteFlag,0)=1
          AND CAST(CRS.UpdatedAt AS DATE) = CAST(GETDATE() AS DATE)
    THEN 1 ELSE 0 END) AS completed_61_90,

          -- ===========================
          -- 90_plus (04-07)
          -- ===========================
          SUM(CASE WHEN NA.dpdQueue IN ('04','05','06','07')
                    AND ISNULL(CRS.InProcessFlag,0)=0
                    AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS pending_90_plus,

          SUM(CASE WHEN NA.dpdQueue IN ('04','05','06','07')
                    AND ISNULL(CRS.InProcessFlag,0)=1
                    AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS inprocess_90_plus,

          SUM(CASE WHEN NA.dpdQueue IN ('04','05','06','07')
          AND ISNULL(CRS.CompleteFlag,0)=1
          AND CAST(CRS.UpdatedAt AS DATE) = CAST(GETDATE() AS DATE)
    THEN 1 ELSE 0 END) AS completed_90_plus

        FROM NPA_Assigned NA
        LEFT JOIN CallRecovery_Status CRS
          ON CRS.LoanAccountNumber = NA.LoanAccountNumber
         AND CRS.UserId = @UserId
      `);

    const row = result.recordset[0] || {};
const response = {
  "0_30": {
    pending: row.pending_0_30 || 0,
    inProcess: row.inprocess_0_30 || 0,
    completed: row.completed_0_30 || 0,
  },
  "31_60": {
    pending: row.pending_31_60 || 0,
    inProcess: row.inprocess_31_60 || 0,
    completed: row.completed_31_60 || 0,
  },
  "61_90": {
    pending: row.pending_61_90 || 0,
    inProcess: row.inprocess_61_90 || 0,
    completed: row.completed_61_90 || 0,
  },
  "90_plus": {
    pending: row.pending_90_plus || 0,
    inProcess: row.inprocess_90_plus || 0,
    completed: row.completed_90_plus || 0,
  }
};

console.log("📦 [NPA_API] fetched data", {
  userId,
  userName,
  response
});

const total =
  response["0_30"].pending +
  response["31_60"].pending +
  response["61_90"].pending +
  response["90_plus"].pending;

console.log("📊 [NPA_API] counts", {
  userId,
  userName,
  "0_30": response["0_30"],
  "31_60": response["31_60"],
  "61_90": response["61_90"],
  "90_plus": response["90_plus"],
  total
});

console.log("✅ [NPA_API] DPD summary ready");

console.log("📤 [NPA_API] sending response", {
  userId,
  userName
});

return res.json(response);

  } catch (err) {
    console.error("❌ [NPA_API] error:", {
  message: err.message,
  stack: err.stack,
  userId
});
    return res.status(500).json({ message: "Failed to load dpd summary v2" });
  }
});
// =====================================================================
// HOME → MEMBERS SUMMARY V4 (Correct Separation)
// NPA & Welcome → Recovery Tables
// Marketing → Leads_Data Table
// =====================================================================
app.post("/api/home/members-summary-v3", async (req, res) => {
	console.log("📥 [HOME_API] members-summary request", { userId: req.body?.userId });
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "userId required" });
  }

  try {
    const pool = await poolPromise;

    // =====================================================
    // 1️⃣ RECOVERY SUMMARY (NPA + WELCOME)
    // =====================================================
		console.log("📊 [HOME_API] Fetching recovery summary", { userId });
    const recoveryResult = await pool.request()
      .input("UserId", sql.VarChar(50), String(userId))
      .query(`
        ;WITH Assigned AS (
          SELECT 
            A.LoanAccountNumber,
            RIGHT('00' + LTRIM(RTRIM(CAST(R.dpdQueue AS VARCHAR(5)))), 2) AS dpdQueue
          FROM Account_Assignments A
          INNER JOIN Recovery_Raw_Data R
            ON R.loanAccountNumber = A.LoanAccountNumber
          WHERE A.AssignedToUserId = @UserId
            AND A.AssignmentStatus = 'Assigned'
        )

        SELECT
          -- NPA (01–07)
          SUM(CASE 
                WHEN A.dpdQueue IN ('01','02','03','04','05','06','07')
                 AND ISNULL(CRS.InProcessFlag,0)=0
                 AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS npa_pending,

          SUM(CASE 
                WHEN A.dpdQueue IN ('01','02','03','04','05','06','07')
                 AND ISNULL(CRS.InProcessFlag,0)=1
                 AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS npa_inprocess,

          SUM(CASE 
      WHEN A.dpdQueue IN ('01','02','03','04','05','06','07')
       AND ISNULL(CRS.CompleteFlag,0)=1
       AND CAST(CRS.UpdatedAt AS DATE) = CAST(GETDATE() AS DATE)
    THEN 1 ELSE 0 END) AS npa_completed,

          -- WELCOME (NULL/EMPTY)
          SUM(CASE 
                WHEN (A.dpdQueue IS NULL OR A.dpdQueue = '')
                 AND ISNULL(CRS.InProcessFlag,0)=0
                 AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS welcome_pending,

          SUM(CASE 
                WHEN (A.dpdQueue IS NULL OR A.dpdQueue = '')
                 AND ISNULL(CRS.InProcessFlag,0)=1
                 AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS welcome_inprocess,

         SUM(CASE 
      WHEN (A.dpdQueue IS NULL OR A.dpdQueue = '')
       AND ISNULL(CRS.CompleteFlag,0)=1
       AND CAST(CRS.UpdatedAt AS DATE) = CAST(GETDATE() AS DATE)
    THEN 1 ELSE 0 END) AS welcome_completed

        FROM Assigned A
        LEFT JOIN CallRecovery_Status CRS
          ON CRS.LoanAccountNumber = A.LoanAccountNumber
         AND CRS.UserId = @UserId
      `);

    const r = recoveryResult.recordset[0] || {};
	console.log("✅ [HOME_API] Recovery summary ready");

    // =====================================================
    // 2️⃣ MARKETING SUMMARY (From Leads_Data)
    // =====================================================
	console.log("📊 [HOME_API] Fetching marketing summary", { userId });
const marketingResult = await pool.request()
  .input("UserId", sql.VarChar(50), String(userId))
  .query(`

  ;WITH LeadLogs AS (
      SELECT
          L.SNo,

          LASTLOG.ActionCode

      FROM Leads_Data L

      OUTER APPLY(
          SELECT TOP 1 ActionCode
          FROM Activity_Logs
          WHERE SourceType='LEAD'
          AND SourceId=L.SNo
          ORDER BY LogId DESC
      ) LASTLOG

      WHERE L.UserID=@UserId
  )

  SELECT

  SUM(
      CASE
          WHEN ActionCode IS NULL
          OR ActionCode IN (
		       'LEAD_NOT_SPOKE',
              'LEAD_BUSY',
              'LEAD_NOT_REACHABLE',
              'LEAD_INVALID_NUMBER'
          )
          THEN 1 ELSE 0
      END
  ) AS marketing_pending,

  SUM(
      CASE
          WHEN ActionCode IN (
              'LEAD_SCHEDULED',
              'LEAD_FLOW_SUBMITTED',
              'LEAD_INTEREST_OTHER_PRODUCT',
              'LEAD_PRODUCT_DEPOSIT',
              'LEAD_PRODUCT_LOAN',
              'LEAD_PRODUCT_OTHER',
              'LEAD_OTHER_PRODUCT_TYPED'
          )
          THEN 1 ELSE 0
      END
  ) AS marketing_inprocess,

  SUM(
      CASE
          WHEN ActionCode IN (
              'LEAD_LOS_CAPTURED',
              'LEAD_NO_REQUIREMENT'
          )
          THEN 1 ELSE 0
      END
  ) AS marketing_completed

  FROM LeadLogs

`);

const m = marketingResult.recordset[0] || {};
console.log("✅ [HOME_API] Marketing summary ready");

    // =====================================================
    // FINAL RESPONSE
    // =====================================================
			console.log("📤 [HOME_API] Sending members summary response");
			const response = {
  members: {
    pending:
      (r.npa_pending || 0) +
      (r.welcome_pending || 0) +
      (m.marketing_pending || 0),

    inProcess:
      (r.npa_inprocess || 0) +
      (r.welcome_inprocess || 0) +
      (m.marketing_inprocess || 0),

    completed:
      (r.npa_completed || 0) +
      (r.welcome_completed || 0) +
      (m.marketing_completed || 0),
  },

  npa: {
    pending: r.npa_pending || 0,
    inProcess: r.npa_inprocess || 0,
    completed: r.npa_completed || 0,
  },

  marketing: {
    pending: m.marketing_pending || 0,
    inProcess: m.marketing_inprocess || 0,
    completed: m.marketing_completed || 0,
  },

  welcome: {
    pending: r.welcome_pending || 0,
    inProcess: r.welcome_inprocess || 0,
    completed: r.welcome_completed || 0,
  }
};
console.log("📦 [HOME_API] Members summary fetched", {
  userId,
  response
});
console.log("📤 [HOME_API] Sending members summary response", {
  userId
});

return res.json(response);
    } catch (err) {
    console.error("❌ [HOME_API] members-summary error:", {
  message: err.message,
  stack: err.stack,
  userId
});
    return res.status(500).json({ message: "Server error" });
  }
});

// =====================================================================
// HOME → SCHEDULE FOR THE DAY SUMMARY (CALL + VISIT)
// ✅ Pending = scheduled date <= today (carry forward)
// ✅ Completed = ONLY completed today (UpdatedAt = today)
// =====================================================================
app.post("/api/home/schedule-summary", async (req, res) => {
	console.log("📥 [HOME_API] schedule-summary request", { userId: req.body?.userId });
  const { userId } = req.body;

if (!userId) {
  console.log("⚠️ [HOME_API] userId missing");
  return res.status(400).json({ message: "userId required" });
}

  try {
    const pool = await poolPromise;
console.log("📊 [HOME_API] Fetching schedule summary", { userId });
    const result = await pool
      .request()
      .input("UserId", sql.VarChar(50), String(userId))
      .query(`
        SELECT
          -- ✅ CALL PENDING (carry forward)
          SUM(CASE 
                WHEN ISNULL(ScheduleCallPendingFlag,0)=1
                 AND ScheduleCallTimestamp IS NOT NULL
                 AND CAST(ScheduleCallTimestamp AS DATE) <= CAST(GETDATE() AS DATE)
                THEN 1 ELSE 0 END) AS call_pending,

          -- ✅ CALL COMPLETED (ONLY TODAY COMPLETED)
          SUM(CASE 
                WHEN ISNULL(ScheduleCallCompletedFlag,0)=1
                 AND CAST(UpdatedAt AS DATE) = CAST(GETDATE() AS DATE)
                THEN 1 ELSE 0 END) AS call_completed,

          -- ✅ VISIT PENDING (carry forward)
          SUM(CASE 
                WHEN ISNULL(ScheduleVisitPendingFlag,0)=1
                 AND ScheduleVisitTimestamp IS NOT NULL
                 AND CAST(ScheduleVisitTimestamp AS DATE) <= CAST(GETDATE() AS DATE)
                THEN 1 ELSE 0 END) AS visit_pending,

          -- ✅ VISIT COMPLETED (ONLY TODAY COMPLETED)
          SUM(CASE 
                WHEN ISNULL(ScheduleVisitCompletedFlag,0)=1
                 AND CAST(UpdatedAt AS DATE) = CAST(GETDATE() AS DATE)
                THEN 1 ELSE 0 END) AS visit_completed

        FROM dbo.CallRecovery_Status
        WHERE UserId = @UserId
      `);

    const row = result.recordset[0] || {};
console.log("✅ [HOME_API] Schedule summary ready");

console.log("📤 [HOME_API] Sending schedule summary response");
    return res.json({
      call: {
        pending: row.call_pending || 0,
        completed: row.call_completed || 0,
      },
      visit: {
        pending: row.visit_pending || 0,
        completed: row.visit_completed || 0,
      },
    });

  } catch (err) {
   console.error("❌ [HOME_API] schedule-summary error:", {
  message: err.message,
  stack: err.stack,
  userId
});
    return res.status(500).json({ message: "Failed to load schedule summary" });
  }
});


// =====================================================================
// HOME → SCHEDULE FOR THE DAY → TODAY + PAST (CALL / VISIT)
// =====================================================================
app.post("/api/home/schedule-today-list", async (req, res) => {
console.log("📥 [TODAY_SCHEDULE_API] request", {
  userId: req.body?.userId,
  userName: req.body?.userName,
  type: req.body?.type,
  payload: req.body
});
  const { userId, type } = req.body; // type = "CALL" or "VISIT"

if (!userId || !type) {
  console.log("⚠️ [TODAY_SCHEDULE_API] missing params", { userId, type });
  return res.status(400).json({ message: "userId and type are required" });
}

  try {
    const pool = await poolPromise;

    const query =
      type === "CALL"
        ? `
        SELECT
          CRS.LoanAccountNumber,
          R.firstname,
          R.mobileNumber,
          R.currentOutstandingBalance AS overdueAmount,
          R.dpdQueue,

          ISNULL(CRS.ScheduleCallPendingFlag,0)   AS ScheduleCallPendingFlag,
          ISNULL(CRS.ScheduleCallCompletedFlag,0) AS ScheduleCallCompletedFlag,

          CRS.ScheduleCallTimestamp,
          CRS.UpdatedAt

        FROM dbo.CallRecovery_Status CRS
        INNER JOIN dbo.Recovery_Raw_Data R
          ON R.loanAccountNumber = CRS.LoanAccountNumber

        WHERE CRS.UserId = @UserId
        AND (
              -- 🔵 TODAY CALL PENDING
              (
                ISNULL(CRS.ScheduleCallPendingFlag,0) = 1
                AND CRS.ScheduleCallTimestamp IS NOT NULL
                AND CONVERT(date, CRS.ScheduleCallTimestamp) = CONVERT(date, GETDATE())
              )

              OR

              -- 🟡 PAST CALL PENDING (Carry Forward)
              (
                ISNULL(CRS.ScheduleCallPendingFlag,0) = 1
                AND CRS.ScheduleCallTimestamp IS NOT NULL
                AND CONVERT(date, CRS.ScheduleCallTimestamp) < CONVERT(date, GETDATE())
              )

              OR

              -- 🟢 CALL COMPLETED TODAY ONLY
              (
                ISNULL(CRS.ScheduleCallCompletedFlag,0) = 1
                AND CONVERT(date, CRS.UpdatedAt) = CONVERT(date, GETDATE())
              )
        )

        ORDER BY
          CONVERT(date, CRS.ScheduleCallTimestamp) DESC,
          CRS.ScheduleCallTimestamp DESC
        `
        : `
        SELECT
          CRS.LoanAccountNumber,
          R.firstname,
          R.mobileNumber,
          R.OVERDUEAMT AS overdueAmount,
          R.dpdQueue,

          ISNULL(CRS.ScheduleVisitPendingFlag,0)   AS ScheduleVisitPendingFlag,
          ISNULL(CRS.ScheduleVisitCompletedFlag,0) AS ScheduleVisitCompletedFlag,

          CRS.ScheduleVisitTimestamp,
          CRS.UpdatedAt

        FROM dbo.CallRecovery_Status CRS
        INNER JOIN dbo.Recovery_Raw_Data R
          ON R.loanAccountNumber = CRS.LoanAccountNumber

        WHERE CRS.UserId = @UserId
        AND (
              -- 🔵 TODAY VISIT PENDING
              (
                ISNULL(CRS.ScheduleVisitPendingFlag,0) = 1
                AND CRS.ScheduleVisitTimestamp IS NOT NULL
                AND CONVERT(date, CRS.ScheduleVisitTimestamp) = CONVERT(date, GETDATE())
              )

              OR

              -- 🟡 PAST VISIT PENDING (Carry Forward)
              (
                ISNULL(CRS.ScheduleVisitPendingFlag,0) = 1
                AND CRS.ScheduleVisitTimestamp IS NOT NULL
                AND CONVERT(date, CRS.ScheduleVisitTimestamp) < CONVERT(date, GETDATE())
              )

              OR

              -- 🟢 VISIT COMPLETED TODAY ONLY
              (
                ISNULL(CRS.ScheduleVisitCompletedFlag,0) = 1
                AND CONVERT(date, CRS.UpdatedAt) = CONVERT(date, GETDATE())
              )
        )

        ORDER BY
          CONVERT(date, CRS.ScheduleVisitTimestamp) DESC,
          CRS.ScheduleVisitTimestamp DESC
        `;
console.log("📊 [TODAY_SCHEDULE_API] Fetching schedules", { userId, type });

const result = await pool
  .request()
  .input("UserId", sql.VarChar(50), String(userId))
  .query(query);

console.log("📦 [TODAY_SCHEDULE_API] fetched data", {
  userId,
  type,
  records: result.recordset
});

console.log("✅ [TODAY_SCHEDULE_API] schedules fetched", {
  userId,
  userName: req.body?.userName,
  type,
  count: result.recordset?.length || 0
});
console.log("📤 [TODAY_SCHEDULE_API] sending response");
return res.json({
  type,
  records: result.recordset || [],
});
  } catch (err) {
   console.error("❌ [TODAY_SCHEDULE_API] error:", {
  message: err.message,
  stack: err.stack,
  userId,
  type
});
    return res.status(500).json({ message: "Failed to load schedule list" });
  }
});

// =====================================================================
// FIELD VISIT
// =====================================================================

// ===============================
// START FIELD VISIT
// ===============================
app.post("/api/field-visit/start", async (req, res) => {

  let {
    userId,
    userName,
    accountNo,
    customerName,
    customerLat,
    customerLng,
    customerAddress
  } = req.body;

  try {
    const pool = await poolPromise;

    // ============================================
    // STEP 0 — FALLBACK TO MANUAL ADDRESS
    // ============================================
    if (!customerAddress || customerAddress.trim() === "") {

      const manualAddressResult = await pool.request()
        .input("AccountNo", sql.VarChar(50), accountNo)
        .query(`
          SELECT TOP 1 Address
          FROM Customer_Manual_Address
          WHERE LoanAccountNumber = @AccountNo
          ORDER BY CreatedAt DESC
        `);

      if (manualAddressResult.recordset.length > 0) {
        customerAddress = manualAddressResult.recordset[0].Address;
        console.log("✅ Using manual address:", customerAddress);
      }
    }

    // ============================================
    // FINAL VALIDATION
    // ============================================
    if (
      !userId ||
      !userName ||
      !accountNo ||
      !customerName ||
      !customerAddress
    ) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // allow null coordinates
    customerLat = customerLat ?? null;
    customerLng = customerLng ?? null;

    // ============================================
    // STEP 1 — GET BRANCH LAT/LNG
    // ============================================
    const branchResult = await pool.request()
      .input("UserId", sql.VarChar(50), userId)
      .query(`
        SELECT 
            B.Latitude AS BranchLatitude,
            B.Longitude AS BranchLongitude
        FROM UsersInfo U
        JOIN Branch_GPS B 
          ON U.BranchCode = B.[Branch Code]
        WHERE U.UserId = @UserId
      `);

    if (branchResult.recordset.length === 0) {
      return res.status(400).json({ message: "Branch not found for user" });
    }

    const branchLat = branchResult.recordset[0].BranchLatitude;
    const branchLng = branchResult.recordset[0].BranchLongitude;

    // ============================================
    // STEP 2 — CHECK LAST VISIT WITHIN 2 HOURS
    // ============================================
    const lastVisitResult = await pool.request()
      .input("UserId", sql.VarChar(50), userId)
      .query(`
        SELECT TOP 1 
          MeetingLatitude,
          MeetingLongitude,
          DATEDIFF(MINUTE, Timestamp, GETDATE()) AS DiffMinutes
        FROM FieldVisitReport
        WHERE UserID = @UserId
          AND MeetingLatitude IS NOT NULL
          AND MeetingLongitude IS NOT NULL
        ORDER BY Timestamp DESC
      `);

let startLat = branchLat;
let startLng = branchLng;
let startAddress = await getAddressFromCoords(branchLat, branchLng);

if (lastVisitResult.recordset.length > 0) {
  const last = lastVisitResult.recordset[0];
  const diffMinutes = last.DiffMinutes;

  console.log("⏱ DiffMinutes:", diffMinutes);

  if (diffMinutes <= 120) {
    startLat = last.MeetingLatitude;
    startLng = last.MeetingLongitude;

    startAddress = await getAddressFromCoords(
      last.MeetingLatitude,
      last.MeetingLongitude
    );
  }

  // ❌ NO ELSE BLOCK NEEDED

    }

    // ============================================
    // STEP 3 — INSERT VISIT
    // ============================================
    const insertResult = await pool.request()
      .input("UserID", sql.VarChar(50), userId)
      .input("UserName", sql.VarChar(100), userName)
      .input("AccountNo", sql.VarChar(50), accountNo)
      .input("CustomerName", sql.VarChar(150), customerName)

      .input("BranchLatitude", sql.Decimal(18, 10), branchLat)
      .input("BranchLongitude", sql.Decimal(18, 10), branchLng)

      // dynamic start location
      .input("StartLatitude", sql.Decimal(18, 10), startLat)
      .input("StartLongitude", sql.Decimal(18, 10), startLng)
      .input("StartAddress", sql.NVarChar(500), startAddress)

      // customer location (optional)
      .input("CustomerLatitude", sql.Decimal(18, 10), customerLat)
      .input("CustomerLongitude", sql.Decimal(18, 10), customerLng)
      .input("CustomerAddress", sql.NVarChar(500), customerAddress)

      .query(`
        INSERT INTO FieldVisitReport
        (
          UserID,
          UserName,
          AccountNo,
          CustomerName,
          MeetingDate,

          BranchLatitude,
          BranchLongitude,

          StartLatitude,
          StartLongitude,
          StartAddress,

          CustomerLatitude,
          CustomerLongitude,
          CustomerAddress,

          Timestamp
        )
        OUTPUT INSERTED.SNo
        VALUES
        (
          @UserID,
          @UserName,
          @AccountNo,
          @CustomerName,
          GETDATE(),

          @BranchLatitude,
          @BranchLongitude,

          @StartLatitude,
          @StartLongitude,
          @StartAddress,

          @CustomerLatitude,
          @CustomerLongitude,
          @CustomerAddress,

          GETDATE()
        )
      `);

    const insertedSNo = insertResult.recordset?.[0]?.SNo;

    return res.json({
      message: "✅ Visit Started Successfully",
      sno: insertedSNo
    });

  } catch (err) {
    console.log("FieldVisit start error:", err);
    return res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});
// ===============================
// STOP FIELD VISIT
// ===============================

app.post("/api/field-visit/stop", async (req, res) => {
  try {
    const { sno, stopLat, stopLng, stopAddress } = req.body;

    const pool = await poolPromise;

    const result = await pool.request()
      .input("SNo", sql.Int, sno)
      .query(`
        SELECT StartLatitude, StartLongitude
        FROM FieldVisitReport
        WHERE SNo = @SNo
      `);

    if (!result.recordset.length) {
      return res.status(404).json({ message: "Visit not found" });
    }

    const startLat = result.recordset[0].StartLatitude;
    const startLng = result.recordset[0].StartLongitude;

    const distanceKm = await getRoadDistanceKm(
      startLat,
      startLng,
      stopLat,
      stopLng
    );

    await pool.request()
      .input("SNo", sql.Int, sno)
      .input("StopLat", sql.Float, stopLat)
      .input("StopLng", sql.Float, stopLng)
      .input("StopAddress", sql.NVarChar(500), stopAddress)
      .input("Distance", sql.Float, distanceKm)
      .query(`
        UPDATE FieldVisitReport
        SET 
          MeetingLatitude = @StopLat,
          MeetingLongitude = @StopLng,
          MeetingAddress = @StopAddress,
          DistanceTravelled = @Distance
        WHERE SNo = @SNo
      `);

    res.json({
      success: true,
      distanceKm: Number(distanceKm.toFixed(3))
    });

  } catch (err) {
    console.error("Stop Visit Error:", err);
    res.status(500).json({ message: "Server error" });
  }
});
// =====================================
// SAVE LEAD API (CORRECTED)
// =====================================
app.post("/api/saveLead", async (req, res) => {
console.log("📥 [SAVE_LEAD_API] request received", {
  userId: req.body?.UserID,
  userName: req.body?.UserName,
  payload: req.body
});
  try {

    let {
      BranchCode,
      BranchName,
      UserID,
      UserName,
      LeadCategory,
      FullName,
      MobileNumber,
      Address,
      PinCode,
      DOB,
      ProductCategory,
      SelectProduct,
      SelectLeadType
    } = req.body;

    // =====================================
    // CLEAN & NORMALIZE DATA
    // =====================================
    LeadCategory = LeadCategory?.trim();
    ProductCategory = ProductCategory?.trim();
    SelectProduct = SelectProduct?.trim();
    SelectLeadType = SelectLeadType?.trim();

    Address = Address || "";
    PinCode = PinCode || "";
    DOB = DOB || "";

    // Normalize ProductCategory
    if (ProductCategory === "Loans") {
      ProductCategory = "Loan";
    }

    if (ProductCategory === "Deposits") {
      ProductCategory = "Deposits";
    }

    // =====================================
    // VALIDATION
    // =====================================
if (!FullName || !MobileNumber || !ProductCategory || !SelectProduct || !SelectLeadType) {
  console.log("⚠️ [SAVE_LEAD_API] mandatory fields missing", {
    userId: UserID
  });
      return res.status(400).json({
        success: false,
        message: "Mandatory fields missing"
      });
    }

if (!["Deposits", "Loan"].includes(ProductCategory)) {
  console.log("⚠️ [SAVE_LEAD_API] invalid product category", {
    userId: UserID,
    ProductCategory
  });
  return res.status(400).json({
    success: false,
    message: "Invalid Product Category"
  });
}

    const pool = await poolPromise;
console.log("📊 [SAVE_LEAD_API] Fetching cluster", {
  BranchCode
});

    // =====================================
    // FETCH CLUSTER FROM BRANCH MASTER
    // =====================================
    const clusterResult = await pool.request()
      .input("BranchCode", sql.VarChar(50), BranchCode)
      .query(`
        SELECT TOP 1 cluster_name
        FROM smart_call.dbo.Branch_Cluster_Master
        WHERE branch_code = @BranchCode
      `);

   if (!clusterResult.recordset.length) {
  console.log("⚠️ [SAVE_LEAD_API] cluster not found", { BranchCode });
      return res.status(400).json({
        success: false,
        message: "Cluster not found for this BranchCode"
      });
    }

    const ClusterName = clusterResult.recordset[0].cluster_name;
	console.log("📦 [SAVE_LEAD_API] cluster fetched", {
  userId: UserID,
  ClusterName
});
console.log("📊 [SAVE_LEAD_API] inserting lead", {
  userId: UserID,
  userName: UserName,
  FullName,
  MobileNumber,
  ProductCategory,
  SelectProduct,
  SelectLeadType
});
    // =====================================
    // INSERT INTO Leads_Data
    // =====================================
    await pool.request()
      .input("BranchCode", sql.VarChar(50), BranchCode)
      .input("BranchName", sql.VarChar(150), BranchName)
      .input("UserID", sql.VarChar(50), UserID)
      .input("UserName", sql.VarChar(150), UserName)
      .input("ClusterName", sql.VarChar(150), ClusterName)
      .input("LeadCategory", sql.VarChar(50), LeadCategory)
      .input("FullName", sql.VarChar(200), FullName)
      .input("MobileNumber", sql.VarChar(20), MobileNumber)
      .input("Address", sql.VarChar(500), Address)
      .input("PinCode", sql.VarChar(10), PinCode)
      .input("DOB", sql.VarChar(20), DOB)
      .input("ProductCategory", sql.VarChar(100), ProductCategory)
      .input("SelectProduct", sql.VarChar(150), SelectProduct)
      .input("SelectLeadType", sql.VarChar(100), SelectLeadType)
      .query(`
        INSERT INTO Leads_Data
        (
          BranchCode,
          BranchName,
          UserID,
          UserName,
          LeadCategory,
          FullName,
          MobileNumber,
          Address,
          PinCode,
          DOB,
          ProductCategory,
          SelectProduct,
          SelectLeadType,
          ClusterName,
          TimeStamp
        )
        VALUES
        (
          @BranchCode,
          @BranchName,
          @UserID,
          @UserName,
          @LeadCategory,
          @FullName,
          @MobileNumber,
          @Address,
          @PinCode,
          @DOB,
          @ProductCategory,
          @SelectProduct,
          @SelectLeadType,
          @ClusterName,
          GETDATE()
        )
      `);

    // =====================================
    // SUCCESS RESPONSE
    // =====================================
console.log("📤 [SAVE_LEAD_API] response success", {
  userId: UserID,
  userName: UserName,
  success: true
});
    return res.json({
      success: true,
      message: "Lead saved successfully"
    });

  } catch (err) {

  console.error("❌ [SAVE_LEAD_API] error:", {
  message: err.message,
  stack: err.stack,
  userId: req.body?.UserID
});

    return res.status(500).json({
      success: false,
      message: "Server error while saving lead"
    });

  }
});

// ================= GET LEADS FOR LOGGED USER =================
app.get("/api/getMyLeads/:userId", async (req, res) => {

  const { userId } = req.params;
  console.log("📥 [LEADS_API] getMyLeads request", { userId });

  try {

    const pool = await poolPromise;

    console.log("📊 [LEADS_API] Fetching leads", { userId });

    const result = await pool.request()
      .input("UserID", sql.VarChar, userId)
      .query(`
        SELECT 
          L.SNo,
          L.FullName,
          L.MobileNumber,
          L.PinCode,
          L.SelectLeadType,
          L.LeadCategory,
          L.TimeStamp,
          ISNULL(A.AttemptCount,0) AS AttemptCount
        FROM Leads_Data L
        LEFT JOIN
        (
          SELECT 
            SourceId,
            COUNT(*) AS AttemptCount
          FROM Activity_Logs
          WHERE SourceType = 'LEAD'
          AND ActionCode IN (
            'LEAD_BUSY',
            'LEAD_NOT_REACHABLE',
            'LEAD_INVALID_NUMBER'
          )
          GROUP BY SourceId
        ) A
        ON A.SourceId = L.SNo
        WHERE L.UserID = @UserID
        ORDER BY L.TimeStamp DESC
      `);

    console.log("✅ [LEADS_API] leads fetched", {
      count: result.recordset.length
    });
     console.log("📦 [LEADS_API] leads data", result.recordset);
    console.log("📤 [LEADS_API] sending response");

    res.json({
      success: true,
      leads: result.recordset
    });

  } catch (err) {
    console.error("❌ [LEADS_API] getMyLeads error:", {
      message: err.message,
      stack: err.stack,
      userId
    });

    res.json({ success: false });
  }
});

// ================= GET FULL LEAD DETAILS BY SNo =================
app.get("/api/getLeadDetails/:sno", async (req, res) => {
console.log("📥 [LEAD_DETAILS_API] request", {
  sno: req.params?.sno,
  userId: req.query?.userId,
  userName: req.query?.userName
});

  try {
    const { sno } = req.params;

    const pool = await poolPromise;

    console.log("📊 [LEAD_DETAILS_API] fetching lead", { sno });

    const result = await pool.request()

      .input("SNo", sql.Int, sno)
      .query(`
        SELECT *
        FROM Leads_Data
        WHERE SNo = @SNo
      `);
console.log("📦 [LEAD_DETAILS_API] fetched data", {
  sno,
  userId: req.query?.userId,
  userName: req.query?.userName,
  records: result.recordset
});
    if (result.recordset.length === 0) {
      console.log("⚠️ [LEAD_DETAILS_API] lead not found", { sno });
      return res.status(404).json({
        success: false,
        message: "Lead not found"
      });
    }

    console.log("✅ [LEAD_DETAILS_API] lead fetched", { sno });
    console.log("📤 [LEAD_DETAILS_API] sending response");

    res.json({
      success: true,
      lead: result.recordset[0]
    });

  } catch (err) {
    console.error("❌ [LEAD_DETAILS_API] error:", {
      message: err.message,
      stack: err.stack,
      sno: req.params?.sno
    });

    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});
//==================================== ACTIVITY HOME HISTORY =======================================================
app.post("/api/activity/history", async (req, res) => {
console.log("📥 [ACTIVITY_API] history request", {
  userId: req.body?.userId,
  userName: req.body?.userName,
  from: req.body?.fromDate,
  to: req.body?.toDate,
  type: req.body?.type,
  search: req.body?.searchText ? "YES" : "NO",
  payload: req.body
});
  try {
    const { userId, fromDate, toDate, searchText, type } = req.body;

if (!userId) {
  console.log("⚠️ [ACTIVITY_API] userId missing");
  return res.status(400).json({ message: "userId required" });
}
    const pool = await poolPromise;
console.log("📊 [ACTIVITY_API] Fetching activity history", {
  userId,
  type,
  hasDateFilter: !!fromDate || !!toDate,
  hasSearch: !!searchText
});
    const result = await pool.request()
      .input("UserId", sql.VarChar(50), String(userId))
      .input("FromDate", sql.Date, fromDate || null)
      .input("ToDate", sql.Date, toDate || null)
      .input("SearchText", sql.VarChar(100), searchText || null)
      .input("Type", sql.VarChar(20), type || null)

      .query(`

/* ======================================================
   LATEST SESSION ACTIONS (NPA + LEAD)
====================================================== */

WITH LatestAction AS (
    SELECT *
    FROM (
        SELECT
            s.SessionId,
            s.SourceType,
            s.LoanAccountNumber,
            s.SourceId,
            s.SessionType,
            l.CreatedAt AS ActionTime,

            ROW_NUMBER() OVER (
                PARTITION BY 
                    CASE 
                        WHEN s.SourceType='LEAD' 
                        THEN CAST(s.SourceId AS VARCHAR)
                        ELSE s.LoanAccountNumber 
                    END
                ORDER BY l.CreatedAt DESC
            ) AS rn

        FROM smart_call.dbo.Activity_Sessions s
        INNER JOIN smart_call.dbo.Activity_Logs l
            ON s.SessionId = l.SessionId
        WHERE
            s.StartedByUserId = @UserId
            AND (
                (@FromDate IS NULL OR CAST(l.CreatedAt AS DATE) >= @FromDate)
                AND (@ToDate IS NULL OR CAST(l.CreatedAt AS DATE) <= @ToDate)
            )
    ) x
    WHERE rn = 1
)

/* ======================================================
   NPA RECORDS
====================================================== */

SELECT
    la.LoanAccountNumber,
    'NPA' AS SourceType,
    la.SessionType,
    r.firstname AS CustomerName,

    sr.[NEW IRAC] AS dpdQueue,

    l.ActionLabel,

    CONVERT(VARCHAR(20), la.ActionTime, 113) AS FormattedTime,

    la.ActionTime,

    CASE
        WHEN ISNULL(cr.CompleteFlag,0)=1
        OR ISNULL(cr.ScheduleCallCompletedFlag,0)=1
        OR ISNULL(cr.ScheduleVisitCompletedFlag,0)=1
        THEN 'COMPLETED'

        WHEN ISNULL(cr.InProcessFlag,0)=1
        OR ISNULL(cr.ScheduleCallPendingFlag,0)=1
        OR ISNULL(cr.ScheduleVisitPendingFlag,0)=1
        THEN 'IN PROCESS'

        ELSE 'PENDING'
    END AS AccountStatus

FROM LatestAction la

INNER JOIN smart_call.dbo.Activity_Logs l
  ON l.SessionId = la.SessionId
 AND l.CreatedAt = la.ActionTime

LEFT JOIN smart_call.dbo.Recovery_Raw_Data r
  ON r.loanAccountNumber = la.LoanAccountNumber

LEFT JOIN smart_call.dbo.SMA_Report sr
  ON sr.[Account No.] = la.LoanAccountNumber

LEFT JOIN smart_call.dbo.CallRecovery_Status cr
  ON cr.LoanAccountNumber = la.LoanAccountNumber
 AND cr.UserId = @UserId

WHERE
    la.SourceType = 'NPA'
    AND (@Type IS NULL OR @Type='ALL' OR @Type='NPA')
    AND (
        @SearchText IS NULL
        OR r.firstname LIKE '%' + @SearchText + '%'
        OR la.LoanAccountNumber LIKE '%' + @SearchText + '%'
    )


UNION ALL

/* ======================================================
   LEAD RECORDS
====================================================== */

SELECT
    ld.MobileNumber AS LoanAccountNumber,

    'LEAD' AS SourceType,

    la.SessionType,

    ld.FullName AS CustomerName,

    NULL AS dpdQueue,

    l.ActionLabel,

    CONVERT(VARCHAR(20), la.ActionTime, 113) AS FormattedTime,

    la.ActionTime,

    CASE
        WHEN l.ActionCode IN (
            'LEAD_LOS_CAPTURED',
            'LEAD_NO_REQUIREMENT'
        )
        THEN 'COMPLETED'

        WHEN l.ActionCode IN (
            'LEAD_SCHEDULED',
            'LEAD_CALLBACK',
            'LEAD_VISIT',
            'LEAD_FLOW_SUBMITTED',
            'LEAD_INTEREST_OTHER_PRODUCT',
            'LEAD_PRODUCT_DEPOSIT',
            'LEAD_PRODUCT_LOAN',
            'LEAD_PRODUCT_OTHER',
            'LEAD_OTHER_PRODUCT_TYPED'
        )
        THEN 'INPROCESS'

        ELSE 'PENDING'
    END AS AccountStatus

FROM LatestAction la

INNER JOIN smart_call.dbo.Activity_Logs l
  ON l.SessionId = la.SessionId
 AND l.CreatedAt = la.ActionTime

INNER JOIN smart_call.dbo.Leads_Data ld
  ON ld.SNo = la.SourceId

WHERE
    la.SourceType = 'LEAD'
    AND (@Type IS NULL OR @Type='ALL' OR @Type='LEAD')
    AND (
        @SearchText IS NULL
        OR ld.FullName LIKE '%' + @SearchText + '%'
        OR ld.MobileNumber LIKE '%' + @SearchText + '%'
    )


UNION ALL

/* ======================================================
   CO USE (SMA)
====================================================== */

SELECT
    s.LoanAccountNumber,

    'CO_USE' AS SourceType,

    s.SessionType,

    sr.[Account Name] AS CustomerName,

    sr.[NEW IRAC] AS dpdQueue,

    l.ActionLabel,

    CONVERT(VARCHAR(20), l.CreatedAt, 113) AS FormattedTime,

    l.CreatedAt AS ActionTime,

    NULL AS AccountStatus

FROM smart_call.dbo.SMA_Activity_Sessions s

INNER JOIN (
    SELECT SessionId, MAX(CreatedAt) AS LatestTime
    FROM smart_call.dbo.SMA_Activity_Logs
    GROUP BY SessionId
) latest
  ON latest.SessionId = s.SessionId

INNER JOIN smart_call.dbo.SMA_Activity_Logs l
  ON l.SessionId = latest.SessionId
 AND l.CreatedAt = latest.LatestTime

LEFT JOIN smart_call.dbo.SMA_Report sr
  ON sr.[Account No.] = s.LoanAccountNumber

WHERE
    s.StartedByUserId = @UserId
    AND (
        (@FromDate IS NULL OR CAST(l.CreatedAt AS DATE) >= @FromDate)
        AND (@ToDate IS NULL OR CAST(l.CreatedAt AS DATE) <= @ToDate)
    )
    AND (@Type IS NULL OR @Type='ALL' OR @Type='CO_USE')
    AND (
        @SearchText IS NULL
        OR sr.[Account Name] LIKE '%' + @SearchText + '%'
        OR s.LoanAccountNumber LIKE '%' + @SearchText + '%'
    )


ORDER BY ActionTime DESC
      `);
	console.log("📦 [ACTIVITY_API] fetched data", {
  userId,
  userName: req.body?.userName,
  count: result.recordset?.length || 0,
  data: result.recordset
}); 
console.log("✅ [ACTIVITY_API] history fetched", {
  userId,
  userName: req.body?.userName,
  count: result.recordset.length
});

console.log("📤 [ACTIVITY_API] sending response", {
  userId,
  userName: req.body?.userName
});

res.json({
  success: true,
  count: result.recordset.length,
  records: result.recordset
});

  } catch (err) {
    console.error("❌ [ACTIVITY_API] history error:", {
  message: err.message,
  stack: err.stack,
  userId
});
    res.status(500).json({ message: "History fetch failed" });
  }
});
//=========================================== HOME ACTIVITY DETAILS ============================================
app.post("/api/activity/history-details", async (req, res) => {
console.log("📥 [ACTIVITY_DETAILS_API] request", {
  userId: req.body?.userId,
  userName: req.body?.userName,
  account: req.body?.loanAccountNumber,
  payload: req.body
});
  try {
    const { loanAccountNumber } = req.body;

  if (!loanAccountNumber) {
  console.log("⚠️ [ACTIVITY_DETAILS_API] account missing");
  
  return res.status(400).json({ message: "LoanAccountNumber required" });
}

    const pool = await poolPromise;

console.log("📊 [ACTIVITY_DETAILS_API] Fetching timeline", {
  account: loanAccountNumber
});

const result = await pool.request()
  .input("LoanAccountNumber", sql.VarChar(50), String(loanAccountNumber))
  .query(`

/* ======================================================
   NPA ACTIVITY TIMELINE
====================================================== */

SELECT
    s.SessionType,
    l.ActionLabel,

  CONVERT(VARCHAR(20), l.CreatedAt, 113) AS FormattedTime,
l.CreatedAt AS ActionTime,

    FORMAT(cr.ScheduleCallTimestamp,'dd/MM/yyyy hh:mm tt')
      AS FormattedCallSchedule,

    FORMAT(cr.ScheduleVisitTimestamp,'dd/MM/yyyy hh:mm tt')
      AS FormattedVisitSchedule,

    'NPA' AS SourceType

FROM smart_call.dbo.Activity_Sessions s

INNER JOIN smart_call.dbo.Activity_Logs l
  ON s.SessionId = l.SessionId

LEFT JOIN smart_call.dbo.CallRecovery_Status cr
  ON cr.LoanAccountNumber = s.LoanAccountNumber

WHERE
    s.SourceType = 'NPA'
    AND s.LoanAccountNumber = @LoanAccountNumber


UNION ALL


/* ======================================================
   LEAD ACTIVITY TIMELINE
====================================================== */

SELECT
    s.SessionType,
    l.ActionLabel,

   CONVERT(VARCHAR(20), l.CreatedAt, 113) AS FormattedTime,
l.CreatedAt AS ActionTime,

    NULL AS FormattedCallSchedule,

    NULL AS FormattedVisitSchedule,

    'LEAD' AS SourceType

FROM smart_call.dbo.Activity_Sessions s

INNER JOIN smart_call.dbo.Activity_Logs l
  ON s.SessionId = l.SessionId

INNER JOIN smart_call.dbo.Leads_Data ld
  ON ld.SNo = s.SourceId

WHERE
    s.SourceType = 'LEAD'
    AND ld.MobileNumber = @LoanAccountNumber


UNION ALL


/* ======================================================
   CO USE (SMA) TIMELINE
====================================================== */

SELECT
    s.SessionType,
    l.ActionLabel,

   CONVERT(VARCHAR(20), l.CreatedAt, 113) AS FormattedTime,
l.CreatedAt AS ActionTime,

    NULL AS FormattedCallSchedule,

    NULL AS FormattedVisitSchedule,

    'CO_USE' AS SourceType

FROM smart_call.dbo.SMA_Activity_Sessions s

INNER JOIN smart_call.dbo.SMA_Activity_Logs l
  ON s.SessionId = l.SessionId

WHERE
    s.LoanAccountNumber = @LoanAccountNumber


ORDER BY ActionTime DESC
      `);
console.log("📦 [ACTIVITY_DETAILS_API] fetched data", {
  userId: req.body?.userId,
  userName: req.body?.userName,
  account: loanAccountNumber,
  count: result.recordset?.length || 0,
  data: result.recordset
});
console.log("✅ [ACTIVITY_DETAILS_API] timeline fetched", {
  userId: req.body?.userId,
  userName: req.body?.userName,
  count: result.recordset.length
});

console.log("📤 [ACTIVITY_DETAILS_API] sending response", {
  userId: req.body?.userId
});
return res.json({
  success: true,
  records: result.recordset
});
  } catch (err) {
    console.error("❌ [ACTIVITY_DETAILS_API] error:", {
  message: err.message,
  stack: err.stack,
  account: req.body?.loanAccountNumber
});
    res.status(500).json({ message: "Details fetch failed" });
  }
});

//============================================================================================
//                               APP SMA Report
//=============================================================================================
app.get("/api/sma-report", async (req, res) => {

console.log("📥 [SMA_REPORT_API] request", {
  userId: req.query.userId || "N/A",
  userName: req.query.userName || "N/A",
  cluster: req.query.cluster,
  branchCode: req.query.branchCode,
  branchName: req.query.branchName,
  irac: req.query.irac
});

  try {

    const { cluster, branchCode, branchName, irac } = req.query;
const { userId, userName } = req.query;

console.log("⚠️ [SMA_REPORT_API] validation", {
  userId,
  userName,
  cluster: cluster || "ALL",
  branchCode: branchCode || "ALL",
  branchName: branchName || "ALL",
  irac: irac || "ALL"
});

console.log("📊 [SMA_REPORT_API] processing", {
  userId,
  userName,
  cluster,
  branchCode,
  branchName,
  irac
});

    const pool = await poolPromise;

    // Cluster Name → Cluster Code mapping
    const clusterMap = {
      "Krishna": "KR",
      "Guntur": "GU",
      "West Godavari": "WG",
      "Visakhapatnam": "VS"
    };

    const clusterCode = clusterMap[cluster] || null;
	console.log("⚠️ Cluster mapped", clusterCode);

    let query = `
      SELECT
        S.[SNo.],
        S.[Br Code],
        S.[Branch Name],
        S.[Cluster Code],
        S.[Account No.],
        S.[Account Name],
        S.[Account Type Description],
        S.[Limit],
        S.[Drawing Power],
        S.[Int Rate],
        S.[Theo Balance],
        S.[Cleared Balance],
        S.[Uncleared Balance],
        S.[Outstanding Balance],
        S.[Overdue],
        S.[Sanction Date],
        S.[Expiry Date],
        S.[EMIs Due],
        S.[EMIs Paid],
        S.[EMIs OD],
        S.[NEW IRAC],
        S.[OLD IRAC],
        S.[NPA Date],
        S.[Arrear Condition],
        S.[Arrear Description],
        S.[Loan Type],
        S.[Product Group],

        COALESCE(MAX(R.mobileNumber), MAX(A.AlternateNumber)) AS MobileNumber,
        MAX(A.AlternateNumber) AS AlternateNumber

      FROM smart_call.dbo.SMA_Report S

      LEFT JOIN smart_call.dbo.Recovery_Raw_Data R
      ON S.[Account No.] = R.loanAccountNumber

      LEFT JOIN smart_call.dbo.Recovery_Alternate_Number A
      ON S.[Account No.] = A.LoanAccountNumber

      WHERE 1=1
    `;

    // Cluster filter
    if (clusterCode) {
      query += ` AND S.[Cluster Code] = '${clusterCode}'`;
    }

    // Branch Code filter
    if (branchCode) {
      query += ` AND CAST(S.[Br Code] AS INT) = ${parseInt(branchCode)}`;
    }

    // Branch Name filter
    if (branchName) {
      query += ` AND S.[Branch Name] LIKE '%${branchName}%'`;
    }

    // IRAC filter
    if (irac) {
      query += ` AND CAST(S.[NEW IRAC] AS INT) = ${parseInt(irac)}`;
    }

    query += `
      GROUP BY
        S.[SNo.],
        S.[Br Code],
        S.[Branch Name],
        S.[Cluster Code],
        S.[Account No.],
        S.[Account Name],
        S.[Account Type Description],
        S.[Limit],
        S.[Drawing Power],
        S.[Int Rate],
        S.[Theo Balance],
        S.[Cleared Balance],
        S.[Uncleared Balance],
        S.[Outstanding Balance],
        S.[Overdue],
        S.[Sanction Date],
        S.[Expiry Date],
        S.[EMIs Due],
        S.[EMIs Paid],
        S.[EMIs OD],
        S.[NEW IRAC],
        S.[OLD IRAC],
        S.[NPA Date],
        S.[Arrear Condition],
        S.[Arrear Description],
        S.[Loan Type],
        S.[Product Group]
    `;
console.log("📊 [SMA_REPORT_API] executing query", {
  userId,
  userName,
  cluster,
  branchCode,
  branchName,
  irac
});
    const result = await pool.request().query(query);
console.log("📦 [SMA_REPORT_API] fetched data", {
  userId,
  userName,
  count: result.recordset?.length || 0,
  data: result.recordset
});
console.log("✅ [SMA_REPORT_API] success", {
  count: result.recordset?.length || 0
});

console.log("📤 [SMA_REPORT_API] response sent", {
  count: result.recordset?.length || 0
});

res.json(result.recordset);

  } catch (err) {

console.log("❌ [SMA_REPORT_API] error", {
  message: err.message,
  stack: err.stack
});

    res.status(500).send("Server Error");

  }
});
//============================================================================================
//                                BRANCH CALL
//============================================================================================
app.get("/api/branch-contacts", async (req,res)=>{
console.log("📥 [BRANCH_CONTACTS_API] request", {
  userId: req.query.userId || "N/A",
  userName: req.query.userName || "N/A",
  branchCode: req.query.branchCode
});

try{

const {branchCode} = req.query;

console.log("⚠️ [BRANCH_CONTACTS_API] validation", {
  branchCode: branchCode || "MISSING"
});

const { userId, userName } = req.query;

console.log("📊 [BRANCH_CONTACTS_API] processing", {
  userId,
  userName,
  branchCode
});

const pool = await poolPromise;

console.log("📊 [BRANCH_CONTACTS_API] executing query", {
  userId,
  userName,
  branchCode
});

const result = await pool.request()
.input("branchCode",branchCode)
.query(`
SELECT
[Employee Name],
[Designation],
[Mobile number]
FROM smart_call.dbo.employees_master
WHERE [Br Code] = @branchCode
`);
console.log("📦 [BRANCH_CONTACTS_API] fetched data", {
  userId,
  userName,
  branchCode,
  count: result.recordset?.length || 0,
  data: result.recordset
});
console.log("✅ [BRANCH_CONTACTS_API] success", {
  count: result.recordset?.length || 0
});

console.log("📤 [BRANCH_CONTACTS_API] response sent", {
  count: result.recordset?.length || 0
});

res.json(result.recordset);

}catch(err){

console.log("❌ [BRANCH_CONTACTS_API] error", {
  message: err.message,
  stack: err.stack,
  branchCode: req.query?.branchCode
});

res.status(500).send("Server error");

}

});

//============================================================================================
//                                CUSTOMER CALL
//============================================================================================
app.get("/api/customer-contact", async (req,res)=>{
console.log("📥 /api/customer-contact request", req.query);
try{
const {accountNumber} = req.query;
console.log("⚠️ Validation check", {
accountNumber: accountNumber || "MISSING"
});

console.log("📊 Processing customer contact", accountNumber);

const pool = await poolPromise;

console.log("📊 Executing customer contact query");

const result = await pool.request()
.input("accountNumber",accountNumber)
.query(`
SELECT
firstname,
mobileNumber
FROM smart_call.dbo.Recovery_Raw_Data
WHERE loanAccountNumber = @accountNumber
`);

console.log("✅ Customer contact success", result.recordset.length);

console.log("📤 /api/customer-contact response sent", result.recordset.length);

res.json(result.recordset);

}catch(err){

console.log("❌ /api/customer-contact error",err);

res.status(500).send("Server error");

}

});
// =======================================================
// GET CUSTOMER + ALL ALTERNATE NUMBERS
// =======================================================
app.get("/api/customer-numbers", async (req, res) => {
console.log("📥 [CUSTOMER_NUMBERS_API] request", {
  userId: req.query.userId || "N/A",
  userName: req.query.userName || "N/A",
  accountNumber: req.query.accountNumber
});
  try {
    const { accountNumber } = req.query;

console.log("⚠️ [CUSTOMER_NUMBERS_API] validation", {
  accountNumber: accountNumber || "MISSING"
});
const { userId, userName } = req.query;

console.log("📊 [CUSTOMER_NUMBERS_API] processing", {
  userId,
  userName,
  accountNumber
});
    const pool = await poolPromise;
console.log("📊 [CUSTOMER_NUMBERS_API] executing query", {
  userId,
  userName,
  accountNumber
});

    const result = await pool.request()
      .input("accountNumber", accountNumber)
      .query(`
        SELECT DISTINCT
            R.mobileNumber,
            A.AlternateNumber
        FROM smart_call.dbo.Recovery_Alternate_Number A
        LEFT JOIN smart_call.dbo.Recovery_Raw_Data R
            ON R.loanAccountNumber = A.LoanAccountNumber
        WHERE A.LoanAccountNumber = @accountNumber

        UNION

        SELECT
            R.mobileNumber,
            NULL AS AlternateNumber
        FROM smart_call.dbo.Recovery_Raw_Data R
        WHERE R.loanAccountNumber = @accountNumber
      `);
console.log("📦 [CUSTOMER_NUMBERS_API] fetched data", {
 userId,
  userName,
  accountNumber,
  count: result.recordset?.length || 0,
  data: result.recordset
});
console.log("✅ [CUSTOMER_NUMBERS_API] success", {
  count: result.recordset?.length || 0
});

console.log("📤 [CUSTOMER_NUMBERS_API] response sent", {
  count: result.recordset?.length || 0
});
    res.json(result.recordset);

  } catch (err) {

console.log("❌ [CUSTOMER_NUMBERS_API] error", {
  message: err.message,
  stack: err.stack,
  accountNumber: req.query?.accountNumber
});

    res.status(500).send("Server error");
  }
});

//=========================SMA START========================================
app.post("/api/sma/session/start", async (req,res)=>{
console.log("📥 [SMA_SESSION_START_API] request", {
  userId: req.body?.userId,
  userName: req.body?.userName,
  loanAccountNumber: req.body?.loanAccountNumber,
  sourceType: req.body?.sourceType,
  sourceId: req.body?.sourceId,
  payload: req.body
});
try{

const {
loanAccountNumber,
userId,
userName,
sourceType,
sourceId
} = req.body;

console.log("⚠️ [SMA_SESSION_START_API] validation", {
  loanAccountNumber,
  userId,
  userName,
  sourceType,
  sourceId
});

console.log("📊 [SMA_SESSION_START_API] processing", {
  loanAccountNumber,
  userId,
  userName
});

const pool = await poolPromise;

console.log("📊 [SMA_SESSION_START_API] executing insert", {
  loanAccountNumber,
  userId,
  userName
});

const result = await pool.request()
.input("loanAccountNumber",loanAccountNumber)
.input("userId",userId)
.input("userName",userName)
.input("sourceType",sourceType)
.input("sourceId",sourceId)

.query(`

INSERT INTO smart_call.dbo.SMA_Activity_Sessions
(
LoanAccountNumber,
SessionType,
StartedByUserId,
StartedByUserName,
SourceType,
SourceId
)
OUTPUT INSERTED.SessionId

VALUES
(
@loanAccountNumber,
'CALL',
@userId,
@userName,
@sourceType,
@sourceId
)
`);
const sessionId = result.recordset[0].SessionId;
console.log("📦 [SMA_SESSION_START_API] fetched data", {
  sessionId,
  userId,
  userName,
  loanAccountNumber
});
console.log("✅ [SMA_SESSION_START_API] success", {
  sessionId,
  userId,
  userName
});

console.log("📤 [SMA_SESSION_START_API] response sent", {
  sessionId
});

res.json({sessionId});

}catch(err){

console.log("❌ [SMA_SESSION_START_API] error", {
  message: err.message,
  stack: err.stack,
  userId: req.body?.userId,
  loanAccountNumber: req.body?.loanAccountNumber
});
res.status(500).send("Server error");
}
});

//======================================SMA ACTIVITY===========================================
app.post("/api/sma/log", async (req,res)=>{

console.log("📥 [SMA_LOG_API] request", {
  userId: req.body?.userId,
  userName: req.body?.userName,
  sessionId: req.body?.sessionId,
  actionCode: req.body?.actionCode,
  actionLabel: req.body?.actionLabel,
  payload: req.body
});

try{

const {
sessionId,
parentLogId,
actionCode,
actionLabel,
reasonCode,
metadata,
userId,
userName,
sourceType,
sourceId
} = req.body;

console.log("⚠️ [SMA_LOG_API] validation", {
  sessionId,
  actionCode,
  actionLabel,
  userId,
  userName
});

console.log("📊 [SMA_LOG_API] processing", {
  sessionId,
  actionCode,
  actionLabel,
  userId
});

const pool = await poolPromise;

const metadataJson = metadata ? JSON.stringify(metadata) : null;

console.log("📊 [SMA_LOG_API] inserting log", {
  sessionId,
  actionCode,
  userId
});

//================ INSERT LOG ==================

const result = await pool.request()

.input("sessionId",sessionId)
.input("parentLogId",parentLogId)
.input("actionCode",actionCode)
.input("actionLabel",actionLabel)
.input("reasonCode",reasonCode)
.input("metadata",metadataJson)
.input("userId",userId)
.input("userName",userName)
.input("sourceType",sourceType)
.input("sourceId",sourceId)

.query(`

INSERT INTO smart_call.dbo.SMA_Activity_Logs
(
SessionId,
ParentLogId,
ActionCode,
ActionLabel,
ReasonCode,
MetadataJson,
CreatedByUserId,
CreatedByUserName,
SourceType,
SourceId
)

OUTPUT INSERTED.LogId

VALUES
(
@sessionId,
@parentLogId,
@actionCode,
@actionLabel,
@reasonCode,
@metadata,
@userId,
@userName,
@sourceType,
@sourceId
)

`);

const logId = result.recordset[0].LogId;
console.log("📦 [SMA_LOG_API] fetched data", {
  logId,
  sessionId,
  actionCode,
  userId,
  userName
});
console.log("✅ [SMA_LOG_API] success", {
  logId,
  actionCode,
  userId
});

//================ INSERT NOTE IF USER ENTERED TEXT ==================

let noteText = null;

/*
Only capture actual typed text.
Ignore metadata.reason (like OTHERS)
*/

if(
metadata &&
metadata.note &&
actionCode === "OTHER_REASON_CAPTURED"
){
noteText = metadata.note.trim();
}

if(noteText && noteText.length > 0){
console.log("📊 [SMA_LOG_API] inserting note", {
  logId,
  userId
});
await pool.request()

.input("logId",logId)
.input("noteText",noteText)
.input("userId",userId)
.input("userName",userName)

.query(`

INSERT INTO smart_call.dbo.SMA_Activity_Notes
(
LogId,
NoteText,
CreatedAt,
CreatedByUserId,
CreatedByUserName
)

VALUES
(
@logId,
@noteText,
GETDATE(),
@userId,
@userName
)

`);

console.log("✅ [SMA_LOG_API] note inserted", {
  logId,
  userId
});

}

console.log("📤 [SMA_LOG_API] response sent", {
  logId
});

res.json({logId});

}catch(err){

console.log("❌ [SMA_LOG_API] error", {
  message: err.message,
  stack: err.stack,
  userId: req.body?.userId,
  sessionId: req.body?.sessionId,
  actionCode: req.body?.actionCode
});

res.status(500).send("Server error");

}

});
//======================================SMA END==================================

app.post("/api/sma/session/end", async (req,res)=>{

console.log("📥 [SMA_SESSION_END_API] request", {
  userId: req.body?.userId,
  userName: req.body?.userName,
  sessionId: req.body?.sessionId,
  payload: req.body
});

try{

const {sessionId} = req.body;

console.log("⚠️ [SMA_SESSION_END_API] validation", {
  sessionId
});

const { userId, userName } = req.body;

console.log("📊 [SMA_SESSION_END_API] processing", {
  userId,
  userName,
  sessionId
});

const pool = await poolPromise;

console.log("📊 [SMA_SESSION_END_API] executing update", {
  userId,
  userName,
  sessionId
});

await pool.request()
.input("sessionId",sessionId)
.query(`
UPDATE smart_call.dbo.SMA_Activity_Sessions
SET
SessionStatus='COMPLETED',
EndedAt=GETDATE(),
IsActive=0
WHERE SessionId=@sessionId
`);
console.log("📦 [SMA_SESSION_END_API] update result", {
  sessionId,
  status: "COMPLETED"
});
console.log("✅ [SMA_SESSION_END_API] success", {
  sessionId
});

console.log("📤 [SMA_SESSION_END_API] response sent", {
  sessionId
});

res.json({success:true});

}catch(err){

console.log("❌ [SMA_SESSION_END_API] error", {
  message: err.message,
  stack: err.stack,
  sessionId: req.body?.sessionId,
  userId: req.body?.userId
});

res.status(500).send("Server error");

}

});

//====================================================== SMA HISTORY ===========================================================
app.get("/api/sma/history", async (req, res) => {
console.log("📥 [SMA_HISTORY_API] request", {
  userId: req.query.userId || "N/A",
  userName: req.query.userName || "N/A",
  accountNumber: req.query.accountNumber
});
  try {

    const { accountNumber } = req.query;
console.log("⚠️ [SMA_HISTORY_API] validation", {
  accountNumber: accountNumber || "MISSING"
});

const { userId, userName } = req.query;

console.log("📊 [SMA_HISTORY_API] processing", {
  userId,
  userName,
  accountNumber
});

    const pool = await poolPromise;
console.log("📊 [SMA_HISTORY_API] executing query", {
  userId,
  userName,
  accountNumber
});
    const result = await pool.request()
      .input("accountNumber", accountNumber)
      .query(`
SELECT
    S.SessionId,
    S.StartedAt,
    L.LogId,
    L.ActionLabel,
    L.ActionCode,
    L.MetadataJson,
    L.CreatedAt,
    N.NoteText

FROM smart_call.dbo.SMA_Activity_Sessions S

LEFT JOIN smart_call.dbo.SMA_Activity_Logs L
ON S.SessionId = L.SessionId

LEFT JOIN smart_call.dbo.SMA_Activity_Notes N
ON L.LogId = N.LogId

WHERE S.LoanAccountNumber = @accountNumber

ORDER BY
S.StartedAt DESC,
L.CreatedAt ASC

`);
console.log("📦 [SMA_HISTORY_API] fetched data", {
  userId,
  userName,
  accountNumber,
  count: result.recordset?.length || 0,
  data: result.recordset
});
console.log("✅ [SMA_HISTORY_API] success", {
  count: result.recordset?.length || 0
});

console.log("📤 [SMA_HISTORY_API] response sent", {
  count: result.recordset?.length || 0
});

    res.json(result.recordset);

  } catch (err) {

console.log("❌ [SMA_HISTORY_API] error", {
  message: err.message,
  stack: err.stack,
  accountNumber
});

    res.status(500).send("Server error");

  }
});
// =========================== LEAD STATUS ===========================
app.get("/api/leads/status/:userId", async (req, res) => {
  const { userId } = req.params;

  console.log("📥 [LEADS_API] status request", { userId });

  try {
    const pool = await poolPromise;

    console.log("📊 [LEADS_API] Fetching lead status", { userId });

    const result = await pool.request()
      .input("UserId", sql.VarChar(50), userId)
      .query(`
        SELECT
          L.SNo,
          ISNULL(LASTLOG.ActionCode,'PENDING') AS ActionCode
        FROM Leads_Data L
        OUTER APPLY (
          SELECT TOP 1 ActionCode
          FROM Activity_Logs
          WHERE SourceType = 'LEAD'
            AND SourceId = L.SNo
            AND CreatedByUserId = @UserId
          ORDER BY LogId DESC
        ) LASTLOG
        WHERE L.UserID = @UserId
      `);

    console.log("✅ [LEADS_API] status fetched", {
      count: result.recordset.length
    });

    console.log("📦 [LEADS_API] status data", result.recordset);
    console.log("📤 [LEADS_API] sending response");

    res.json(result.recordset);

  } catch (err) {
    console.error("❌ [LEADS_API] status error:", {
      message: err.message,
      stack: err.stack,
      userId
    });

    res.status(500).send("Server error");
  }
});

//================================== EDIT IN PROCESS =========================================================

app.post("/api/recovery/reset-today", async (req, res) => {

console.log("📥 /api/recovery/reset-today request", {
loanAccountNumber: req.body.loanAccountNumber,
type: req.body.type,
userName: req.body.userName
});
  try {

    const { loanAccountNumber, type } = req.body;

console.log("⚠️ Validation check", {
loanAccountNumber,
type
});

console.log("📊 Processing reset today", {
loanAccountNumber,
type
});

    const pool = await poolPromise;

console.log("📊 Fetching existing schedule");

    // STEP 1 — get current values
    const existing = await pool.request()
      .input("loanAccountNumber", sql.VarChar(50), loanAccountNumber)
      .query(`
        SELECT 
          AssignmentId,
          UserId,
          ScheduleCallTimestamp,
          ScheduleVisitTimestamp
        FROM CallRecovery_Status
        WHERE LoanAccountNumber = @loanAccountNumber
        AND InProcessFlag = 1
      `);

    if (!existing.recordset.length) {

console.log("❌ No active schedule found", loanAccountNumber);

      return res.json({ success: false });
    }

    const row = existing.recordset[0];
console.log("📊 Existing schedule", {
prevCall: row.ScheduleCallTimestamp,
prevVisit: row.ScheduleVisitTimestamp,
userId: row.UserId
});

    let updateQuery = "";
    let newCall = null;
    let newVisit = null;

    if (type === "CALL") {

console.log("📊 Reset type CALL");

      updateQuery = `
        UPDATE CallRecovery_Status
        SET
          ScheduleCallTimestamp = GETDATE(),
          ScheduleVisitTimestamp = NULL,

          ScheduleCallPendingFlag = 1,
          ScheduleCallCompletedFlag = 0,

          ScheduleVisitPendingFlag = 0,
          ScheduleVisitCompletedFlag = 0,

          LastActionCode = 'RESET_TO_CALL',
          LastActionLabel = 'Reset to Call Today',
          UpdatedAt = GETDATE()

        WHERE LoanAccountNumber = @loanAccountNumber
        AND InProcessFlag = 1
      `;

      newCall = new Date();
    }

    if (type === "VISIT") {

console.log("📊 Reset type VISIT");

      updateQuery = `
        UPDATE CallRecovery_Status
        SET
          ScheduleVisitTimestamp = GETDATE(),
          ScheduleCallTimestamp = NULL,

          ScheduleVisitPendingFlag = 1,
          ScheduleVisitCompletedFlag = 0,

          ScheduleCallPendingFlag = 0,
          ScheduleCallCompletedFlag = 0,

          LastActionCode = 'RESET_TO_VISIT',
          LastActionLabel = 'Reset to Visit Today',
          UpdatedAt = GETDATE()

        WHERE LoanAccountNumber = @loanAccountNumber
        AND InProcessFlag = 1
      `;

      newVisit = new Date();
    }

console.log("📊 Updating main schedule table");

    // STEP 2 — update main table
    await pool.request()
      .input("loanAccountNumber", sql.VarChar(50), loanAccountNumber)
      .query(updateQuery);

console.log("📊 Inserting reset history log");

    // STEP 3 — insert log
    await pool.request()
      .input("loanAccountNumber", sql.VarChar(50), loanAccountNumber)
      .input("assignmentId", sql.Int, row.AssignmentId)
      .input("userId", sql.VarChar(50), row.UserId)
      .input("type", sql.VarChar(10), type)
      .input("prevCall", sql.DateTime, row.ScheduleCallTimestamp)
      .input("prevVisit", sql.DateTime, row.ScheduleVisitTimestamp)
      .input("newCall", sql.DateTime, newCall)
      .input("newVisit", sql.DateTime, newVisit)
      .query(`
        INSERT INTO Reset_For_Today_Log (
          LoanAccountNumber,
          AssignmentId,
          UserId,
          ResetType,
          PreviousCallTimestamp,
          PreviousVisitTimestamp,
          NewCallTimestamp,
          NewVisitTimestamp
        )
        VALUES (
          @loanAccountNumber,
          @assignmentId,
          @userId,
          @type,
          @prevCall,
          @prevVisit,
          @newCall,
          @newVisit
        )
      `);

console.log("✅ Reset today success", {
loanAccountNumber,
type,
userId: row.UserId
});

console.log("📤 /api/recovery/reset-today response sent", {
loanAccountNumber,
type,
userId: row.UserId
});
    res.json({ success: true });

  } catch (err) {

console.log("❌ /api/recovery/reset-today error", err);

    res.status(500).json({ message: "Server error" });
  }
});
//============================VISIT NEARBY CUSTOMERS=========================================
async function getCoordsFromAddress(address) {
  try {
    const response = await axios.get(
      "https://maps.googleapis.com/maps/api/geocode/json",
      {
        params: {
          address: address,
         key: process.env.GOOGLE_API_KEY,
        },
      }
    );

    if (response.data.status === "OK") {
      const loc = response.data.results[0].geometry.location;
      return {
        latitude: loc.lat,
        longitude: loc.lng,
      };
    }

    return null;
  } catch (err) {
    console.log("Geocode error:", err.message);
    return null;
  }
}


async function getRoadDistance(originLat, originLng, destLat, destLng) {
  try {
    const response = await axios.get(
      "https://maps.googleapis.com/maps/api/distancematrix/json",
      {
        params: {
          origins: `${originLat},${originLng}`,
          destinations: `${destLat},${destLng}`,
          key: process.env.GOOGLE_API_KEY,
          mode: "driving",
        },
      }
    );

    const element = response.data.rows[0].elements[0];

    if (element.status === "OK") {
      return {
        distanceKm: element.distance.value / 1000,
        duration: element.duration.text,
      };
    }

    return null;
  } catch (err) {
    console.log("Distance API error:", err.message);
    return null;
  }
}
//==================================VISIT NEARBY CUSTOMERS=========================================


app.get("/nearby-customers", async (req, res) => {

console.log("📥 /nearby-customers request", {
lat: req.query.lat,
lng: req.query.lng,
userId: req.query.userId,
userName: req.query.userName
});
  try {
    const { lat, lng, userId, userName } = req.query;
    const radius = 2; // KM

console.log("⚠️ Validation check", { lat, lng, userId });

    if (!lat || !lng || !userId) {
console.log("❌ Missing lat/lng/userId");
      return res.status(400).json({ message: "lat, lng, userId required" });
    }

console.log("📊 Processing nearby customers", {
lat,
lng,
userId,
userName
});
    const pool = await poolPromise;

console.log("📊 Fetching assigned customers");

    const result = await pool.request()
      .input("UserId", sql.VarChar(50), String(userId))
      .query(`
       SELECT 
  R.loanAccountNumber,
  R.firstname,
  R.gp,
  R.pincode,

  CASE 
    WHEN CRS.CompleteFlag = 1 THEN 'COMPLETED'
    WHEN CRS.InProcessFlag = 1 THEN 'IN PROCESS'
    ELSE 'PENDING'
  END AS AccountStatus
        FROM Recovery_Raw_Data R
        INNER JOIN Account_Assignments A
          ON A.LoanAccountNumber = R.loanAccountNumber
		  LEFT JOIN CallRecovery_Status CRS
  ON CRS.LoanAccountNumber = R.loanAccountNumber
    WHERE
  A.AssignedToUserId = @UserId
  AND A.AssignmentStatus = 'Assigned'
AND ISNULL(CRS.CompleteFlag, 0) = 0
      `);

    const rows = result.recordset;
console.log("📦 Assigned customers data", rows);
console.log("📊 Assigned customers count", rows.length);

    const nearby = [];

    for (const row of rows) {

      const address =
        `${row.gp || ""}, ${row.pincode || ""}, Andhra Pradesh, India`;

console.log("📍 Checking address", address);

      // Step 1: Get customer lat/lng
      const coords = await getCoordsFromAddress(address);
      if (!coords) {
console.log("⚠️ No coords found", address);
continue;
}

      // Step 2: Get GOOGLE ROAD DISTANCE
      const road = await getRoadDistance(
        lat,
        lng,
        coords.latitude,
        coords.longitude
      );

      if (!road) {
console.log("⚠️ No road distance", address);
continue;
}

      const distance = road.distanceKm;

      // Step 3: filter within radius
      if (distance <= radius) {

console.log("✅ Nearby customer", row.loanAccountNumber, distance);

       nearby.push({
  loanAccountNumber: row.loanAccountNumber,
  customerName: row.firstname,
  address: address,
  distance: distance,
  duration: road.duration,
  AccountStatus: row.AccountStatus   // ⭐ ADD THIS
});
      }
    }

console.log("📊 Nearby customers before sort", nearby.length);

    // Step 4: sort nearest first
    nearby.sort((a, b) => a.distance - b.distance);

console.log("📊 Nearby customers sorted");

console.log("📤 /nearby-customers response sent", nearby.length);
console.log("📦 Nearby customers response data", nearby);
    res.json(nearby);

  } catch (err) {

console.log("❌ /nearby-customers error", err);

    res.status(500).json({ message: "Server error" });
  }
});
//================================== FUTURE / PAST SCHEDULED LIST ==================================
app.post("/api/recovery/scheduled-list", async (req, res) => {

console.log("📥 /api/recovery/scheduled-list request", req.body);

  try {
    const { type, userId, userName } = req.body;

console.log("⚠️ Validation check", {
  userId,
  userName,
  type
});
    const pool = await poolPromise;
    const request = pool.request();

    request.input("userId", sql.VarChar(50), userId);

    let dateCondition = "";

    if (type === "FUTURE") {

console.log("📊 Fetching FUTURE scheduled accounts");

      dateCondition = `
        (
          (CRS.ScheduleCallTimestamp IS NOT NULL 
           AND CAST(CRS.ScheduleCallTimestamp AS DATE) > CAST(GETDATE() AS DATE))
          OR
          (CRS.ScheduleVisitTimestamp IS NOT NULL 
           AND CAST(CRS.ScheduleVisitTimestamp AS DATE) > CAST(GETDATE() AS DATE))
        )
      `;
    }

    if (type === "PAST") {

console.log("📊 Fetching PAST scheduled accounts");

      dateCondition = `
        (
          (CRS.ScheduleCallTimestamp IS NOT NULL 
           AND CAST(CRS.ScheduleCallTimestamp AS DATE) < CAST(GETDATE() AS DATE))
          OR
          (CRS.ScheduleVisitTimestamp IS NOT NULL 
           AND CAST(CRS.ScheduleVisitTimestamp AS DATE) < CAST(GETDATE() AS DATE))
        )
      `;
    }

console.log("📊 Executing scheduled list query");

    const query = `
      SELECT
        R.firstname,
        R.loanAccountNumber AS LoanAccountNumber,
        R.mobileNumber,
        R.OVERDUEAMT AS overdueAmount,
        0 AS AttemptCount,
        'IN PROCESS' AS AccountStatus,
        CRS.ScheduleCallTimestamp,
        CRS.ScheduleVisitTimestamp
      FROM CallRecovery_Status CRS
      INNER JOIN Recovery_Raw_Data R
        ON R.loanAccountNumber = CRS.LoanAccountNumber
      WHERE CRS.UserId = @userId
      AND CRS.InProcessFlag = 1
      AND ${dateCondition}
      ORDER BY CRS.UpdatedAt DESC
    `;

    const result = await request.query(query);
console.log("📦 Scheduled list fetched data", {
  userId,
  userName,
  records: result.recordset
});
console.log("✅ Scheduled list success", {
  userId,
  userName,
  count: result.recordset.length
});
console.log("📤 /api/recovery/scheduled-list response sent", result.recordset.length);

    res.json({
      success: true,
      records: result.recordset
    });

  } catch (err) {

console.log("❌ /api/recovery/scheduled-list error", err);

    res.status(500).json({ message: "Server error" });
  }
});


//==================================================================================================================================================================================
//                                                                         --------------------------------------------------------------------
//==================================================================================================================================================================================


// ================= ALL BRANCHES =================
app.get("/api/branches", async (req, res) => {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query(`
      SELECT branch_code, branch_name
      FROM dbo.Branch_Cluster_Master
      WHERE branch_name <> 'Corporate Office'
      ORDER BY branch_name
    `);

    res.status(200).json(result.recordset);

  } catch (err) {
    console.error("❌ BRANCH API ERROR:", err);
    res.status(500).json({ message: "Failed to fetch branches" });
  }
});

//============================================================================================
//                                CLUSTER MASTER LIST
//============================================================================================
app.get("/api/clusters", async (req, res) => {
  try {
    const pool = await poolPromise;

    const result = await pool.query(`
      SELECT DISTINCT cluster_name
      FROM dbo.Branch_Cluster_Master
      WHERE cluster_name IS NOT NULL
      ORDER BY cluster_name
    `);

    res.status(200).json(result.recordset);
  } catch (error) {
    console.error("❌ CLUSTER API ERROR:", error);
    res.status(500).json({ message: "Failed to fetch clusters" });
  }
});

// ================= CLUSTER BRANCHES =================
app.get("/api/branches/:clusterName", async (req, res) => {
  const { clusterName } = req.params;

  try {
    const pool = await poolPromise;

    if (clusterName === "Corporate Office") {
      const result = await pool.request().query(`
        SELECT branch_code, branch_name
        FROM dbo.Branch_Cluster_Master
        WHERE branch_name <> 'Corporate Office'
        ORDER BY branch_name
      `);

      return res.status(200).json(result.recordset);
    }

    const result = await pool.request()
      .input("cluster_name", sql.VarChar, clusterName)
      .query(`
        SELECT branch_code, branch_name
        FROM dbo.Branch_Cluster_Master
        WHERE cluster_name = @cluster_name
        AND branch_name <> 'Corporate Office'
        ORDER BY branch_name
      `);

    res.status(200).json(result.recordset);

  } catch (err) {
    console.error("❌ BRANCH API ERROR:", err);
    res.status(500).json({ message: "Failed to fetch branches" });
  }
});

//============================================================================================
//                                CSV FILE DATA UPLOAD + DAILY COMPARISON
//============================================================================================
app.post("/api/recovery-upload", async (req, res) => {
  const startTime = Date.now();
  logInfo("Recovery Upload API called");
  const { records } = req.body;

   if (!records || !Array.isArray(records)) {
  logWarn("Invalid records format received", req.body);
    return res.status(400).json({ message: "Invalid JSON format" });
  }

  try {
    const pool = await poolPromise;
	
	const userId = req.headers["x-user-id"];
  logInfo("User ID received", userId);

  if (!userId) {
  logWarn("Unauthorized request - missing userId");
  return res.status(401).json({ message: "Unauthorized" });
}

logInfo("Fetching user role from DB");
// Fetch user role from DB
const roleResult = await pool.request()
  .input("userId", sql.VarChar(50), userId)
  .query(`
    SELECT Role 
    FROM UsersInfo
    WHERE UserId = @userId
  `);

if (!roleResult.recordset.length) {
  logWarn("User not found in DB", userId);
  return res.status(403).json({ message: "User not found" });
}

const userRole = roleResult.recordset[0].Role;
logInfo("User role fetched", userRole);

if (
  userRole === "Branch Manager" ||
  userRole.startsWith("Regional Manager")
) {
  logWarn("Access denied for user role", userRole);
  return res.status(403).json({
    message: "Access Denied. Please Contact Admin."
  });
}

    const todayCount = records.length;
    logInfo("Records received for upload", todayCount);

    // ------------------------------------------------------------------
    // STEP 1 — Get yesterday upload count (from log table)
    // ------------------------------------------------------------------
    logInfo("Fetching yesterday upload count");
    const yesterdayRes = await pool.request().query(`
      SELECT TOP 1 record_count
      FROM Recovery_Upload_Log
      WHERE upload_date < CAST(GETDATE() AS DATE)
      ORDER BY upload_date DESC
    `);

    const yesterdayCount = yesterdayRes.recordset.length
  ? yesterdayRes.recordset[0].record_count
  : 0;

logInfo("Yesterday count", yesterdayCount);

    // ------------------------------------------------------------------
    // STEP 2 — Backup current active data (HISTORY = BACKUP ONLY)
    // ------------------------------------------------------------------
    const oldCountRes = await pool.request()
  .query(`SELECT COUNT(*) AS cnt FROM Recovery_Raw_Data`);

logInfo("Checking existing data before backup");

if (oldCountRes.recordset[0].cnt > 0) {
  logInfo("Backing up existing data to history table");  // ✅ ADD THIS LINE

  await pool.request().query(`
    INSERT INTO Recovery_Raw_Data_history (
          firstname, dob, gender, religion, socialcategory, voterId,
          drivingLicense, rationCard, pancard, gp, pincode, village,
          branchCode, branchName, fathersName, product, mobileNumber,
          loanAccountNumber, dpdQueue, currentOutstandingBalance,
          principleDue, interestDue, interestRate, lastInterestAppliedDate,
          npaDate, EMIAMOUNT, OVERDUEAMT, extra, uploadtimestamp
        )
        SELECT firstname, dob, gender, religion, socialcategory, voterId,
          drivingLicense, rationCard, pancard, gp, pincode, village,
          branchCode, branchName, fathersName, product, mobileNumber,
          loanAccountNumber, dpdQueue, currentOutstandingBalance,
          principleDue, interestDue, interestRate, lastInterestAppliedDate,
          npaDate, EMIAMOUNT, OVERDUEAMT, extra, GETDATE()
        FROM Recovery_Raw_Data
      `);

      await pool.request().query(`TRUNCATE TABLE Recovery_Raw_Data`);
    }

    // ------------------------------------------------------------------
    // STEP 3 — Bulk insert TODAY data
    // ------------------------------------------------------------------
    const table = new sql.Table("Recovery_Raw_Data");
    table.create = false;

    table.columns.add('firstname', sql.NVarChar(100));
    table.columns.add('dob', sql.Date);
    table.columns.add('gender', sql.NVarChar(50));
    table.columns.add('religion', sql.NVarChar(100));
    table.columns.add('socialcategory', sql.NVarChar(100));
    table.columns.add('voterId', sql.NVarChar(50));
    table.columns.add('drivingLicense', sql.NVarChar(50));
    table.columns.add('rationCard', sql.NVarChar(50));
    table.columns.add('pancard', sql.NVarChar(50));
    table.columns.add('gp', sql.NVarChar(sql.MAX));
    table.columns.add('pincode', sql.NVarChar(10));
    table.columns.add('village', sql.NVarChar(100));
    table.columns.add('branchCode', sql.NVarChar(50));
    table.columns.add('branchName', sql.NVarChar(100));
    table.columns.add('fathersName', sql.NVarChar(100));
    table.columns.add('product', sql.NVarChar(100));
    table.columns.add('mobileNumber', sql.NVarChar(15));
    table.columns.add('loanAccountNumber', sql.NVarChar(50));
    table.columns.add('dpdQueue', sql.NVarChar(50));
    table.columns.add('currentOutstandingBalance', sql.Decimal(18,2));
    table.columns.add('principleDue', sql.Decimal(18,2));
    table.columns.add('interestDue', sql.Decimal(18,2));
    table.columns.add('interestRate', sql.Decimal(5,2));
    table.columns.add('lastInterestAppliedDate', sql.Date);
    table.columns.add('npaDate', sql.Date);
    table.columns.add('EMIAMOUNT', sql.Decimal(18,2));
    table.columns.add('OVERDUEAMT', sql.Decimal(18,2));
    table.columns.add('extra', sql.NVarChar(sql.MAX));

    records.forEach(r => {
      table.rows.add(
        r.firstname, r.dob, r.gender, r.religion, r.socialcategory,
        r.voterId, r.drivingLicense, r.rationCard, r.pancard, r.gp,
        r.pincode, r.village, r.branchCode, r.branchName, r.fathersName,
        r.product, r.mobileNumber, r.loanAccountNumber, r.dpdQueue,
        parseFloat(r.currentOutstandingBalance) || 0, r.principleDue, r.interestDue,
        r.interestRate, r.lastInterestAppliedDate, r.npaDate,
        r.EMIAMOUNT, r.OVERDUEAMT, r.extra
      );
    });

    await pool.request().bulk(table);
    logSuccess("Bulk insert completed", { inserted: todayCount });
	
// ------------------------------------------------------------------
// STEP 4 — Also store NEW upload into History table
// ------------------------------------------------------------------
logInfo("Storing uploaded data into history table");
await pool.request().query(`
  INSERT INTO Recovery_Raw_Data_history (
    firstname, dob, gender, religion, socialcategory, voterId,
    drivingLicense, rationCard, pancard, gp, pincode, village,
    branchCode, branchName, fathersName, product, mobileNumber,
    loanAccountNumber, dpdQueue, currentOutstandingBalance,
    principleDue, interestDue, interestRate, lastInterestAppliedDate,
    npaDate, EMIAMOUNT, OVERDUEAMT, extra, uploadtimestamp
  )
  SELECT firstname, dob, gender, religion, socialcategory, voterId,
    drivingLicense, rationCard, pancard, gp, pincode, village,
    branchCode, branchName, fathersName, product, mobileNumber,
    loanAccountNumber, dpdQueue, currentOutstandingBalance,
    principleDue, interestDue, interestRate, lastInterestAppliedDate,
    npaDate, EMIAMOUNT, OVERDUEAMT, extra, GETDATE()
  FROM Recovery_Raw_Data
`);

    // ------------------------------------------------------------------
// STEP 5 — Insert EVERY upload into log table
// ------------------------------------------------------------------
logInfo("Inserting upload log into Recovery_Upload_Log");
await pool.request()
  .input("cnt", sql.Int, todayCount)
  .query(`
    INSERT INTO Recovery_Upload_Log 
    (upload_date, record_count, uploaded_at)
    VALUES 
    (CAST(GETDATE() AS DATE), @cnt, GETDATE())
  `);

// ------------------------------------------------------------------
// STEP 6 — Get LAST upload BEFORE today (NOT today)
// ------------------------------------------------------------------
logInfo("Fetching previous upload count");
const prevRes = await pool.request().query(`
  SELECT TOP 1 record_count
  FROM Recovery_Upload_Log
  WHERE upload_date < CAST(GETDATE() AS DATE)
  ORDER BY uploaded_at DESC
`);

const previousCount =
  prevRes.recordset.length
    ? prevRes.recordset[0].record_count
    : 0;

logInfo("Previous count", previousCount);

// ------------------------------------------------------------------
// STEP 7 — Calculate difference
// ------------------------------------------------------------------
const archived =
  todayCount < previousCount
    ? previousCount - todayCount
    : 0;

const newRecords =
  todayCount > previousCount
    ? todayCount - previousCount
    : 0;

logSuccess("Upload comparison calculated", {
  today: todayCount,
  previous: previousCount,
  newRecords,
  archived
});

    // ------------------------------------------------------------------
    // FINAL RESPONSE (USED BY FRONTEND MODAL)
    // ------------------------------------------------------------------
    logInfo("API execution time (ms)", Date.now() - startTime);
    logSuccess("Upload API completed successfully");
    res.status(200).json({
      success: true,
      message: "Upload completed successfully",
      archived,
      uploaded: newRecords,
      history_total: todayCount
    });

  } catch (err) {
  logError("Recovery Upload API failed", {
  message: err.message,
  stack: err.stack
});
    res.status(500).json({ message: "Internal Server Error", error: err.message });
  }
});


//============================================================================================
//                          FILE UPLOAD STATUS (FINAL CORRECT LOGIC)
//============================================================================================
app.get("/api/recovery-upload-status", async (req, res) => {
const startTime = Date.now();
  logInfo("Upload Status API called");
  try {

    const pool = await poolPromise;

    const userId = req.headers["x-user-id"];
    logInfo("User ID received", userId);

if (!userId) {
  logWarn("Unauthorized request - missing userId");
      return res.status(401).json({ message: "Unauthorized" });
    }

    logInfo("Fetching user role for status API");
    // 🔹 Fetch user role
    const roleResult = await pool.request()
      .input("userId", sql.VarChar(50), userId)
      .query(`
        SELECT Role 
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    if (!roleResult.recordset.length) {
  logWarn("User not found in DB", userId);
  return res.status(403).json({ message: "User not found" });
}
    const userRole = roleResult.recordset[0].Role;
    logInfo("User role fetched", userRole);

    if (
  userRole === "Branch Manager" ||
  userRole.startsWith("Regional Manager")
) {
  logWarn("Access denied for status API", userRole);
      return res.status(403).json({
        message: "Access Denied. Please Contact Admin."
      });
    }

    // ============================================================
    // 🔹 STEP 1 — Get latest upload
    // ============================================================
    logInfo("Fetching latest upload data");
    const latestRes = await pool.request().query(`
      SELECT TOP 1 record_count, uploaded_at
      FROM Recovery_Upload_Log
      ORDER BY uploaded_at DESC
    `);

    const latestDate = latestRes.recordset.length
      ? latestRes.recordset[0].uploaded_at
      : null;

    const today = latestRes.recordset.length
      ? latestRes.recordset[0].record_count
      : 0;

    // ============================================================
    // 🔹 STEP 2 — Get previous upload from DIFFERENT DATE
    // ============================================================
    logInfo("Fetching previous upload data");
    const prevRes = await pool.request()
      .input("latestDate", sql.DateTime, latestDate)
      .query(`
        SELECT TOP 1 record_count
        FROM Recovery_Upload_Log
        WHERE CAST(uploaded_at AS DATE) < CAST(@latestDate AS DATE)
        ORDER BY uploaded_at DESC
      `);

    const previous = prevRes.recordset.length
      ? prevRes.recordset[0].record_count
      : 0;

    // ============================================================
    // 🔹 STEP 3 — Calculate difference
    // ============================================================
    const archived = today < previous ? previous - today : 0;
    const uploaded = today > previous ? today - previous : 0;

    // ============================================================
    // 🔹 RESPONSE
    // ============================================================
logInfo("API execution time (ms)", Date.now() - startTime);
    logSuccess("Status calculated", {
  today,
  previous,
  archived,
  uploaded
});

res.json({
  archived,
  uploaded,
  history_total: today
});

  } catch (err) {
  logError("Upload Status API failed", {
  message: err.message,
  stack: err.stack
});
    res.status(500).json({ message: "Internal Server Error" });
  }
});


//============================================================================================
//                                TRANSACTION SEARCH API
//============================================================================================
app.post("/api/transaction/search", async (req, res) => {
	
	const userId = req.headers["x-user-id"];
const startTime = Date.now();


if (!userId) {
  return res.status(401).json({ message: "Unauthorized" });
}
	
  const {
    mobileNumber,
    cluster,
    pincode,
    branchName,
    product,
    assignedTo,
    loanAccount,
    queue,
    dpdQueue,
    memberName
  } = req.body;

console.log("🔍 [SEARCH API HIT]", {
  userId,
  body: {
    mobileNumber,
    loanAccount,
    memberName,
    cluster,
    branchName
  }
});

console.log("📋 Filters Applied:", {
  mobileNumber,
  cluster,
  branchName,
  product,
  assignedTo,
  queue,
  dpdQueue
});

const isDirectSearch =
  (loanAccount && loanAccount.trim() !== "") ||
  (mobileNumber && mobileNumber.trim() !== "") ||
  (memberName && memberName.trim() !== "");


  try {
	  
    const pool = await poolPromise;

// 🔥 Get logged-in user role & branch
const userInfo = await pool.request()
  .input("userId", sql.VarChar, userId)
  .query(`
    SELECT Role, BranchName, ClusterName
FROM smart_call.dbo.UsersInfo
WHERE UserId = @userId
  `);

if (!userInfo.recordset.length) {
  console.warn("❌ User not found for ID:", userId);
  return res.status(403).json({ message: "User not found" });
}

console.log("👤 User Info:", userInfo.recordset[0]);

const { Role, BranchName: userBranch } = userInfo.recordset[0];

const isBranchManager = Role === "Branch Manager";
const isRegionalManager = Role?.startsWith("Regional Manager");

// 🔥 Extract cluster from role
let userCluster = null;

if (isRegionalManager) {
  const match = Role.match(/\((.*?)\)/);
  if (match) {
    userCluster = match[1];
  }
}


    let query = `
  SELECT 
    R.firstname AS firstName,
    R.loanAccountNumber AS accountNumber,
    R.product,
    R.mobileNumber,
    R.branchName AS branch,
    CASE 
      WHEN EXISTS (
        SELECT 1 FROM Account_Assignments A
        WHERE A.LoanAccountNumber = R.loanAccountNumber
          AND A.AssignmentStatus = 'Assigned'
      ) THEN 'Assigned'
      ELSE 'Not Assigned'
    END AS status
  FROM dbo.Recovery_Raw_Data R
  WHERE 1=1
`;

  
    const request = pool.request();
	
	// 🔒 FORCE BRANCH RESTRICTION FOR BRANCH MANAGER
if (isBranchManager) {
  query += ` AND R.branchName = @restrictedBranch`;
  request.input("restrictedBranch", sql.VarChar, userBranch);
}

// 🔒 Regional Manager restriction
if (isRegionalManager) {
  query += ` AND R.branchName IN (
    SELECT branch_name
    FROM Branch_Cluster_Master
    WHERE cluster_name = @restrictedCluster
  )`;

  request.input("restrictedCluster", sql.VarChar, userCluster);
}

    if (mobileNumber) {
      query += ` AND mobileNumber = @mobileNumber`;
      request.input("mobileNumber", sql.VarChar, mobileNumber);
    }

    if (pincode) {
      query += ` AND pincode = @pincode`;
      request.input("pincode", sql.VarChar, pincode);
    }

    if (branchName) {
   query += ` AND R.branchName LIKE @branchName`;
       request.input("branchName", sql.VarChar, `%${branchName}%`);
    }

    if (product) {
      query += ` AND product = @product`;
      request.input("product", sql.VarChar, product);
    }

    if (loanAccount) {
      query += ` AND loanAccountNumber = @loanAccount`;
      request.input("loanAccount", sql.VarChar, loanAccount);
    }

    if (memberName && memberName.trim() !== "") {
  query += ` AND R.firstname LIKE @memberName`;
  request.input("memberName", sql.VarChar, `%${memberName.trim()}%`);
}

// ================= Queue Filter =================
if (queue === "NPA") {
  query += ` AND R.dpdQueue >= '04'`;
}

    if (dpdQueue) {
  switch (dpdQueue) {
    case "0-30":
      query += ` AND dpdQueue = '01'`;
      break;
    case "31-60":
      query += ` AND dpdQueue = '02'`;
      break;
    case "61-90":
      query += ` AND dpdQueue = '03'`;
      break;
    case "90+":
      query += ` AND dpdQueue >= '04'`;
      break;
  }
}

if (assignedTo) {
  // Show only assigned records for selected user
  query += ` AND loanAccountNumber IN (
    SELECT LoanAccountNumber
    FROM Account_Assignments
    WHERE AssignedToUserId = @assignedTo
      AND AssignmentStatus = 'Assigned'
  )`;
  request.input("assignedTo", sql.VarChar, assignedTo);
}
else if (!isDirectSearch) {
  // Hide assigned accounts in normal search
  query += ` AND loanAccountNumber NOT IN (
    SELECT LoanAccountNumber
    FROM Account_Assignments
    WHERE AssignmentStatus = 'Assigned'
  )`;
}

    // 🌟 Cluster filter works through branch master mapping
    if (cluster && cluster !== "Corporate Office") {
  query += ` AND R.branchName IN (
    SELECT branch_name
    FROM Branch_Cluster_Master
    WHERE cluster_name = @cluster
  )`;
  request.input("cluster", sql.VarChar, cluster);
}

console.log("📡 Executing Search Query...");
console.log("🧾 Final Query:", query);
const dbStart = Date.now();
    const result = await request.query(query);
console.log("⏱ DB Time:", Date.now() - dbStart, "ms");
console.log("✅ Search Success:", {
  count: result.recordset.length
});

console.log("⏱ Search API Time:", Date.now() - startTime, "ms");
    return res.status(200).json(result.recordset);

  } catch (error) {
    console.error("❌ SEARCH API ERROR:", {
  userId,
  filters: {
  mobileNumber,
  loanAccount,
  memberName,
  cluster,
  branchName
},
  message: error.message,
  stack: error.stack
});
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/assignUsers", async (req, res) => {
  try {
console.log("📡 [AssignUsers API HIT]", {
  branchName: req.body.branchName,
  cluster: req.body.cluster
});
    const pool = await poolPromise;
    const { branchName, cluster } = req.body;

    let query = `
      SELECT 
        UserId AS userId,
        UserName AS name,
        BranchName AS branchName,
        ClusterName AS clusterName,
        Role AS role,
        BranchCode AS branchCode
      FROM UsersInfo
      WHERE 1 = 1
    `;

    const request = pool.request();

    if (cluster && cluster !== "") {
      query += ` AND ClusterName = @cluster`;
      request.input("cluster", cluster);
    }

    if (branchName && branchName !== "") {
      query += ` AND BranchName = @branchName`;
      request.input("branchName", branchName);
    }

console.log("📡 AssignUsers Query:", query);
    const result = await request.query(query);
console.log("✅ AssignUsers Success:", result.recordset.length);
    res.json(result.recordset);

  } catch (err) {
    console.error("❌ AssignUsers Error:", {
  body: req.body,
  message: err.message
});
    res.status(500).json({ message: "Server Error" });
  }
});

app.get("/api/branches", async (req, res) => {
  const result = await pool.request().query(`
    SELECT branch_code AS branchId,
           branch_name AS branchName
    FROM Branch_Cluster_Master
    ORDER BY branch_name
  `);
  res.json(result.recordset);
});


app.post("/api/assign", async (req, res) => {
  const { loanIds, assignedToUserId } = req.body;

// 🔥 GET LOGGED-IN ADMIN FROM REQUEST HEADER
const assignedByAdminId = req.headers["x-user-id"];

console.log("📌 [ASSIGN API HIT]", {
  loanIds,
  assignedToUserId,
  assignedByAdminId
});

if (!assignedByAdminId) {
  return res.status(400).json({ message: "Admin ID missing in header" });
}


  if (!Array.isArray(loanIds) || loanIds.length === 0 || !assignedToUserId || !assignedByAdminId) {
    return res.status(400).json({ message: "Invalid request data" });
  }

  let transaction;

  try {
    const pool = await poolPromise;
    transaction = new sql.Transaction(pool);
    await transaction.begin();

    /* ======================================================
       1️⃣ FETCH ASSIGNED USER DETAILS
    ====================================================== */
    const userReq = new sql.Request(transaction);
    userReq.input("userId", sql.VarChar, assignedToUserId);

    const userResult = await userReq.query(`
      SELECT 
        UserName,
        BranchName,
        BranchCode,
        ClusterName
      FROM UsersInfo
      WHERE UserId = @userId
    `);

    if (userResult.recordset.length === 0) {
      await transaction.rollback();
      return res.status(404).json({ message: "Assigned user not found" });
    }

    const {
      UserName: assignedToUserName,
      BranchName: userBranchName,
      BranchCode: userBranchCode,
      ClusterName: userClusterName
    } = userResult.recordset[0];
console.log("👤 Assigned To:", assignedToUserName);

    /* ======================================================
       2️⃣ FETCH ADMIN DETAILS (FOR AUDIT)
    ====================================================== */
    const adminReq = new sql.Request(transaction);
    adminReq.input("adminId", sql.VarChar, assignedByAdminId);

    const adminResult = await adminReq.query(`
      SELECT UserName
      FROM UsersInfo
      WHERE UserId = @adminId
    `);

    if (adminResult.recordset.length === 0) {
      await transaction.rollback();
      return res.status(404).json({ message: "Admin not found" });
    }

    const assignedByAdminName = adminResult.recordset[0].UserName;
console.log("👤 Assigned By:", assignedByAdminName);

    /* ======================================================
       3️⃣ FETCH & VALIDATE LOAN ACCOUNTS (SINGLE QUERY)
    ====================================================== */
    const loanReq = new sql.Request(transaction);
    loanIds.forEach((id, i) => {
      loanReq.input(`loanId${i}`, sql.VarChar, id);
    });

    const loanResult = await loanReq.query(`
      SELECT 
        loanAccountNumber,
        branchName,
        product
      FROM Recovery_Raw_Data
      WHERE loanAccountNumber IN (${loanIds.map((_, i) => `@loanId${i}`).join(",")})
    `);

    if (loanResult.recordset.length !== loanIds.length) {
      await transaction.rollback();
      return res.status(400).json({ message: "Some loan accounts not found" });
    }

   const invalidAccounts = loanResult.recordset
  .filter(r => r.branchName !== userBranchName)
  .map(r => r.loanAccountNumber);

    if (invalidAccounts.length > 0) {
      await transaction.rollback();
console.warn("❌ Invalid Accounts:", invalidAccounts);
      return res.status(400).json({
        message: "User is not related to this branch",
        invalidAccounts
      });
    }

    /* ======================================================
       4️⃣ UNASSIGN EXISTING ACTIVE ASSIGNMENTS
    ====================================================== */
    const unassignReq = new sql.Request(transaction);
    loanIds.forEach((id, i) => {
      unassignReq.input(`loanId${i}`, sql.VarChar, id);
    });

    await unassignReq.query(`
      UPDATE Account_Assignments
      SET 
        AssignmentStatus = 'Unassigned',
        UnassignedAt = GETDATE()
      WHERE LoanAccountNumber IN (${loanIds.map((_, i) => `@loanId${i}`).join(",")})
        AND AssignmentStatus = 'Assigned'
    `);

    /* ======================================================
       5️⃣ INSERT NEW ASSIGNMENTS
    ====================================================== */
    for (const row of loanResult.recordset) {
      const insertReq = new sql.Request(transaction);

      insertReq
        .input("loanId", sql.VarChar, row.loanAccountNumber)
        .input("assignedToUserId", sql.VarChar, assignedToUserId)
        .input("assignedToUserName", sql.VarChar, assignedToUserName)
        .input("assignedByAdminId", sql.VarChar, assignedByAdminId)
        .input("assignedByAdminName", sql.VarChar, assignedByAdminName)
        .input("branchCode", sql.VarChar, userBranchCode)
        .input("branchName", sql.VarChar, userBranchName)
        .input("clusterName", sql.VarChar, userClusterName)
        .input("product", sql.VarChar, row.product);

      await insertReq.query(`
        INSERT INTO Account_Assignments
        (
          LoanAccountNumber,
          AssignedToUserId,
          AssignedToUserName,
          AssignedByAdminId,
          AssignedByAdminName,
          BranchCode,
          BranchName,
          ClusterName,
          Product,
          AssignmentStatus,
          AssignedAt,
          WorkStatus
        )
        VALUES
        (
          @loanId,
          @assignedToUserId,
          @assignedToUserName,
          @assignedByAdminId,
          @assignedByAdminName,
          @branchCode,
          @branchName,
          @clusterName,
          @product,
          'Assigned',
          GETDATE(),
          'Pending'
        )
      `);
    }

    await transaction.commit();
console.log("✅ Assignment Success:", loanIds.length);
    return res.json({ message: "Accounts assigned successfully" });

  } catch (err) {
    if (transaction) await transaction.rollback();
    console.error("❌ ASSIGN API ERROR:", {
  loanIds,
  assignedToUserId,
  assignedByAdminId,
  message: err.message,
  stack: err.stack
});
    return res.status(500).json({ message: "Assignment failed" });
  }
});


//============================================================================================
//                         TRANSACTION VIEW DETAILS (READ ONLY)
//============================================================================================
app.get("/api/transaction/details/:loanAccountNumber", async (req, res) => {

  const userId = req.headers["x-user-id"];
console.log("👁 [VIEW DETAILS API HIT]", {
  userId,
  loanAccountNumber: req.params.loanAccountNumber
});

  if (!userId) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const { loanAccountNumber } = req.params;
console.log("📡 Fetching details for:", loanAccountNumber);

  if (!loanAccountNumber) {
    return res.status(400).json({ message: "Loan Account Number required" });
  }

  try {
    const pool = await poolPromise;

    // 🔥 Get user role + branch
    const userInfo = await pool.request()
      .input("userId", sql.VarChar, userId)
      .query(`
        SELECT Role, BranchName, ClusterName
FROM smart_call.dbo.UsersInfo
WHERE UserId = @userId
      `);

    if (!userInfo.recordset.length) {
      return res.status(403).json({ message: "User not found" });
    }

    const { Role, BranchName: userBranch } = userInfo.recordset[0];

let userCluster = null;

if (Role?.startsWith("Regional Manager")) {
  const match = Role.match(/\((.*?)\)/);
  if (match) {
    userCluster = match[1];
  }
}

const isRegionalManager = Role?.startsWith("Regional Manager");

    let query = `
      SELECT TOP 1
        firstname AS customerName,
        CONVERT(VARCHAR, dob, 105) AS dob,
        CASE 
          WHEN gender = 'M' THEN 'Male'
          WHEN gender = 'F' THEN 'Female'
          ELSE gender
        END AS gender,
        pancard AS panNumber,
        gp AS address,
        pincode,
        mobileNumber,
        loanAccountNumber,
        OVERDUEAMT AS outstandingAmount,
        interestDue,
        principleDue AS principalDue,
        interestRate
      FROM smart_call.dbo.Recovery_Raw_Data
      WHERE loanAccountNumber = @loanAccountNumber
    `;

    const request = pool.request();
    request.input("loanAccountNumber", sql.VarChar, loanAccountNumber);

    // 🔒 Restrict Branch Manager
    if (Role === "Branch Manager") {
      query += ` AND branchName = @restrictedBranch`;
      request.input("restrictedBranch", sql.VarChar, userBranch);
    }
	
	// 🔒 Regional Manager restriction
if (isRegionalManager) {
  query += ` AND branchName IN (
      SELECT branch_name
      FROM Branch_Cluster_Master
      WHERE cluster_name = @restrictedCluster
  )`;

  request.input("restrictedCluster", sql.VarChar, userCluster);
}

    const result = await request.query(query);

    if (!result.recordset.length) {
      return res.status(404).json({ message: "Record not found or access denied" });
    }

console.log("✅ View Details Success");
    return res.status(200).json(result.recordset[0]);

  } catch (err) {
    console.error("❌ VIEW DETAILS ERROR:", {
  loanAccountNumber,
  message: err.message
});
    return res.status(500).json({ message: "Failed to fetch transaction details" });
  }
});


// ============================================================
// TRANSACTION → EXPORT PDF (FINAL CLEAN STABLE VERSION)
// ============================================================

app.post("/api/transaction/export-pdf", async (req, res) => {
  const { selectedIds, columns, fileName, serialData } = req.body;
console.log("📄 [PDF API HIT]", {
  selectedIds,
  columns,
  fileName
});

  if (!selectedIds || selectedIds.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {
    const pool = await poolPromise;
    const request = pool.request();

    // Bind parameters safely
    selectedIds.forEach((id, index) => {
      request.input(`id${index}`, sql.VarChar, id);
    });

    // Preserve exact selected order
    const orderCase = selectedIds
      .map((id, index) => `WHEN R.loanAccountNumber = @id${index} THEN ${index}`)
      .join(" ");

    const result = await request.query(`
      SELECT 
        R.firstname AS firstName,
        R.loanAccountNumber AS accountNumber,
        R.product,
        R.mobileNumber,
        R.branchName AS branch,
        CASE 
          WHEN EXISTS (
            SELECT 1 
            FROM Account_Assignments A
            WHERE A.LoanAccountNumber = R.loanAccountNumber
              AND A.AssignmentStatus = 'Assigned'
          ) THEN 'Assigned'
          ELSE 'Not Assigned'
        END AS status
      FROM dbo.Recovery_Raw_Data R
      WHERE R.loanAccountNumber IN (${selectedIds.map((_, i) => `@id${i}`).join(",")})
      ORDER BY CASE ${orderCase} END
    `);

    const data = result.recordset || [];
console.log("📊 Records fetched for PDF:", data.length);
	
	// 🔴 If somehow no data found, stop PDF generation
if (data.length === 0) {
  return res.status(400).json({ message: "No records found for PDF" });
}
	
	// Attach serial numbers from frontend
if (serialData && Array.isArray(serialData)) {

  // Convert to map for fast lookup
  const serialMap = {};
  serialData.forEach(item => {
    serialMap[item.accountNumber] = item.serialNumber;
  });

  data.forEach(row => {
    row.serialNumber = serialMap[row.accountNumber] || "";
  });
}

console.log("📡 Generating PDF...");
    const PDFDocument = require("pdfkit");

    const doc = new PDFDocument({
      size: "A4",
      layout: "landscape",
      margin: 40
    });

    const safeName = (fileName || "Transaction_Report").replace(/\s+/g, "_");

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.pdf"`
    );

    doc.pipe(res);

    // ================= TITLE =================
    doc.font("Helvetica-Bold")
       .fontSize(16)
       .text("Transaction Report", { align: "center" });

    doc.moveDown(1);

    // ================= TABLE SETUP =================
    const pageWidth =
      doc.page.width - doc.page.margins.left - doc.page.margins.right;

    // Define custom column widths
const columnWidths = {};

columns.forEach(col => {
  if (col === "serialNumber") {
    columnWidths[col] = 50; // 👈 small width for S. No.
  } else {
    columnWidths[col] = null; // calculate later
  }
});

// Calculate remaining width
const usedWidth = Object.values(columnWidths)
  .filter(w => w !== null)
  .reduce((a, b) => a + b, 0);

const remainingCols = columns.filter(col => columnWidths[col] === null);
const remainingWidth = pageWidth - usedWidth;
const equalWidth = remainingWidth / remainingCols.length;

remainingCols.forEach(col => {
  columnWidths[col] = equalWidth;
});

    const rowHeight = 22;

    const COLUMN_LABELS = {
  serialNumber: "S. No.",
  firstName: "First Name",
  accountNumber: "Account Number",
  product: "Product",
  mobileNumber: "Mobile Number",
  branch: "Branch",
  status: "Status"
};

    let y = doc.y;

    // ================= DRAW HEADER =================
    const drawHeader = () => {
      let x = doc.page.margins.left;

      doc.font("Helvetica-Bold").fontSize(10);

      columns.forEach(col => {
        doc.rect(x, y, columnWidths[col], rowHeight)
           .fillAndStroke("#e2e8f0", "#94a3b8");

        doc.fillColor("#000")
           .text(COLUMN_LABELS[col], x + 5, y + 6, {
             width: columnWidths[col] - 10,
             align: "center"
           });

        x += columnWidths[col];
      });

      y += rowHeight;
      doc.font("Helvetica").fontSize(9);
    };

    drawHeader();

    // ================= ROWS =================
    data.forEach((row, index) => {

  let x = doc.page.margins.left;

  // 🔥 STEP 1: Calculate dynamic row height
  let dynamicHeight = 20;

  columns.forEach(col => {
    const text = String(row[col] ?? "");
    const textHeight = doc.heightOfString(text, {
      width: columnWidths[col] - 10
    });

    dynamicHeight = Math.max(dynamicHeight, textHeight + 10);
  });

  // 🔥 STEP 2: Page break check
  if (y + dynamicHeight > doc.page.height - 40) {
    doc.addPage({
      size: "A4",
      layout: "landscape",
      margin: 40
    });
    y = doc.page.margins.top;
    drawHeader();
  }

  // 🔥 STEP 3: Alternate row shading
  if (index % 2 === 0) {
    doc.rect(x, y, pageWidth, dynamicHeight)
       .fill("#f8fafc");
  }

  // 🔥 STEP 4: Draw each cell
  columns.forEach(col => {

    doc.rect(x, y, columnWidths[col], dynamicHeight).stroke();

    doc.fillColor("#000")
       .text(String(row[col] ?? ""), x + 5, y + 5, {
         width: columnWidths[col] - 10,
         align: "center"
       });

    x += columnWidths[col];
  });

  y += dynamicHeight;
});

console.log("✅ PDF Generated Successfully");
    doc.end();

  } catch (err) {
    console.error("❌ PDF ERROR:", {
  selectedIds,
  message: err.message
});
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});


// ======================
// Assign To (Updated)
// ======================

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "x-user-id"]
}));


// ======================
// Assign Users (dropdown)
// ======================
app.post("/api/assignUsers/v2", async (req, res) => {
  try {

    const userId = req.headers["x-user-id"];

    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const { branchName, cluster } = req.body;

    const pool = await poolPromise;

    // Get logged-in user role
    const userInfo = await pool.request()
      .input("userId", sql.VarChar, userId)
      .query(`
        SELECT Role, BranchName, ClusterName
FROM smart_call.dbo.UsersInfo
WHERE UserId = @userId
      `);

    if (!userInfo.recordset.length) {
      return res.status(403).json({ message: "User not found" });
    }

const { Role, BranchName: userBranch } = userInfo.recordset[0];

const isRegionalManager = Role?.startsWith("Regional Manager");

// 🔥 Extract cluster from role
let userCluster = null;

if (isRegionalManager) {
  const match = Role.match(/\((.*?)\)/);
  if (match) {
    userCluster = match[1];
  }
}

    let query = `
  SELECT 
    UserId AS userId,
    UserName AS name,
    BranchName AS branchName,
    ClusterName AS clusterName,
    Role AS role,
    BranchCode AS branchCode
  FROM smart_call.dbo.UsersInfo
  WHERE 
  (
      Role LIKE '%Admin%'
      OR Role LIKE '%Branch Manager%'
      OR Role LIKE '%Calling Agent%'
      OR Role LIKE '%Regional Manager%'
  )
  AND BranchName <> 'Corporate Office'
  AND ISNULL(Status, 'Active') = 'Active'
`;

    const request = pool.request();

    // 🔒 Branch Manager restriction
    if (Role === "Branch Manager") {
      query += ` AND BranchName = @restrictedBranch`;
      request.input("restrictedBranch", sql.VarChar, userBranch);
    }
	
// 🔒 Regional Manager restriction
if (isRegionalManager) {
  query += ` AND ClusterName = @restrictedCluster`;
  request.input("restrictedCluster", sql.VarChar, userCluster);
}

    // ✅ Cluster filter
if (cluster && cluster !== "" && cluster !== "Corporate Office") {
  query += ` AND ClusterName = @cluster`;
  request.input("cluster", sql.VarChar, cluster);
}

    // ✅ Branch filter
    if (branchName && branchName !== "") {
      query += ` AND BranchName = @branchName`;
      request.input("branchName", sql.VarChar, branchName);
    }

    query += ` ORDER BY UserName`;

    const result = await request.query(query);

    res.json(result.recordset);

  } catch (err) {

    console.error("assignUsers error:", err);

    res.status(500).json({
      message: "Server Error",
      error: err.message
    });

  }
});


// ======================
// Assign Loans to User
// ======================
app.post("/api/assign", async (req, res) => {
  try {
    const { loanIds, assignedToUserId, assignedByAdminId } = req.body;

console.log("📌 [ASSIGN V2 API HIT]", {
  loanIds,
  assignedToUserId,
  assignedByAdminId
});

    if (!loanIds?.length) {
      return res.status(400).json({ message: "No loans selected" });
    }

    const pool = await poolPromise;

    // Fetch AssignedToUserName
    const toUser = await pool.request()
      .input("uid", sql.VarChar, assignedToUserId)
      .query(`SELECT UserName FROM UsersInfo WHERE UserId = @uid`);

    if (!toUser.recordset.length) {
      return res.status(400).json({ message: "Invalid AssignedToUserId" });
    }

    const assignedToUserName = toUser.recordset[0].UserName;

    // Fetch AssignedByAdminName
    const byUser = await pool.request()
      .input("adminId", sql.VarChar, assignedByAdminId)
      .query(`SELECT UserName FROM UsersInfo WHERE UserId = @adminId`);

    if (!byUser.recordset.length) {
      return res.status(400).json({ message: "Invalid AssignedByAdminId" });
    }

    const assignedByAdminName = byUser.recordset[0].UserName;

    // Fetch Metadata from Recovery_Raw_Data + Branch_Cluster_Master
    const loanMeta = await pool.request().query(`
      SELECT 
        R.loanAccountNumber,
        R.branchName,
        R.product,
        BCM.branch_code AS branchCode,
        BCM.cluster_name AS clusterName
      FROM Recovery_Raw_Data R
      LEFT JOIN Branch_Cluster_Master BCM
        ON R.branchName = BCM.branch_name
      WHERE R.loanAccountNumber IN (${loanIds.map(x => `'${x}'`).join(",")})
    `);

    if (!loanMeta.recordset.length) {
      return res.status(400).json({ message: "Loan Metadata Not Found" });
    }

    // Unassign previous records
    await pool.request().query(`
      UPDATE Account_Assignments
      SET AssignmentStatus = 'Unassigned', UnassignedAt = GETDATE()
      WHERE LoanAccountNumber IN (${loanIds.map(x => `'${x}'`).join(",")})
        AND AssignmentStatus = 'Assigned'
    `);

    // Insert new assignments
    const values = loanMeta.recordset.map(row =>
      `('${row.loanAccountNumber}', '${assignedToUserId}', '${assignedToUserName}', '${assignedByAdminId}', '${assignedByAdminName}', '${row.branchCode || ""}', '${row.branchName || ""}', '${row.clusterName || ""}', '${row.product || ""}', 'Assigned', GETDATE())`
    ).join(",");

    await pool.request().query(`
      INSERT INTO Account_Assignments
      (LoanAccountNumber, AssignedToUserId, AssignedToUserName, AssignedByAdminId, AssignedByAdminName, BranchCode, BranchName, ClusterName, Product, AssignmentStatus, AssignedAt)
      VALUES ${values}
    `);

console.log("✅ Assign V2 Success:", loanIds.length);
    return res.json({ message: "Assigned Successfully", assignedCount: loanIds.length });

  } catch (err) {
    console.error("❌ Assign V2 Error:", {
  loanIds,
  assignedToUserId,
  assignedByAdminId,
  message: err.message
});
    return res.status(500).json({ message: "Assignment Failed" });
  }
});



// ======================
// ADD USER
// ======================
app.post("/api/users", async (req, res) => {
  const {
  userId,
  userName,
  branchName,
  roles,
  dateOfBirth,
  mobileNumber,
  validFrom,
  validUntil,
  designation,
  status   // ✅ ADD THIS
} = req.body;

  const pool = await poolPromise;

  // Duplicate check
  const exists = await pool.request()
    .input("UserId", sql.VarChar, userId)
    .query("SELECT COUNT(*) cnt FROM UsersInfo WHERE UserId=@UserId");

  if (exists.recordset[0].cnt > 0)
    return res.status(409).json({ message: "UserId already exists" });

  // Branch → Cluster mapping
  const branch = await pool.request()
    .input("BranchName", sql.VarChar, branchName)
    .query(`
      SELECT branch_code, cluster_name
      FROM Branch_Cluster_Master
      WHERE branch_name=@BranchName
    `);

  if (!branch.recordset.length)
    return res.status(400).json({ message: "Invalid branch name" });

  const { branch_code, cluster_name } = branch.recordset[0];

  await pool.request()
    .input("UserId", sql.VarChar, userId)
    .input("UserName", userName)
    .input("BranchName", branchName)
    .input("BranchCode", sql.Int, branch_code)
    .input("ClusterName", sql.VarChar, cluster_name)
    .input("MobileNumber", mobileNumber)
    .input("DateOfBirth", sql.Date, dateOfBirth === "" ? null : dateOfBirth)
    .input("ValidFrom", sql.Date, validFrom === "" ? null : validFrom)
    .input("ValidUntil", sql.Date, validUntil === "" ? null : validUntil)
	.input("Designation", sql.VarChar, designation)
	.input("Status", sql.VarChar, status || "Active")

    .query(`
      INSERT INTO UsersInfo (
  UserId, UserName,
  BranchName, BranchCode, ClusterName,
  MobileNumber, DateOfBirth, ValidFrom, ValidUntil, Status, Designation, CreatedAt
) VALUES (
  @UserId, @UserName,
  @BranchName, @BranchCode, @ClusterName,
  @MobileNumber, @DateOfBirth, @ValidFrom, @ValidUntil, @Status, @Designation, GETDATE()
)
    `);
	
	// Insert roles into mapping table
if (roles && roles.length > 0) {
  for (const roleId of roles) {
    await pool.request()
      .input("UserId", sql.VarChar, userId)
      .input("RoleId", sql.Int, roleId)
      .query(`
        INSERT INTO UserRoles (UserId, RoleId)
        VALUES (@UserId, @RoleId)
      `);
  }
}

// Get role names as comma-separated string
const roleNamesRes = await pool.request()
  .input("UserId", sql.VarChar, userId)
  .query(`
    SELECT STRING_AGG(R.RoleName, ',') AS roleNames
    FROM UserRoles UR
    INNER JOIN Roles R ON UR.RoleId = R.RoleId
    WHERE UR.UserId = @UserId
  `);

const roleNames = roleNamesRes.recordset[0].roleNames || "";

// Update UsersInfo.Role column
await pool.request()
  .input("UserId", sql.VarChar, userId)
  .input("Role", sql.VarChar, roleNames)
  .query(`
    UPDATE UsersInfo
    SET Role = @Role
    WHERE UserId = @UserId
  `);

  res.json({ message: "User created successfully" });
});

//=============USER ID ============================================
app.put("/api/users/:userId", async (req, res) => {
  const { userId } = req.params;

  const {
  userName,
  branchName,
  roles,
  mobileNumber,
  dateOfBirth,
  validFrom,
  validUntil,
  designation,
  status   // ✅ ADD
} = req.body;

  try {
    const pool = await poolPromise;

    // 1️⃣ Validate user exists
    const userCheck = await pool.request()
      .input("UserId", sql.VarChar, userId)
      .query(`
        SELECT COUNT(*) AS cnt
        FROM UsersInfo
        WHERE UserId = @UserId
      `);

    if (userCheck.recordset[0].cnt === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    // 2️⃣ Re-derive BranchCode & ClusterName (if branch changed)
    const branchRes = await pool.request()
      .input("BranchName", sql.VarChar, branchName)
      .query(`
        SELECT branch_code, cluster_name
        FROM Branch_Cluster_Master
        WHERE branch_name = @BranchName
      `);

    if (branchRes.recordset.length === 0) {
      return res.status(400).json({
        message: "Invalid branch name. Not found in branch master."
      });
    }

    const { branch_code, cluster_name } = branchRes.recordset[0];

    // 3️⃣ Update UsersInfo
    await pool.request()
      .input("UserId", sql.VarChar, userId)
      .input("UserName", sql.VarChar, userName)
      .input("BranchName", sql.VarChar, branchName)
      .input("BranchCode", sql.Int, branch_code)
      .input("ClusterName", sql.VarChar, cluster_name)
      .input("MobileNumber", sql.VarChar, mobileNumber)
      .input("DateOfBirth", sql.Date, dateOfBirth === "" ? null : dateOfBirth)
      .input("ValidFrom", sql.Date, validFrom === "" ? null : validFrom)
      .input("ValidUntil", sql.Date, validUntil === "" ? null : validUntil)
	  .input("Designation", sql.VarChar, designation)
	  .input("Status", sql.VarChar, status)
      .query(`
        UPDATE UsersInfo SET
  UserName = @UserName,
  BranchName = @BranchName,
  BranchCode = @BranchCode,
  ClusterName = @ClusterName,
  MobileNumber = @MobileNumber,
  DateOfBirth = @DateOfBirth,
  ValidFrom = @ValidFrom,
  ValidUntil = @ValidUntil,
  Status = @Status,
  Designation = @Designation,
  UpdatedAt = GETDATE()
WHERE UserId = @UserId
      `);
	  
	  // Delete old roles
await pool.request()
  .input("UserId", sql.VarChar, userId)
  .query(`DELETE FROM UserRoles WHERE UserId=@UserId`);

// Insert new roles
if (roles && roles.length > 0) {
  for (const roleId of roles) {
    await pool.request()
      .input("UserId", sql.VarChar, userId)
      .input("RoleId", sql.Int, roleId)
      .query(`
        INSERT INTO UserRoles (UserId, RoleId)
        VALUES (@UserId, @RoleId)
      `);
  }
}

// Get updated role names
const roleNamesRes = await pool.request()
  .input("UserId", sql.VarChar, userId)
  .query(`
    SELECT STRING_AGG(R.RoleName, ',') AS roleNames
    FROM UserRoles UR
    INNER JOIN Roles R ON UR.RoleId = R.RoleId
    WHERE UR.UserId = @UserId
  `);

const roleNames = roleNamesRes.recordset[0].roleNames || "";

// Update UsersInfo.Role column
await pool.request()
  .input("UserId", sql.VarChar, userId)
  .input("Role", sql.VarChar, roleNames)
  .query(`
    UPDATE UsersInfo
    SET Role = @Role
    WHERE UserId = @UserId
  `);
  
    return res.json({ message: "User updated successfully" });

  } catch (err) {
    console.error("UPDATE USER ERROR:", err.message, err);
    return res.status(500).json({ message: "Failed to update user" });
  }
});
//========================DELETE USER========================================
app.delete("/api/users/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const pool = await poolPromise;

    // Delete roles first
    await pool.request()
      .input("UserId", userId)
      .query(`DELETE FROM UserRoles WHERE UserId=@UserId`);

    // Delete user
    await pool.request()
      .input("UserId", userId)
      .query(`DELETE FROM UsersInfo WHERE UserId=@UserId`);

    res.json({ message: "User deleted successfully" });

  } catch (err) {
    console.error("DELETE ERROR:", err);
    res.status(500).json({ message: "Failed to delete user" });
  }
});


// ======================
// GET USERS (LIST) - POST
// ======================
app.post("/api/users/list", async (req, res) => {
 const {
  page = 1,
  pageSize = 15,
  userId = "",
  name = "",
  branch = "",
  cluster = "",
  status = ""   // ✅ ADD THIS
} = req.body;
  
  const role = req.headers["x-user-role"];
const loggedBranch = req.headers["x-user-branch"];
const loggedCluster = req.headers["x-user-cluster"];

  let finalBranch = branch;
let finalCluster = cluster;

// 🔒 If Branch Manager → force restriction
if (role === "Branch Manager") {
  finalBranch = loggedBranch;
  finalCluster = loggedCluster;
}

const offset = (page - 1) * pageSize;

  try {
    const pool = await poolPromise;

    const dataQuery = `
      SELECT
        UserId       AS userId,
        UserName     AS userName,
        BranchName   AS branchName,
        BranchCode   AS branchCode,
        ClusterName  AS clusterName,
		
        ISNULL(STUFF((
    SELECT ',' + R.RoleName
    FROM UserRoles UR
    INNER JOIN Roles R ON UR.RoleId = R.RoleId
    WHERE UR.UserId = UsersInfo.UserId
    FOR XML PATH('')
),1,1,''),'') AS role,

ISNULL((
    SELECT STRING_AGG(CAST(UR.RoleId AS VARCHAR), ',')
    FROM UserRoles UR
    WHERE UR.UserId = UsersInfo.UserId
),'') AS roleIds,


        MobileNumber AS mobileNumber,
        DateOfBirth  AS dateOfBirth,
        ValidFrom    AS validFrom,
        ValidUntil   AS validUntil,
        ISNULL(Status, 'Active') AS status,
Designation AS designation
      FROM UsersInfo
      WHERE
(@userId = '' OR UserId LIKE '%' + @userId + '%')
AND (@name = '' OR UserName LIKE '%' + @name + '%')
AND (@branch = '' OR BranchName = @branch)
AND (@cluster = '' OR ClusterName = @cluster)
AND (@status = '' OR ISNULL(Status,'Active') = @status)
      ORDER BY UserName ASC
      OFFSET @offset ROWS
      FETCH NEXT @pageSize ROWS ONLY
    `;

    const countQuery = `
      SELECT COUNT(*) AS total
      FROM UsersInfo
      WHERE
  (@userId = '' OR UserId LIKE '%' + @userId + '%')
  AND (@name = '' OR UserName LIKE '%' + @name + '%')
  AND (@branch = '' OR BranchName = @branch)
  AND (@cluster = '' OR ClusterName = @cluster)
AND (@status = '' OR ISNULL(Status,'Active') = @status)  
    `;

    // ✅ DATA QUERY REQUEST
const dataRequest = pool.request()
  .input("userId", sql.VarChar, userId)
  .input("name", sql.VarChar, name)
  .input("branch", sql.VarChar, finalBranch || "")
  .input("cluster", sql.VarChar, finalCluster || "")
  .input("status", sql.VarChar, status)
  .input("offset", sql.Int, offset)
  .input("pageSize", sql.Int, pageSize);

// ✅ COUNT QUERY REQUEST
const countRequest = pool.request()
  .input("userId", sql.VarChar, userId)
  .input("name", sql.VarChar, name)
  .input("branch", sql.VarChar, finalBranch || "")
  .input("cluster", sql.VarChar, finalCluster || "")
  .input("status", sql.VarChar, status);

// ✅ EXECUTE
const records = await dataRequest.query(dataQuery);
const countRes = await countRequest.query(countQuery);

    const total = countRes.recordset[0].total;
    const pages = Math.ceil(total / pageSize);

    res.json({
  records: records.recordset,
  page,
  pages,
  totalRecords: total
});

  } catch (err) {
    console.error("GET USERS ERROR:", err);
    res.status(500).json({ message: "Failed to fetch users" });
  }
});

// ======================
// Product
// ======================

app.get("/api/products", async (req, res) => {
  try {
    const pool = await poolPromise;

    const result = await pool.request().query(`
      SELECT DISTINCT product
      FROM smart_call.dbo.Recovery_Raw_Data
      WHERE product IS NOT NULL AND product <> ''
      ORDER BY product ASC
    `);

    return res.json(result.recordset || []);
  } catch (error) {
    console.error("PRODUCT API ERROR:", error);
    return res.status(500).json({ error: error.message });
  }
});

// ====================================================================================
// FIELD VISIT REPORT
// ====================================================================================
app.post("/api/field-visit-report", async (req, res) => {
  const { user, cluster, branch, fromDate, toDate } = req.body;

  logInfo("FIELD VISIT API HIT", {
  user, cluster, branch, fromDate, toDate
});

  try {

    const pool = await poolPromise;   // ✅ MOVE THIS UP
    const request = pool.request();

    const userId = req.headers["x-user-id"];

logInfo("User ID received", userId);

if (!userId) {
  logError("Unauthorized request - missing userId");
  return res.status(401).json([]);
}

logInfo("Fetching user role from DB");
    const roleResult = await pool.request()
      .input("userId", userId)
      .query(`
        SELECT Role, BranchName, ClusterName
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    const userInfo = roleResult.recordset[0];
    logSuccess("User role fetched", userInfo);

    logInfo("Building SQL query");
    let query = `
      SELECT
        f.UserID,
        f.UserName,
        f.AccountNo,
        f.CustomerName,
        f.BranchLatitude,
        f.BranchLongitude,
        f.MeetingDate,
        f.StartLatitude,
        f.StartLongitude,
        f.MeetingLatitude,
        f.MeetingLongitude,
        f.MeetingAddress,
        f.DistanceTravelled,
        f.CustomerLatitude,
        f.CustomerLongitude,
        f.Variance
        
      FROM smart_call.dbo.FieldVisitReport f
      INNER JOIN smart_call.dbo.Account_Assignments aa
        ON f.AccountNo = aa.LoanAccountNumber
        AND f.UserID = aa.AssignedToUserId
      WHERE 1 = 1
        AND aa.AssignmentStatus = 'ASSIGNED'
        AND aa.UnassignedAt IS NULL
    `;

    if (userInfo?.Role === "Branch Manager") {
      logInfo("Applying Branch Manager filter", userInfo.BranchName);
      query += " AND aa.BranchName = @userBranch";
      request.input("userBranch", userInfo.BranchName);
    }
	
	// ================= REGIONAL MANAGER RESTRICTION =================
if (userInfo?.Role?.startsWith("Regional Manager")) {
  logInfo("Applying Regional Manager filter", userInfo.Role);

  const match = userInfo.Role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  query += " AND aa.ClusterName = @rmCluster";
  request.input("rmCluster", rmCluster);

}

    if (user) {
      logInfo("Filter applied: user", user);
      query += " AND f.UserID = @user";
      request.input("user", user);
    }

    if (cluster && cluster !== "Corporate Office") {
      logInfo("Filter applied: cluster", cluster);
      query += " AND aa.ClusterName = @cluster";
      request.input("cluster", cluster);
    }

    if (branch) {
      logInfo("Filter applied: branch", branch);
      query += " AND aa.BranchName = @branch";
      request.input("branch", branch);
    }

    if (fromDate) {
      logInfo("Filter applied: fromDate", fromDate);
      query += " AND CAST(f.MeetingDate AS DATE) >= @fromDate";
      request.input("fromDate", fromDate);
    }

    if (toDate) {
      logInfo("Filter applied: toDate", toDate);
      query += " AND CAST(f.MeetingDate AS DATE) <= @toDate";
      request.input("toDate", toDate);
    }

    query += " ORDER BY f.MeetingDate DESC";

logInfo("Executing SQL query");
   const result = await request.query(query);
   logSuccess("Query executed successfully", {
  rowCount: result.recordset?.length || 0
});
const data = result.recordset || [];

// ================= FETCH SESSIONS =================

if (data.length === 0) {
  logWarn("No records found");
  return res.json([]);
}

logInfo("Fetching sessions for accounts", data.length);
const requestSessions = pool.request();

data.forEach((row, index) => {
  requestSessions.input(`acc${index}`, row.AccountNo);
});

const sessionsResult = await requestSessions.query(`
  SELECT
    s.SessionId,
    s.SourceId AS AccountNo
  FROM Activity_Sessions s
  WHERE s.SourceId IN (${data.map((_, i) => `@acc${i}`).join(",")})
    AND s.SessionType = 'VISIT'
    AND ISNULL(s.SourceType,'NPA') = 'NPA'
`);

const sessions = sessionsResult.recordset;
logSuccess("Sessions fetched", sessions.length);

// ================= FETCH LOGS =================

const sessionIds = sessions.map(s => s.SessionId);

let logs = [];

if (sessionIds.length > 0) {
  logInfo("Fetching activity logs", sessionIds.length);

  const requestLogs = pool.request();

  sessionIds.forEach((id, index) => {
    requestLogs.input(`sid${index}`, id);
  });

  const logsResult = await requestLogs.query(`
    SELECT 
      L.SessionId,
      L.ActionLabel
    FROM Activity_Logs L
    WHERE L.SessionId IN (${sessionIds.map((_, i) => `@sid${i}`).join(",")})
    ORDER BY L.CreatedAt
  `);

  logs = logsResult.recordset;
  logSuccess("Logs fetched", logs.length);
}

// ================= BUILD FLOW =================

logInfo("Building final response with flow");
const finalData = data.map(row => {

  const session = sessions.find(s => s.AccountNo == row.AccountNo);

  if (!session) {
    return { ...row, Flow: "" };
  }

  const sessionLogs = logs.filter(l => l.SessionId === session.SessionId);

  const flow = sessionLogs
    .map((l, index) => `${index + 1}. ${l.ActionLabel}`)
    .join("\n");

  return {
    ...row,
    Flow: flow
  };
});

logSuccess("FIELD VISIT API SUCCESS", {
  finalCount: finalData.length
});
res.json(finalData);

  } catch (err) {
  logError("FIELD VISIT API ERROR", {
    message: err.message,
    stack: err.stack
  });
    res.status(500).json([]);
  }
});


// ====================================
// FIELD VISIT REPORT EXPORT PDF
// ====================================

const PDFDocument = require("pdfkit");

app.post("/api/field-visit-report/export-pdf", (req, res) => {
  const { columns, data } = req.body;

  logInfo("PDF EXPORT API HIT", {
  columns: columns?.length,
  rows: data?.length
});
  // ================= PDF CONFIG =================
  const doc = new PDFDocument({
    size: "A3",            // 🔥 IMPORTANT: A3 for wide tables
    layout: "landscape",
    margin: 20
  });

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    "attachment; filename=Field_Visit_Report.pdf"
  );

  doc.pipe(res);

  // ================= TITLE =================
  doc
    .font("Helvetica-Bold")
    .fontSize(16)
    .text("Field Visit Report", { align: "center" });

  doc.moveDown(1);

  // ================= HEADER LABELS =================
  const HEADER_LABELS = {
    sno: "S. No.",
    UserName: "User Name",
    AccountNo: "Account No",
    CustomerName: "Customer Name",
    BranchLatitude: "Branch Latitude",
    BranchLongitude: "Branch Longitude",
    MeetingDate: "Meeting Date",
    StartLatitude: "Start Latitude",
    StartLongitude: "Start Longitude",
    MeetingLatitude: "Meeting Latitude",
    MeetingLongitude: "Meeting Longitude",
    MeetingAddress: "Meeting Address",
    DistanceTravelled: "Distance Travelled",
    CustomerLatitude: "Customer Latitude",
    CustomerLongitude: "Customer Longitude",
    Variance: "Variance",
    Flow: "Flow"
  };

  // ================= TABLE CONFIG =================
  const pdfColumns = ["sno", ...columns];

  const pageWidth =
    doc.page.width - doc.page.margins.left - doc.page.margins.right;

  const columnWidth = pageWidth / pdfColumns.length;
  const headerHeight = 50;

  let startX = doc.page.margins.left;
  let startY = doc.y;

  // ================= DRAW TABLE HEADER =================
  const drawTableHeader = () => {
    doc.font("Helvetica-Bold").fontSize(11);

    pdfColumns.forEach((col, i) => {
      const x = startX + i * columnWidth;
      const label = HEADER_LABELS[col] || col;

      // Header background
      doc
        .rect(x, startY, columnWidth, headerHeight)
        .fillAndStroke("#f1f5f9", "#000");

      doc
        .fillColor("#000")
        .text(label, x + 4, startY + 16, {
          width: columnWidth - 8,
          align: "center",
          lineBreak: false   // 🔥 prevents word breaking
        });
    });

    startY += headerHeight;

    // 🔥 Reset font so body text never becomes bold
    doc.font("Helvetica").fontSize(10);
  };

  // Draw header initially
  drawTableHeader();

  // ================= TABLE ROWS =================
  data.forEach((row, rowIndex) => {
    let maxRowHeight = 28;

    // ---- Calculate row height dynamically ----
    pdfColumns.forEach(col => {
      let value = "";

      if (col === "sno") value = String(rowIndex + 1);
      else if (col === "MeetingDate" && row[col])
        value = row[col].split("T")[0];
      else value = row[col] ?? "";

      const height = doc.heightOfString(String(value), {
        width: columnWidth - 8,
        lineGap: 2
      });

      maxRowHeight = Math.max(maxRowHeight, height + 12);
    });

    // ---- PAGE BREAK ----
    if (startY + maxRowHeight > doc.page.height - doc.page.margins.bottom) {
      doc.addPage();
      startY = doc.page.margins.top;
      drawTableHeader(); // 🔥 header on every page
    }

    // ---- Draw row cells ----
    pdfColumns.forEach((col, i) => {
      const x = startX + i * columnWidth;
      let value = "";

      if (col === "sno") value = String(rowIndex + 1);
      else if (col === "MeetingDate" && row[col])
        value = row[col].split("T")[0];
      else value = row[col] ?? "";

      doc.rect(x, startY, columnWidth, maxRowHeight).stroke();

      doc.text(String(value), x + 4, startY + 8, {
        width: columnWidth - 8,
        lineGap: 2
      });
    });

    startY += maxRowHeight;
  });

  logSuccess("PDF generated successfully");
  doc.end();
});

// ====================================
// FIELD VISIT REPORT EXPORT EXCEL
// ====================================

const ExcelJS = require("exceljs");

app.post("/api/field-visit-report/export-excel", async (req, res) => {

  const { columns, data } = req.body;

  logInfo("EXCEL EXPORT API HIT", {
  columns: columns?.length,
  rows: data?.length
});

  try {

    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet("Field Visit Report");

    const HEADER_LABELS = {
      sno: "S. No.",
      UserName: "User Name",
      AccountNo: "Account No",
      CustomerName: "Customer Name",
      BranchLatitude: "Branch Latitude",
      BranchLongitude: "Branch Longitude",
      MeetingDate: "Meeting Date",
      StartLatitude: "Start Latitude",
      StartLongitude: "Start Longitude",
      MeetingLatitude: "Meeting Latitude",
      MeetingLongitude: "Meeting Longitude",
      MeetingAddress: "Meeting Address",
      DistanceTravelled: "Distance Travelled",
      CustomerLatitude: "Customer Latitude",
      CustomerLongitude: "Customer Longitude",
      Variance: "Variance",
      Flow: "Flow"
    };

    const excelColumns = ["sno", ...columns];

    sheet.columns = excelColumns.map(col => ({
      header: HEADER_LABELS[col] || col,
      key: col,
      width: 25
    }));

    data.forEach((row, index) => {

      const newRow = {};

      excelColumns.forEach(col => {

        if (col === "sno") newRow[col] = index + 1;
        else if (col === "MeetingDate" && row[col])
          newRow[col] = row[col].split("T")[0];
        else newRow[col] = row[col] ?? "";

      });

      sheet.addRow(newRow);

    });

    // Header style
    sheet.getRow(1).font = { bold: true };

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );

    res.setHeader(
      "Content-Disposition",
      "attachment; filename=Field_Visit_Report.xlsx"
    );

    logInfo("Writing Excel file");
    await workbook.xlsx.write(res);

    logSuccess("Excel generated successfully");
    res.end();

  } catch (err) {

    logError("EXCEL EXPORT ERROR", {
  message: err.message,
  stack: err.stack
});
    res.status(500).send("Excel export failed");

  }

});


// =============================
// Activity Summary
// =============================
app.post("/api/activity-summary", async (req, res) => {

  const { user, branch, cluster, fromDate, toDate } = req.body;
    logInfo("ACTIVITY SUMMARY API HIT", {
  user, branch, cluster, fromDate, toDate
});

  try {

    // ================= USER VALIDATION =================
    const rawUserId = req.headers["x-user-id"];
    logInfo("User ID received", rawUserId);

    if (!rawUserId) {
  logWarn("Unauthorized access attempt");
  return res.status(401).json({ message: "Unauthorized" });
}

    // ✅ FIXED: No parseInt
    const userId = rawUserId;

    const pool = await poolPromise;

    // 🔹 Fetch role
    const roleResult = await pool.request()
      .input("userId", sql.VarChar(50), userId)   // ✅ FIXED
      .query(`
        SELECT Role, BranchName
        FROM UsersInfo
        WHERE UserId = @userId
      `);
logInfo("Role query result", roleResult.recordset);
logSuccess("User info fetched", roleResult.recordset[0]);

    if (!roleResult.recordset.length) {
  logWarn("User not found in UsersInfo");
  return res.json([]);
}

    const userInfo = roleResult.recordset[0];
    logInfo("User info", userInfo);

    const request = pool.request();

   logInfo("Filters applied", { user, branch, cluster, fromDate, toDate });

request.input("fromDate", sql.Date, fromDate || null);
request.input("toDate", sql.Date, toDate || null);

    let query = `
      WITH CallVisitCounts AS (
        SELECT
          aa.AssignedToUserName AS UserName,
          aa.BranchName,
          aa.LoanAccountNumber,

          COUNT(CASE WHEN l.ActionCode = 'CALL_SPOKE' THEN 1 END) AS CallCount,
          COUNT(CASE WHEN l.ActionCode = 'VISIT_COMPLETED' THEN 1 END) AS VisitCount

        FROM Account_Assignments aa

        LEFT JOIN Activity_Sessions s
          ON aa.LoanAccountNumber = s.LoanAccountNumber
          AND aa.AssignedToUserName = s.StartedByUserName

        LEFT JOIN Activity_Logs l
          ON s.SessionId = l.SessionId
          AND (
            l.ActionCode = 'CALL_SPOKE'
            OR l.ActionCode = 'VISIT_COMPLETED'
          )
          AND (@fromDate IS NULL OR CAST(l.CreatedAt AS DATE) >= @fromDate)
          AND (@toDate IS NULL OR CAST(l.CreatedAt AS DATE) <= @toDate)

        WHERE
          aa.AssignmentStatus = 'ASSIGNED'
          AND aa.UnassignedAt IS NULL
    `;

    // ================= BRANCH MANAGER RESTRICTION =================
    if (userInfo.Role === "Branch Manager") {
      logInfo("Branch Manager restriction applied", userInfo.BranchName);
      query += ` AND aa.BranchName = @userBranch`;
      request.input("userBranch", sql.NVarChar, userInfo.BranchName);
    }
	
	// ================= REGIONAL MANAGER RESTRICTION =================
if (userInfo.Role.startsWith("Regional Manager")) {
  logInfo("Regional Manager restriction applied", userInfo.Role);

  const match = userInfo.Role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  query += ` AND aa.ClusterName = @rmCluster`;
  request.input("rmCluster", sql.NVarChar, rmCluster);

}

    // ================= USER FILTER =================
    if (user) {
      logInfo("Applying user filter", user);
      query += ` AND aa.AssignedToUserId = @user`;
      request.input("user", sql.VarChar(50), user);
    }

    // ================= BRANCH FILTER =================
    if (branch) {
      logInfo("Applying branch filter", branch);
      query += ` AND aa.BranchName = @branch`;
      request.input("branch", sql.NVarChar, branch);
    }

    // ================= CLUSTER FILTER =================
    if (cluster && cluster !== "Corporate Office") {
      logInfo("Applying cluster filter", cluster);
      query += ` AND aa.ClusterName = @cluster`;
      request.input("cluster", sql.NVarChar, cluster);
    }

    query += `
        GROUP BY
          aa.AssignedToUserName,
          aa.BranchName,
          aa.ClusterName,
          aa.LoanAccountNumber
      )

      SELECT
        UserName,
        BranchName,
        COUNT(*) AS Assigned,

        SUM(CASE WHEN CallCount >= 1 THEN 1 ELSE 0 END) AS CalledOnce,
        SUM(CASE WHEN CallCount >= 2 THEN 1 ELSE 0 END) AS CalledTwice,
        SUM(CASE WHEN CallCount >= 3 THEN 1 ELSE 0 END) AS CalledThrice,

        SUM(CallCount) AS NoOfTimesCalled,

        SUM(CASE WHEN CallCount = 0 THEN 1 ELSE 0 END) AS NotCalled,
        SUM(VisitCount) AS NoOfVisits

      FROM CallVisitCounts
      GROUP BY UserName, BranchName
      ORDER BY UserName, BranchName;
    `;

logInfo("Final query prepared");
   const startTime = Date.now();
logInfo("Executing Activity Summary query");

const result = await request.query(query);

logSuccess("Query executed successfully", {
  rowCount: result.recordset.length,
  executionTimeMs: Date.now() - startTime
});

logSuccess("Response sent", {
  rowCount: result.recordset.length,
  status: 200
});
res.json(result.recordset || []);

  } catch (err) {
    logError("ACTIVITY SUMMARY ERROR", err);
    res.status(500).json([]);
  }
});



// =====================================================================
// ACTIVITY SUMMARY → EXPORT PDF
// =====================================================================
app.post("/api/activity-summary/export-pdf", async (req, res) => {
  
  const { selectedData, columns, fileName } = req.body;

  logInfo("ACTIVITY SUMMARY PDF EXPORT HIT", {
  rows: selectedData?.length,
  columns,
  fileName
});

  if (!selectedData || selectedData.length === 0) {
  logWarn("PDF export failed - no data");
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
  logWarn("PDF export failed - no columns");
    return res.status(400).json({ message: "No columns selected" });
  }

  try {

logInfo("Starting PDF generation", {
  rows: selectedData.length,
  columns
});
    const doc = new PDFDocument({
      size: "A4",
      layout: "landscape",
      margin: 30
    });

    const safeName = (fileName || "Activity_Summary_Report")
  .replace(/\s+/g, "_");

logInfo("PDF filename", safeName);

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.pdf"`
    );

    doc.pipe(res);

    // ================= TITLE =================
    doc.font("Helvetica-Bold")
       .fontSize(14)
       .text("Activity Summary Report", { align: "center" });

    doc.moveDown(1);

    // ================= COLUMN LABELS =================
    const COLUMN_LABELS = {
      SNo: "S. No.",
      UserName: "User Name",
      BranchName: "Branch Name",
      Assigned: "Assigned",
      NotCalled: "Not Called",
      CalledOnce: "Called Once",
      CalledTwice: "Called Twice",
      CalledThrice: "Called Thrice",
      NoOfTimesCalled: "No. of Times Called",
      NoOfVisits: "No. of Visits"
    };

    const finalColumns = ["SNo", ...columns]; // ✅ Always add S.No first

    const pageWidth =
      doc.page.width - doc.page.margins.left - doc.page.margins.right;

    const colWidth = pageWidth / finalColumns.length;
    const rowHeight = 22;

    let x = doc.page.margins.left;
    let y = doc.y;

    // ================= HEADER =================
    doc.fontSize(9).font("Helvetica-Bold");

    finalColumns.forEach(col => {
      doc.rect(x, y, colWidth, rowHeight)
         .fillAndStroke("#e5e7eb", "#000");

      doc.fillColor("#000")
         .text(COLUMN_LABELS[col], x + 4, y + 6, {
           width: colWidth - 8,
           align: "center"
         });

      x += colWidth;
    });

    y += rowHeight;
    doc.font("Helvetica").fontSize(9);

    // ================= ROWS =================
    selectedData.forEach(row => {

      x = doc.page.margins.left;

      finalColumns.forEach(col => {
        doc.rect(x, y, colWidth, rowHeight).stroke();

        doc.text(String(row[col] ?? ""), x + 4, y + 6, {
          width: colWidth - 8,
          align: "center"
        });

        x += colWidth;
      });

      y += rowHeight;

      if (y + rowHeight > doc.page.height - doc.page.margins.bottom) {
        doc.addPage({ layout: "landscape" });
        y = doc.page.margins.top;
      }
    });

    logSuccess("PDF generated successfully");
    logSuccess("PDF response sent");
    doc.end();

  } catch (err) {
    logError("PDF generation error", err);
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});



// =====================================================================
// ASSIGNMENT SUMMARY
// =====================================================================

app.post("/api/assignment-summary/search", async (req, res) => {

  const { userName, cluster, branch, fromDate, toDate } = req.body;

  logInfo("ASSIGNMENT SUMMARY API HIT", {
  body: req.body
});

  const role = req.headers["x-user-role"];
const loggedBranch = req.headers["x-user-branch"];
const loggedCluster = req.headers["x-user-cluster"];

logInfo("User context received", {
  role,
  branch: loggedBranch,
  cluster: loggedCluster
});


if (!userName && !cluster && !branch && !fromDate && !toDate) {
  logWarn("Search blocked - no filters provided");
  return res.json([]);
}

  try {
logInfo("Starting Assignment Summary DB process");
    const pool = await poolPromise;
    logInfo("DB connection established");
    const request = pool.request();

    logInfo("Applying filters", {
  userName,
  cluster,
  branch,
  fromDate,
  toDate
});

if (userName) {
  logInfo("Filter applied: userName", userName);
}
    request.input("UserName", sql.VarChar, userName || "");

    let finalCluster = cluster;
    let finalBranch = branch;

    // 🔒 Branch Manager restriction
    if (role === "Branch Manager") {
      logInfo("Branch Manager restriction applied", {
  loggedCluster,
  loggedBranch
});
      finalCluster = loggedCluster;
      finalBranch = loggedBranch;
    }
	
	// 🔒 Regional Manager restriction
if (role && role.startsWith("Regional Manager")) {
logInfo("Regional Manager restriction applied", role);
  const match = role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  finalCluster = rmCluster;

}

    // Corporate Office → show all clusters
    if (finalCluster === "Corporate Office") {
      logInfo("Corporate Office selected → removing cluster filter");
      finalCluster = "";
    }

    request.input("Cluster", sql.VarChar, finalCluster || "");
    request.input("Branch", sql.VarChar, finalBranch || "");
    request.input("FromDate", sql.Date, fromDate || null);
    request.input("ToDate", sql.Date, toDate || null);

    logInfo("Final filters applied to SQL", {
  finalCluster,
  finalBranch,
  fromDate,
  toDate
});

logInfo("Executing Assignment Summary query");
    const result = await request.query(`

      SELECT 
          A.AssignedByAdminId     AS AssignedByUserId,
          A.AssignedByAdminName   AS AssignedByUserName,
          A.AssignedToUserId      AS AssignedToUserId,
          A.AssignedToUserName    AS AssignedToUserName,
          A.BranchCode,
          A.BranchName,
          A.LoanAccountNumber     AS AccountNumber,
          R.firstname             AS CustomerName,
          R.dpdQueue              AS DpdQueue,
          ISNULL(C.CallCount,0)   AS NoOfCalls

      FROM Account_Assignments A

      INNER JOIN Recovery_Raw_Data R
          ON A.LoanAccountNumber = R.loanAccountNumber

      OUTER APPLY (
          SELECT COUNT(AL.LogId) AS CallCount
          FROM Activity_Sessions S
          INNER JOIN Activity_Logs AL
              ON S.SessionId = AL.SessionId
          WHERE 
              S.LoanAccountNumber = A.LoanAccountNumber
              AND AL.ActionCode = 'CALL_SPOKE'
              AND AL.ActionLabel = 'Spoke to Customer'
      ) AS C

      WHERE 
          (@UserName = '' OR A.AssignedByAdminName = @UserName)
          AND (@Cluster = '' OR A.ClusterName = @Cluster)
          AND (@Branch = '' OR A.BranchName = @Branch)
          AND (@FromDate IS NULL OR CAST(A.AssignedAt AS DATE) >= @FromDate)
          AND (@ToDate IS NULL OR CAST(A.AssignedAt AS DATE) <= @ToDate)

      ORDER BY A.AssignedAt DESC

    `);

    const rows = result.recordset;
    logSuccess("Query executed successfully", {
  count: result.recordset?.length || 0
});

if (!result.recordset.length) {
  logWarn("No records found");
}

    // ================= GROUP DATA =================
logInfo("Starting data grouping process");
    const grouped = {};

    rows.forEach(row => {

      const key = `${row.AssignedByUserId}_${row.AssignedToUserId}_${row.BranchCode}`;

      if (!grouped[key]) {

        grouped[key] = {
          AssignedByUserId: row.AssignedByUserId,
          AssignedByUserName: row.AssignedByUserName,
          AssignedToUserId: row.AssignedToUserId,
          AssignedToUserName: row.AssignedToUserName,
          BranchCode: row.BranchCode,
          BranchName: row.BranchName,
          AccountCount: 0,
          accounts: []
        };

      }

      grouped[key].AccountCount++;

      grouped[key].accounts.push({
        AccountNumber: row.AccountNumber,
        CustomerName: row.CustomerName,
        DpdQueue: row.DpdQueue,
        NoOfCalls: row.NoOfCalls
      });

    });

    logSuccess("Assignment Summary response prepared", {
  groups: Object.keys(grouped).length
});

logSuccess("ASSIGNMENT SUMMARY API SUCCESS", {
  responseCount: Object.values(grouped).length
});
    res.json(Object.values(grouped));

  } catch (err) {

    logError("ASSIGNMENT SUMMARY ERROR", {
  message: err.message,
  stack: err.stack
});
    res.status(500).send("Server error");

  }

});

// ============================================================
// ASSIGNMENT SUMMARY → EXPORT PDF
// ============================================================

app.post("/api/assignment-summary/export-pdf", async (req, res) => {

  const { records, columns, fileName } = req.body;

  logInfo("ASSIGNMENT SUMMARY PDF EXPORT API HIT", {
  records: req.body.records?.length,
  columns: req.body.columns?.length
});

  if (!records || records.length === 0) {
    logWarn("PDF export blocked - no records");
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    logWarn("PDF export blocked - no columns");
    return res.status(400).json({ message: "No columns selected" });
  }

  try {
logInfo("Starting PDF generation");
    const PDFDocument = require("pdfkit");

    const doc = new PDFDocument({
      size: "A4",
      layout: "landscape",
      margin: 40
    });

    const safeName = (fileName || "Assignment_Summary")
      .replace(/\s+/g, "_");

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.pdf"`
    );

    doc.pipe(res);

    // ================= TITLE =================
    doc.font("Helvetica-Bold")
       .fontSize(16)
       .text("Assignment Summary Report", { align: "center" });

    doc.moveDown(1);

    // ================= TABLE SETUP =================
    const pageWidth =
      doc.page.width - doc.page.margins.left - doc.page.margins.right;

    const columnWidth = pageWidth / columns.length;

    let y = doc.y;

    const LABELS = {
  serialNumber: "S. No.",

  AssignedByUserId: "Assigned By User Id",
  AssignedByUserName: "Assigned By User Name",
  AssignedToUserId: "Assigned To User Id",
  AssignedToUserName: "Assigned To User Name",

  BranchCode: "Branch Code",
  BranchName: "Branch Name",
  AccountNumber: "Account Number",
  CustomerName: "Customer Name",
  DpdQueue: "DPD Queue",
  NoOfCalls: "No. of Calls"
};

    // ================= HEADER =================
doc.font("Helvetica-Bold").fontSize(10);

let headerHeight = 25;

// ✅ Calculate dynamic header height
columns.forEach(col => {

  const textHeight = doc.heightOfString(LABELS[col] || col, {
    width: columnWidth - 10
  });

  headerHeight = Math.max(headerHeight, textHeight + 10);
});

let x = doc.page.margins.left;

columns.forEach(col => {

  doc.rect(x, y, columnWidth, headerHeight)
     .fillAndStroke("#e2e8f0", "#94a3b8");

  doc.fillColor("#000")
     .text(LABELS[col] || col, x + 5, y + 5, {
       width: columnWidth - 10,
       align: "center"
     });

  x += columnWidth;
});

y += headerHeight;
doc.font("Helvetica").fontSize(9);

    // ================= ROWS =================
    records.forEach((row, index) => {

      let x = doc.page.margins.left;
      let dynamicHeight = 20;

      // 🔹 Calculate dynamic row height
      columns.forEach(col => {

        let value = row[col] ?? "";

        if (col === "DpdQueue") {
          if (value === "01") value = "0-30 Days";
          else if (value === "02") value = "31-60 Days";
          else if (value === "03") value = "61-90 Days";
          else if (!isNaN(value) && parseInt(value) >= 4) value = "Above 90 Days";
        }

        const textHeight = doc.heightOfString(String(value), {
          width: columnWidth - 10
        });

        dynamicHeight = Math.max(dynamicHeight, textHeight + 10);
      });

      // 🔹 Page Break Check
      if (y + dynamicHeight > doc.page.height - 40) {

        doc.addPage({
          size: "A4",
          layout: "landscape",
          margin: 40
        });

        y = doc.page.margins.top;

        // Redraw Header on new page
doc.font("Helvetica-Bold").fontSize(10);

let newHeaderHeight = 25;

// Recalculate height
columns.forEach(col => {
  const textHeight = doc.heightOfString(LABELS[col] || col, {
    width: columnWidth - 10
  });

  newHeaderHeight = Math.max(newHeaderHeight, textHeight + 10);
});

let newX = doc.page.margins.left;

columns.forEach(col => {

  doc.rect(newX, y, columnWidth, newHeaderHeight)
     .fillAndStroke("#e2e8f0", "#94a3b8");

  doc.fillColor("#000")
     .text(LABELS[col] || col, newX + 5, y + 5, {
       width: columnWidth - 10,
       align: "center"
     });

  newX += columnWidth;
});

y += newHeaderHeight;
doc.font("Helvetica").fontSize(9);
      }

      // 🔹 Alternate Row Background
      if (index % 2 === 0) {
        doc.rect(doc.page.margins.left, y, pageWidth, dynamicHeight)
           .fill("#f8fafc");
      }

      // 🔹 Draw Cells
      columns.forEach(col => {

        doc.rect(x, y, columnWidth, dynamicHeight).stroke();

        let value = row[col] ?? "";

        if (col === "DpdQueue") {
          if (value === "01") value = "0-30 Days";
          else if (value === "02") value = "31-60 Days";
          else if (value === "03") value = "61-90 Days";
          else if (!isNaN(value) && parseInt(value) >= 4) value = "Above 90 Days";
        }

        doc.fillColor("#000")
           .text(String(value), x + 5, y + 5, {
             width: columnWidth - 10,
             align: "center"
           });

        x += columnWidth;
      });

      y += dynamicHeight;
    });

    logSuccess("ASSIGNMENT SUMMARY EXPORT COMPLETED", {
  fileName: safeName,
  columns: columns.length
});
    doc.end();

  } catch (err) {
    logError("ASSIGNMENT SUMMARY PDF ERROR", {
  message: err.message,
  stack: err.stack
});

    if (!res.headersSent) {
      res.status(500).json({ message: "Failed to generate PDF" });
    }
  }
});

// ======================================================
// BORROWERS CONTACTED BY PHONE 
// ======================================================
app.post("/api/borrowers-contacted/search", async (req, res) => {

  logInfo("BORROWERS CONTACTED API HIT", {
  body: req.body
});

  const loggedInUserId = req.headers["x-user-id"];
  logInfo("User ID received", loggedInUserId);

  if (!loggedInUserId) {
    logError("Unauthorized request - missing userId");
    return res.status(401).json({ message: "Unauthorized" });
  }

  const { cluster, branch, userId, fromDate, toDate } = req.body;

  try {
    const pool = await poolPromise;

    logInfo("Fetching user role from DB");
// 🔥 Get logged-in user role & branch
const userInfo = await pool.request()
  .input("userId", sql.VarChar, loggedInUserId)
  .query(`
    SELECT Role, BranchName
    FROM UsersInfo
    WHERE UserId = @userId
  `);

if (!userInfo.recordset.length) {
  logError("User not found in DB", loggedInUserId);
  return res.status(403).json({ message: "User not found" });
}

const { Role, BranchName: userBranch } = userInfo.recordset[0];
logSuccess("User role fetched", { Role, userBranch });

const request = pool.request();

logInfo("Building SQL query");
    let query = `
    WITH SpokeSessions AS (
        SELECT DISTINCT SessionId
        FROM smart_call.dbo.Activity_Logs
        WHERE ActionCode = 'CALL_SPOKE'
    ),

    OrderedLogs AS (
        SELECT
            S.SessionId,
            S.StartedAt,

            AA.AssignedToUserId,
            AA.AssignedToUserName,
            AA.LoanAccountNumber,
            AA.BranchName,
            AA.ClusterName,

            RD.firstname,
            RD.mobileNumber,

            AL.ActionLabel,
            AL.CreatedAt,

            ROW_NUMBER() OVER (
                PARTITION BY S.SessionId
                ORDER BY AL.CreatedAt ASC
            ) AS StepNumber

        FROM smart_call.dbo.Account_Assignments AA

        INNER JOIN smart_call.dbo.Activity_Sessions S
            ON S.AssignmentId = AA.AssignmentId

        INNER JOIN SpokeSessions SS
            ON SS.SessionId = S.SessionId

        INNER JOIN smart_call.dbo.Activity_Logs AL
            ON AL.SessionId = S.SessionId

        LEFT JOIN smart_call.dbo.Recovery_Raw_Data RD
            ON RD.loanAccountNumber = AA.LoanAccountNumber
    )

    SELECT
        AssignedToUserId      AS employeeId,
        AssignedToUserName    AS employeeName,
        LoanAccountNumber     AS accountNumber,
        BranchName            AS branchName,
        firstname             AS borrowerName,
        mobileNumber          AS numberContacted,

        StartedAt AS dateOfCall,
		
        STRING_AGG(
            CAST(StepNumber AS VARCHAR) + '. ' + ActionLabel,
            CHAR(10)
        ) WITHIN GROUP (ORDER BY StepNumber) AS flow

    FROM OrderedLogs
    WHERE 1=1
    `;
	
	// 🔒 FORCE BRANCH RESTRICTION
if (Role === "Branch Manager") {
  logInfo("Applying Branch Manager restriction", userBranch);
  query += ` AND BranchName = @restrictedBranch`;
  request.input("restrictedBranch", sql.VarChar, userBranch);
}

// 🔒 FORCE CLUSTER RESTRICTION FOR REGIONAL MANAGER
if (Role.startsWith("Regional Manager")) {
logInfo("Applying Regional Manager restriction", Role);
  const match = Role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  query += ` AND ClusterName = @rmCluster`;
  request.input("rmCluster", sql.VarChar, rmCluster);

}

    // ================= USER FILTER =================
    if (userId) {
      logInfo("Filter applied: userId", userId);
      query += ` AND AssignedToUserId = @userId`;
      request.input("userId", sql.VarChar, userId);
    }

    // ================= BRANCH FILTER =================
    if (branch) {
      logInfo("Filter applied: branch", branch);
      query += ` AND BranchName = @branch`;
      request.input("branch", sql.VarChar, branch);
    }

    // ================= CLUSTER FILTER =================
    if (cluster && cluster !== "Corporate Office") {
      logInfo("Filter applied: cluster", cluster);
      query += ` AND ClusterName = @cluster`;
      request.input("cluster", sql.VarChar, cluster);
    }

    // ================= DATE FILTER =================
    if (fromDate) {
      logInfo("Filter applied: fromDate", fromDate);
      query += ` AND CAST(StartedAt AS DATE) >= @fromDate`;
      request.input("fromDate", sql.Date, fromDate);
    }

    if (toDate) {
      logInfo("Filter applied: toDate", toDate);
      query += ` AND CAST(StartedAt AS DATE) <= @toDate`;
      request.input("toDate", sql.Date, toDate);
    }

    query += `
    GROUP BY
        SessionId,
        StartedAt,
        AssignedToUserId,
        AssignedToUserName,
        LoanAccountNumber,
        BranchName,
        firstname,
        mobileNumber

    ORDER BY StartedAt DESC
    `;

    logInfo("Executing SQL query");

logInfo("Final Query Filters", {
  cluster,
  branch,
  userId,
  fromDate,
  toDate,
  role: Role
});

const result = await request.query(query);

logSuccess("Query executed successfully", {
  count: result.recordset?.length || 0
});

if (!result.recordset.length) {
  logWarn("No records found");
}

logSuccess("BORROWERS API SUCCESS", {
  count: result.recordset?.length || 0
});

res.json(result.recordset);

  } catch (err) {
    logError("BORROWERS API ERROR", {
  message: err.message,
  stack: err.stack
});
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// BORROWERS CONTACTED → EXPORT PDF
// ============================================================

app.post("/api/borrowers-contacted/export-pdf", async (req, res) => {
  const { selectedIndexes, columns, fileName, fullData } = req.body;

  logInfo("BORROWERS PDF EXPORT API HIT", {
  selected: req.body.selectedIndexes?.length,
  columns: req.body.columns?.length
});

  if (!selectedIndexes || selectedIndexes.length === 0) {
    logWarn("PDF export blocked - no records selected");
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    logWarn("PDF export blocked - no columns selected");
    return res.status(400).json({ message: "No columns selected" });
  }

  try {
    // Preserve order from frontend
    const data = selectedIndexes.map(i => fullData[i]);

    if (!data || data.length === 0) {
      logWarn("PDF export blocked - no data after mapping");
      return res.status(400).json({ message: "No records found" });
    }

    logInfo("Generating PDF document");
    const PDFDocument = require("pdfkit");

    const doc = new PDFDocument({
      size: "A4",
      layout: "landscape",
      margin: 40
    });

    const safeName = (fileName || "Borrowers_Contacted_Report")
      .replace(/\s+/g, "_");

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.pdf"`
    );

    doc.pipe(res);

    // ================= TITLE =================
    doc.font("Helvetica-Bold")
      .fontSize(16)
      .text("Borrowers Contacted By Phone Report", { align: "center" });

    doc.moveDown(1);

    const pageWidth =
      doc.page.width - doc.page.margins.left - doc.page.margins.right;

    const columnWidths = {};
    const equalWidth = pageWidth / columns.length;

    columns.forEach(col => {
      columnWidths[col] = equalWidth;
    });

    const COLUMN_LABELS = {
      serialNumber: "S. No.",
      employeeId: "Employee Id",
      employeeName: "Employee Name",
      accountNumber: "Account Number",
      branchName: "Branch Name",
      borrowerName: "Borrower Name",
      dateOfCall: "Date Of Call",
      numberContacted: "Number Contacted",
      flow: "Flow"
    };

    let y = doc.y;

    const drawHeader = () => {

  let x = doc.page.margins.left;

  doc.font("Helvetica-Bold").fontSize(10);

  // ✅ Dynamic header height
  let headerHeight = 25;

  columns.forEach(col => {
    const textHeight = doc.heightOfString(COLUMN_LABELS[col], {
      width: columnWidths[col] - 10
    });

    headerHeight = Math.max(headerHeight, textHeight + 10);
  });

  columns.forEach(col => {

    doc.rect(x, y, columnWidths[col], headerHeight)
       .fillAndStroke("#e2e8f0", "#94a3b8");

    doc.fillColor("#000")
       .text(COLUMN_LABELS[col], x + 5, y + 5, {
         width: columnWidths[col] - 10,
         align: "center"
       });

    x += columnWidths[col];
  });

  y += headerHeight;

  doc.font("Helvetica").fontSize(9);
};
    drawHeader();

    data.forEach((row, index) => {
      let x = doc.page.margins.left;

      let dynamicHeight = 20;

      columns.forEach(col => {
        const value =
          col === "serialNumber"
            ? selectedIndexes[index] + 1
            : row[col] ?? "";

        const textHeight = doc.heightOfString(String(value), {
          width: columnWidths[col] - 10
        });

        dynamicHeight = Math.max(dynamicHeight, textHeight + 10);
      });

      if (y + dynamicHeight > doc.page.height - 40) {
        doc.addPage({
          size: "A4",
          layout: "landscape",
          margin: 40
        });
        y = doc.page.margins.top;
        drawHeader();
      }

      columns.forEach(col => {
        const value =
          col === "serialNumber"
            ? selectedIndexes[index] + 1
            : row[col] ?? "";

        doc.rect(x, y, columnWidths[col], dynamicHeight).stroke();

        doc.text(String(value), x + 5, y + 5, {
          width: columnWidths[col] - 10,
          align: "center"
        });

        x += columnWidths[col];
      });

      y += dynamicHeight;
    });

    logSuccess("PDF generated successfully", {
  rows: data.length
});

    doc.end();

  } catch (err) {
    logError("PDF EXPORT ERROR", {
  message: err.message,
  stack: err.stack
});
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});




// =====================================================================
// CASH COLLECTION REPORT (ONLY CASH PAYMENTS)
// =====================================================================
app.post("/api/cash-collection-report/search", async (req, res) => {
  const { user, cluster, branch, fromDate, toDate } = req.body;

  logInfo("CASH COLLECTION API HIT", {
  body: req.body
});

  const userIdFromHeader = req.headers["x-user-id"];
  logInfo("User ID received", userIdFromHeader);

  if (!userIdFromHeader) {
  logError("Unauthorized request - missing userId");
  return res.status(401).json([]);
}

  // ✅ Block empty search
 if (!user && !cluster && !branch && !fromDate && !toDate) {
  logWarn("Search blocked - no filters");
  return res.json([]);
}

  try {
    const pool = await poolPromise;
    logInfo("DB connection established");

    logInfo("Fetching user role from DB");
    // 🔍 Get logged-in user details
    const userCheck = await pool.request()
      .input("userId", sql.VarChar(50), userIdFromHeader)
      .query(`
        SELECT Role, BranchName, ClusterName
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    if (userCheck.recordset.length === 0) {
  logError("User not found in DB", userIdFromHeader);
  return res.status(403).json([]);
}

    const loggedUser = userCheck.recordset[0];
    logSuccess("User role fetched", loggedUser);

    const request = pool.request();

    logInfo("Building SQL query");
    let query = `
      SELECT
        A.AssignedToUserId      AS employeeId,
        A.AssignedToUserName    AS userName,
        A.BranchName            AS branchName,
        S.LoanAccountNumber     AS accountNumber,
        R.firstname             AS customerName,
        CONVERT(VARCHAR, L.CreatedAt, 105) AS collectionDate,
        SUM(CAST(P.amount AS DECIMAL(18,2))) AS amountCollected

      FROM Activity_Logs L

      INNER JOIN Activity_Sessions S
        ON L.SessionId = S.SessionId

      INNER JOIN Account_Assignments A
        ON S.AssignmentId = A.AssignmentId

      INNER JOIN Recovery_Raw_Data R
        ON S.LoanAccountNumber = R.loanAccountNumber

      CROSS APPLY OPENJSON(L.MetadataJson, '$.payments')
      WITH (
        type NVARCHAR(50) '$.type',
        amount NVARCHAR(50) '$.amount'
      ) AS P

      WHERE 
        L.ActionCode = 'VISIT_PAYMENT_COLLECTED'
        AND L.ActionLabel = 'Payment Collected During Visit'
        AND P.type = 'CASH'
    `;

    // 🔒 Branch Manager restriction (INSIDE WHERE)
    if (loggedUser.Role === "Branch Manager") {
      logInfo("Applying Branch Manager restriction", loggedUser.BranchName);
      query += ` AND A.BranchName = @restrictedBranch`;
      request.input("restrictedBranch", sql.VarChar(100), loggedUser.BranchName);
    }
	
	// 🔒 Regional Manager restriction
if (loggedUser.Role.startsWith("Regional Manager")) {
logInfo("Applying Regional Manager restriction", loggedUser.Role);
  const match = loggedUser.Role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  query += ` AND A.ClusterName = @rmCluster`;
  request.input("rmCluster", sql.VarChar(100), rmCluster);

}

    // ================= USER FILTER =================
    if (user) {
      logInfo("Filter applied: user", user);
      query += ` AND A.AssignedToUserId = @user`;
      request.input("user", sql.VarChar(50), user);
    }

    // ================= CLUSTER FILTER =================
    if (cluster && cluster !== "Corporate Office") {
      logInfo("Filter applied: cluster", cluster);
      query += ` AND A.ClusterName = @cluster`;
      request.input("cluster", sql.VarChar(100), cluster);
    }

    // ================= BRANCH FILTER =================
    if (branch) {
      logInfo("Filter applied: branch", branch);
      query += ` AND A.BranchName = @branch`;
      request.input("branch", sql.VarChar(100), branch);
    }

    // ================= DATE FILTER =================
    if (fromDate) {
      logInfo("Filter applied: fromDate", fromDate);
      query += ` AND CAST(L.CreatedAt AS DATE) >= @fromDate`;
      request.input("fromDate", sql.Date, fromDate);
    }

    if (toDate) {
      logInfo("Filter applied: toDate", toDate);
      query += ` AND CAST(L.CreatedAt AS DATE) <= @toDate`;
      request.input("toDate", sql.Date, toDate);
    }

    query += `
      GROUP BY
        A.AssignedToUserId,
        A.AssignedToUserName,
        A.BranchName,
        S.LoanAccountNumber,
        R.firstname,
        L.CreatedAt

      ORDER BY L.CreatedAt DESC
    `;

logInfo("Executing SQL query");

logInfo("Final Query Filters", {
  user,
  cluster,
  branch,
  fromDate,
  toDate,
  role: loggedUser.Role
});

    const result = await request.query(query);

    logSuccess("Query executed successfully", {
  count: result.recordset?.length || 0
});

if (!result.recordset.length) {
  logWarn("No records found");
}
logSuccess("CASH COLLECTION API SUCCESS");

    return res.json(result.recordset);

  } catch (err) {
    logError("CASH COLLECTION API ERROR", {
  message: err.message,
  stack: err.stack
});
    return res.status(500).json([]);
  }
});

// ============================================================
// CASH COLLECTION REPORT → EXPORT PDF
// ============================================================

app.post("/api/cash-collection-report/export-pdf", async (req, res) => {
  const { selectedIndexes, columns, fileName, fullData } = req.body;

  logInfo("CASH COLLECTION PDF EXPORT API HIT", {
  selected: req.body.selectedIndexes?.length,
  columns: req.body.columns?.length
});
logInfo("Export file name", fileName);

  if (!selectedIndexes || selectedIndexes.length === 0) {
    logWarn("PDF export blocked - no records selected");
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    logWarn("PDF export blocked - no columns selected");
    return res.status(400).json({ message: "No columns selected" });
  }

  try {

    const data = selectedIndexes.map(i => fullData[i]).filter(Boolean);

    if (data.length === 0) {
      logWarn("PDF export blocked - no data after mapping");
      return res.status(400).json({ message: "No records found" });
    }

logInfo("Generating PDF document");
    const PDFDocument = require("pdfkit");

    const doc = new PDFDocument({
      size: "A4",
      layout: "landscape",
      margin: 40
    });

    const safeName = (fileName || "Cash_Collection_Report")
      .replace(/\s+/g, "_");

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.pdf"`
    );

    doc.pipe(res);

    doc.font("Helvetica-Bold")
       .fontSize(16)
       .text("Cash Collection Report", { align: "center" });

    doc.moveDown(1);

    const pageWidth =
      doc.page.width - doc.page.margins.left - doc.page.margins.right;

    // ===== COLUMN WIDTH FITTING (NO CUT ISSUE) =====
    const columnWidths = {};

    const serialWidth = columns.includes("serialNumber") ? 50 : 0;
    const availableWidth = pageWidth - serialWidth;

    const otherColumns = columns.filter(col => col !== "serialNumber");
    const equalWidth = availableWidth / otherColumns.length;

    columns.forEach(col => {
      if (col === "serialNumber") {
        columnWidths[col] = 50;
      } else {
        columnWidths[col] = equalWidth;
      }
    });

    const COLUMN_LABELS = {
      serialNumber: "S. No.",
      employeeId: "Employee Id",
      userName: "User Name",
      branchName: "Branch Name",
      accountNumber: "Account Number",
      customerName: "Customer Name",
      collectionDate: "Collection Date",
      amountCollected: "Amount Collected"
    };

    let y = doc.y;

    // ===== Dynamic Header =====
    const drawHeader = () => {
      let x = doc.page.margins.left;

      doc.font("Helvetica-Bold").fontSize(10);

      let headerHeight = 25;

      columns.forEach(col => {
        const textHeight = doc.heightOfString(COLUMN_LABELS[col], {
          width: columnWidths[col] - 10
        });
        headerHeight = Math.max(headerHeight, textHeight + 12);
      });

      columns.forEach(col => {
        doc.rect(x, y, columnWidths[col], headerHeight)
           .fillAndStroke("#e2e8f0", "#94a3b8");

        doc.fillColor("#000")
           .text(COLUMN_LABELS[col], x + 5, y + 6, {
             width: columnWidths[col] - 10,
             align: "center"
           });

        x += columnWidths[col];
      });

      y += headerHeight;
      doc.font("Helvetica").fontSize(9);
    };

    drawHeader();

    // ===== Rows =====
    data.forEach((row, index) => {

      let x = doc.page.margins.left;
      let dynamicHeight = 20;

      columns.forEach(col => {

        const value =
          col === "serialNumber"
            ? selectedIndexes[index] + 1
            : row[col] ?? "";

        const textHeight = doc.heightOfString(String(value), {
          width: columnWidths[col] - 10
        });

        dynamicHeight = Math.max(dynamicHeight, textHeight + 10);
      });

      if (y + dynamicHeight > doc.page.height - 40) {
        doc.addPage({
          size: "A4",
          layout: "landscape",
          margin: 40
        });
        y = doc.page.margins.top;
        drawHeader();
      }

      columns.forEach(col => {

        const value =
          col === "serialNumber"
            ? selectedIndexes[index] + 1
            : row[col] ?? "";

        doc.rect(x, y, columnWidths[col], dynamicHeight).stroke();

        doc.text(String(value), x + 5, y + 5, {
          width: columnWidths[col] - 10,
          align: "center"
        });

        x += columnWidths[col];
      });

      y += dynamicHeight;
    });

    logSuccess("PDF generated successfully", {
  rows: data.length
});
    doc.end();

  } catch (err) {
    logError("PDF EXPORT ERROR", {
  message: err.message,
  stack: err.stack
});
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});


// =====================================================================
// USER TRIPS REPORT
// =====================================================================
app.post("/api/user-trips", async (req, res) => {
  const { cluster, branch, fromDate, toDate } = req.body;

  logInfo("USER TRIPS API HIT", {
  body: req.body
});

const role = req.headers["x-user-role"];
const loggedBranch = req.headers["x-user-branch"];
const loggedCluster = req.headers["x-user-cluster"];

logInfo("User context received", {
  role,
  branch: loggedBranch,
  cluster: loggedCluster
});

  if (!cluster && !branch && !fromDate && !toDate) {
    logWarn("Search blocked - no filters provided");
    return res.status(200).json([]);
  }

  try {
logInfo("Starting User Trips DB process");
    const pool = await poolPromise;
    logInfo("DB connection established");
	let finalCluster = cluster;
let finalBranch = branch;

// 🔒 If Branch Manager → force restriction
if (role === "Branch Manager") {
  logInfo("Branch Manager restriction applied", {
  loggedCluster,
  loggedBranch
});
  finalCluster = loggedCluster;
  finalBranch = loggedBranch;
}

// 🔒 Regional Manager restriction
if (role?.startsWith("Regional Manager")) {
  logInfo("Regional Manager restriction applied", role);

  const match = role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  finalCluster = rmCluster;
}

    const request = pool.request();

logInfo("Building SQL query");
    let query = `
      SELECT
        AA.AssignedToUserName     AS UserName,
        AA.AssignedToUserId       AS UserId,
        RR.firstname              AS MemberName,
        AA.LoanAccountNumber      AS AccountNumber,
        AA.BranchName             AS BranchName,

        FORMAT(AA.AssignedAt, 'MMM yyyy') AS MonthYear,
        CAST(AA.AssignedAt AS DATE)       AS VisitDate,

        FVR.DistanceTravelled     AS TotalDistance,
        FVR.DistanceTravelled     AS DistanceTravelled,
        FVR.StartAddress          AS StartLocation,
        FVR.MeetingAddress        AS EndLocation

      FROM smart_call.dbo.Account_Assignments AA

      LEFT JOIN smart_call.dbo.Recovery_Raw_Data RR
        ON AA.LoanAccountNumber = RR.loanAccountNumber

      LEFT JOIN smart_call.dbo.FieldVisitReport FVR
        ON AA.LoanAccountNumber = FVR.AccountNo
        AND AA.AssignedToUserId = FVR.UserID

      WHERE 1 = 1
    `;

    // ================= CLUSTER FILTER =================
    if (finalCluster && finalCluster !== "Corporate Office") {
      logInfo("Filter applied: cluster", finalCluster);
  query += " AND AA.ClusterName = @cluster";
  request.input("cluster", sql.VarChar, finalCluster);
}
    

    // ================= BRANCH FILTER =================
    if (finalBranch) {
      logInfo("Filter applied: branch", finalBranch);
  query += " AND AA.BranchName = @branch";
  request.input("branch", sql.VarChar, finalBranch);
}

    // ================= FROM DATE =================
    if (fromDate) {
      logInfo("Filter applied: fromDate", fromDate);
      query += " AND CAST(AA.AssignedAt AS DATE) >= @fromDate";
      request.input("fromDate", sql.Date, fromDate);
    }

    // ================= TO DATE =================
    if (toDate) {
      logInfo("Filter applied: toDate", toDate);
      query += " AND CAST(AA.AssignedAt AS DATE) <= @toDate";
      request.input("toDate", sql.Date, toDate);
    }

    query += " ORDER BY AA.AssignedAt DESC";

    logInfo("Final filters applied to SQL", {
  finalCluster,
  finalBranch,
  fromDate,
  toDate
});

    logInfo("Executing SQL query", {
  finalCluster,
  finalBranch,
  fromDate,
  toDate,
  role
});
    const result = await request.query(query);

    logSuccess("Query executed successfully", {
  count: result.recordset?.length || 0
});

if (!result.recordset.length) {
  logWarn("No records found");
}

logSuccess("USER TRIPS API SUCCESS", {
  count: result.recordset?.length || 0
});

    return res.status(200).json(result.recordset || []);

  } catch (err) {
    logError("USER TRIPS API ERROR", {
  message: err.message,
  stack: err.stack
});
    return res.status(500).json([]);
  }
});

// ============================================================
// USER TRIPS → EXPORT PDF
// ============================================================

app.post("/api/user-trips/export-pdf", async (req, res) => {
  const { selectedIndexes, columns, fileName, fullData } = req.body;

  logInfo("USER TRIPS PDF EXPORT API HIT", {
  selected: selectedIndexes?.length,
  columns: columns?.length
});

  if (!selectedIndexes || selectedIndexes.length === 0) {
    logWarn("PDF export blocked - no records selected");
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    logWarn("PDF export blocked - no columns selected");
    return res.status(400).json({ message: "No columns selected" });
  }

  try {
    logInfo("Starting PDF generation");

    // Preserve exact order from frontend
    const data = selectedIndexes.map(i => fullData[i]).filter(Boolean);

    if (data.length === 0) {
      logWarn("PDF export blocked - no data after mapping");
      return res.status(400).json({ message: "No records found for PDF" });
    }

    const PDFDocument = require("pdfkit");

    const doc = new PDFDocument({
      size: "A4",
      layout: "landscape",
      margin: 40
    });

    const safeName = (fileName || "User_Trips_Report")
      .replace(/\s+/g, "_");

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.pdf"`
    );

    doc.pipe(res);

    // ================= TITLE =================
    doc.font("Helvetica-Bold")
       .fontSize(16)
       .text("User Trips Report", { align: "center" });

    doc.moveDown(1);

    const pageWidth =
      doc.page.width - doc.page.margins.left - doc.page.margins.right;

    // Column Width Logic (S.No small, others auto)
    const columnWidths = {};

    columns.forEach(col => {
      if (col === "serialNumber") {
        columnWidths[col] = 50;
      } else {
        columnWidths[col] = null;
      }
    });

    const usedWidth = Object.values(columnWidths)
      .filter(w => w !== null)
      .reduce((a, b) => a + b, 0);

    const remainingCols = columns.filter(c => columnWidths[c] === null);
    const remainingWidth = pageWidth - usedWidth;
    const equalWidth = remainingWidth / remainingCols.length;

    remainingCols.forEach(col => {
      columnWidths[col] = equalWidth;
    });

    const COLUMN_LABELS = {
      serialNumber: "S. No.",
      UserName: "User Name",
      UserId: "User Id",
      MemberName: "Member Name",
      AccountNumber: "Account Number",
      BranchName: "Branch Name",
      MonthYear: "Month Year",
      VisitDate: "Date",
      TotalDistance: "Total Distance",
      DistanceTravelled: "Distance Travelled",
      StartLocation: "Start Location",
      EndLocation: "End Location"
    };

    let y = doc.y;
    const drawHeader = () => {

  let x = doc.page.margins.left;

  doc.font("Helvetica-Bold").fontSize(10);

  // 🔥 Calculate dynamic header height
  let headerHeight = 25;

  columns.forEach(col => {

    const textHeight = doc.heightOfString(COLUMN_LABELS[col], {
      width: columnWidths[col] - 10
    });

    headerHeight = Math.max(headerHeight, textHeight + 10);
  });

  columns.forEach(col => {

    doc.rect(x, y, columnWidths[col], headerHeight)
       .fillAndStroke("#e2e8f0", "#94a3b8");

    doc.fillColor("#000")
       .text(COLUMN_LABELS[col], x + 5, y + 5, {
         width: columnWidths[col] - 10,
         align: "center"
       });

    x += columnWidths[col];
  });

  y += headerHeight;

  doc.font("Helvetica").fontSize(9);
};

    drawHeader();

    // ================= ROWS =================
    data.forEach((row, index) => {

      let x = doc.page.margins.left;
      let dynamicHeight = 20;

      columns.forEach(col => {

        let value =
          col === "serialNumber"
            ? selectedIndexes[index] + 1
            : row[col] ?? "";

        if (col === "VisitDate" && value) {
          value = value.toString().split("T")[0];
        }

        const textHeight = doc.heightOfString(String(value), {
          width: columnWidths[col] - 10
        });

        dynamicHeight = Math.max(dynamicHeight, textHeight + 10);
      });

      if (y + dynamicHeight > doc.page.height - 40) {
        doc.addPage({
          size: "A4",
          layout: "landscape",
          margin: 40
        });
        y = doc.page.margins.top;
        drawHeader();
      }

      columns.forEach(col => {

        let value =
          col === "serialNumber"
            ? selectedIndexes[index] + 1
            : row[col] ?? "";

        if (col === "VisitDate" && value) {
          value = value.toString().split("T")[0];
        }

        doc.rect(x, y, columnWidths[col], dynamicHeight).stroke();

        doc.text(String(value), x + 5, y + 5, {
          width: columnWidths[col] - 10,
          align: "center"
        });

        x += columnWidths[col];
      });

      y += dynamicHeight;
    });

    logSuccess("PDF generated successfully", {
  rows: data.length
});
    doc.end();

  } catch (err) {
    logError("USER TRIPS PDF ERROR", {
  message: err.message,
  stack: err.stack
});
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});


// ============================================================
// USER TRIPS → EXPORT EXCEL
// ============================================================

app.post("/api/user-trips/export-excel", async (req, res) => {

  const { selectedIndexes, columns, fileName, fullData } = req.body;

  logInfo("USER TRIPS EXCEL EXPORT API HIT", {
  selected: selectedIndexes?.length,
  columns: columns?.length
});

  try {
logInfo("Starting Excel generation");
    const data = selectedIndexes.map(i => fullData[i]).filter(Boolean);

    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet("User Trips");

    const COLUMN_LABELS = {
      serialNumber: "S. No.",
      UserName: "User Name",
      UserId: "User Id",
      MemberName: "Member Name",
      AccountNumber: "Account Number",
      BranchName: "Branch Name",
      MonthYear: "Month Year",
      VisitDate: "Date",
      TotalDistance: "Total Distance",
      DistanceTravelled: "Distance Travelled",
      StartLocation: "Start Location",
      EndLocation: "End Location"
    };

    // ===== HEADER =====
    sheet.columns = columns.map(col => ({
      header: COLUMN_LABELS[col] || col,
      key: col,
      width: 25
    }));

    // ===== DATA =====
    data.forEach((row, index) => {

      const newRow = {};

      columns.forEach(col => {

        if (col === "serialNumber") {
          newRow[col] = selectedIndexes[index] + 1;
        }
        else if (col === "VisitDate" && row[col]) {
          newRow[col] = row[col].toString().split("T")[0];
        }
        else {
          newRow[col] = row[col] ?? "";
        }

      });

      sheet.addRow(newRow);

    });

    // Header Style
    sheet.getRow(1).font = { bold: true };

    const safeName = (fileName || "User_Trips_Report").replace(/\s+/g, "_");

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.xlsx"`
    );

    // 🔥 IMPORTANT FIX
    await workbook.xlsx.write(res);
    logSuccess("Excel generated successfully", {
  rows: data.length
});
    res.end();

  } catch (err) {

    logError("EXCEL EXPORT ERROR", {
  message: err.message,
  stack: err.stack
});
    res.status(500).send("Excel export failed");

  }

});


// =====================================================================
// LEAD DATA REPORT
// =====================================================================
app.post("/api/lead-data-report", async (req, res) => {

  const loggedUserId = req.headers["x-user-id"];
  logInfo("User context received", {
  loggedUserId
});

  const { userId, cluster, branch, fromDate, toDate } = req.body;

  logInfo("LEAD DATA REPORT API HIT", {
  body: req.body
});

  logInfo("Checking filters", {
  userId,
  cluster,
  branch,
  fromDate,
  toDate
});



  if (!loggedUserId) {
    logWarn("Unauthorized access - missing userId");
    return res.status(401).json({ message: "Unauthorized" });
  }

  if (!userId && !cluster && !branch && !fromDate && !toDate) {
    logWarn("Search blocked - no filters provided");
    return res.json([]);
  }

 try {
  logInfo("Starting Lead Data DB process");

  const pool = await poolPromise;
  logInfo("DB connection established");
    const request = pool.request();

    // ================= GET LOGGED USER ROLE =================
    logInfo("Fetching logged user role", loggedUserId);
    const userInfo = await pool.request()
      .input("userId", sql.VarChar, loggedUserId)
      .query(`
        SELECT Role, BranchName
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    if (!userInfo.recordset.length) {
      logWarn("User not found in UsersInfo table", loggedUserId);
      return res.status(403).json({ message: "User not found" });
    }

    const { Role, BranchName: userBranch } = userInfo.recordset[0];

    logInfo("User role fetched", {
  Role,
  userBranch
});

    const isBranchManager = Role === "Branch Manager";
	const isRegionalManager = Role?.startsWith("Regional Manager");

  logInfo("Role flags", {
  isBranchManager,
  isRegionalManager
});

    // ================= MAIN QUERY =================
    logInfo("Building SQL query");
    let query = `

SELECT

L.BranchName,
L.UserName AS LeadGeneratedBy,
LA.LeadAssignedToUserName AS LeadAssignedTo,
L.FullName AS MemberName,
L.Address AS MemberAddress,
L.MobileNumber AS MemberMobileNumber,
L.ProductCategory,
L.SelectProduct AS InitialProduct,
'' AS InterestedProduct,
CONVERT(VARCHAR, L.TimeStamp, 105) AS DateOfEntry,
'' AS DateOfVisit,

CASE
  WHEN EXISTS (
  SELECT 1
  FROM smart_call.dbo.Activity_Logs AL
  WHERE AL.SourceId = CAST(L.SNo AS VARCHAR(50))
    AND AL.ActionCode = 'LEAD_NO_REQUIREMENT'
    AND AL.ActionLabel = 'Lead Does Not Require Loan'
)
THEN 'NOT INTERESTED'

  WHEN EXISTS (
    SELECT 1
    FROM smart_call.dbo.Activity_Logs AL
    WHERE AL.SourceId = CAST(L.SNo AS VARCHAR(50))
      AND AL.ActionCode = 'LEAD_LOS_CAPTURED'
      AND AL.ActionLabel = 'LOS Number Captured'
  )
  THEN 'OPEN'

  WHEN EXISTS (
    SELECT 1
    FROM smart_call.dbo.Activity_Logs AL
    WHERE AL.SourceId = CAST(L.SNo AS VARCHAR(50))
  )
  THEN 'WORKING'

  ELSE 'PENDING'
END AS ActivityStatus

FROM smart_call.dbo.Leads_Data L

LEFT JOIN smart_call.dbo.Lead_Assignments LA
ON L.SNo = LA.LeadSNo

WHERE 1 = 1
`;

   // 🔒 Branch Manager restriction
if (isBranchManager) {
  logInfo("Branch Manager restriction applied", userBranch);
  query += ` AND L.BranchName = @restrictedBranch `;
  request.input("restrictedBranch", sql.VarChar, userBranch);
}

// 🔒 Regional Manager restriction
if (isRegionalManager) {
logInfo("Regional Manager restriction applied", Role);
  query += `
  AND L.BranchName IN (
    SELECT branch_name
    FROM Branch_Cluster_Master
    WHERE cluster_name = @rmCluster
  )
  `;

  const match = Role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  request.input("rmCluster", sql.VarChar, rmCluster);
}

     // ================= USER FILTER =================
if (userId) {
  logInfo("Filter applied: userId", userId);
  query += `
    AND (
      LA.LeadAssignedToUserId = @userId
      OR L.UserID = @userId
    )
  `;
  request.input("userId", sql.VarChar, userId);
}

    // ================= CLUSTER FILTER =================
    if (cluster && cluster !== "Corporate Office") {
      logInfo("Filter applied: cluster", cluster);
      query += `
      AND L.BranchName IN (
        SELECT branch_name
        FROM Branch_Cluster_Master
        WHERE cluster_name = @cluster
      )
      `;
      request.input("cluster", sql.VarChar, cluster);
    }

    // ================= BRANCH FILTER =================
    if (branch) {
      logInfo("Filter applied: branch", branch);
      query += ` AND L.BranchName = @branch `;
      request.input("branch", sql.VarChar, branch);
    }

    // ================= DATE FILTER =================
    if (fromDate) {
      logInfo("Filter applied: fromDate", fromDate);
      query += ` AND CAST(L.TimeStamp AS DATE) >= @fromDate `;
      request.input("fromDate", sql.Date, fromDate);
    }

    if (toDate) {
      logInfo("Filter applied: toDate", toDate);
      query += ` AND CAST(L.TimeStamp AS DATE) <= @toDate `;
      request.input("toDate", sql.Date, toDate);
    }

    query += ` ORDER BY L.TimeStamp DESC`;

logInfo("Executing SQL query", {
  userId,
  cluster,
  branch,
  fromDate,
  toDate,
  Role
});
    const result = await request.query(query);

    logSuccess("Query executed successfully", {
  count: result.recordset?.length || 0
});

if (!result.recordset.length) {
  logWarn("No records found");
}

    logSuccess("LEAD DATA REPORT API SUCCESS", {
  count: result.recordset?.length || 0
});

res.json(result.recordset || []);

  } catch (err) {

    logError("LEAD DATA REPORT ERROR", {
  message: err.message,
  stack: err.stack
});
    res.status(500).json([]);

  }

});

// ============================================================
// LEAD DATA REPORT → EXPORT PDF
// ============================================================

app.post("/api/lead-data-report/export-pdf", async (req, res) => {
  const { selectedIndexes, columns, fileName, fullData } = req.body;

  logInfo("LEAD DATA PDF EXPORT API HIT", {
  selected: selectedIndexes?.length,
  columns: columns?.length
});

  if (!selectedIndexes || selectedIndexes.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {
logInfo("Starting PDF generation");
    // Preserve exact order from frontend
    const data = selectedIndexes.map(i => fullData[i]).filter(Boolean);

    if (data.length === 0) {
      logWarn("PDF export blocked - no data after mapping");
      return res.status(400).json({ message: "No records found" });
    }

    const PDFDocument = require("pdfkit");

    const doc = new PDFDocument({
      size: "A4",
      layout: "landscape",
      margin: 40
    });

    const safeName = (fileName || "Lead_Data_Report")
      .replace(/\s+/g, "_");

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.pdf"`
    );

    doc.pipe(res);

    // ================= TITLE =================
    doc.font("Helvetica-Bold")
       .fontSize(16)
       .text("Lead Data Report", { align: "center" });

    doc.moveDown(1);

    const pageWidth =
      doc.page.width - doc.page.margins.left - doc.page.margins.right;

    // Column Width Logic
    const columnWidths = {};

const totalColumns = columns.length;

// Special width for S.No
const serialWidth = columns.includes("serialNumber") ? 50 : 0;

const availableWidth = pageWidth - serialWidth;

// Remaining columns
const otherColumns = columns.filter(col => col !== "serialNumber");

// Distribute evenly so total ALWAYS fits page
const equalWidth = availableWidth / otherColumns.length;

columns.forEach(col => {
  if (col === "serialNumber") {
    columnWidths[col] = 50;
  } else {
    columnWidths[col] = equalWidth;
  }
});

const COLUMN_LABELS = {
  serialNumber: "S. No.",
  BranchName: "Branch Name",
  LeadGeneratedBy: "Lead Generated By",
  LeadAssignedTo: "Lead Assigned To",
  MemberName: "Member Name",
  MemberAddress: "Member Address",
  MemberMobileNumber: "Member Mobile Number",
  ProductCategory: "Product Category",
  InitialProduct: "Initial Product",
  InterestedProduct: "Interested Product",
  DateOfEntry: "Date Of Entry",
  DateOfVisit: "Date Of Visit",
  ActivityStatus: "Activity Status"
};

    let y = doc.y;

    // 🔥 Dynamic Header Height
    const drawHeader = () => {
      let x = doc.page.margins.left;

      doc.font("Helvetica-Bold").fontSize(10);

      let headerHeight = 25;

      columns.forEach(col => {
        const textHeight = doc.heightOfString(COLUMN_LABELS[col], {
          width: columnWidths[col] - 10
        });

        headerHeight = Math.max(headerHeight, textHeight + 12);
      });

      columns.forEach(col => {
        doc.rect(x, y, columnWidths[col], headerHeight)
           .fillAndStroke("#e2e8f0", "#94a3b8");

        doc.fillColor("#000")
           .text(COLUMN_LABELS[col], x + 5, y + 6, {
             width: columnWidths[col] - 10,
             align: "center"
           });

        x += columnWidths[col];
      });

      y += headerHeight;
      doc.font("Helvetica").fontSize(9);
    };

    drawHeader();

    // ================= ROWS =================
    data.forEach((row, index) => {

      let x = doc.page.margins.left;
      let dynamicHeight = 20;

      columns.forEach(col => {

        const value =
          col === "serialNumber"
            ? selectedIndexes[index] + 1
            : row[col] ?? "";

        const textHeight = doc.heightOfString(String(value), {
          width: columnWidths[col] - 10
        });

        dynamicHeight = Math.max(dynamicHeight, textHeight + 10);
      });

      if (y + dynamicHeight > doc.page.height - 40) {
        doc.addPage({
          size: "A4",
          layout: "landscape",
          margin: 40
        });
        y = doc.page.margins.top;
        drawHeader();
      }

      columns.forEach(col => {

        const value =
          col === "serialNumber"
            ? selectedIndexes[index] + 1
            : row[col] ?? "";

        doc.rect(x, y, columnWidths[col], dynamicHeight).stroke();

        doc.text(String(value), x + 5, y + 5, {
          width: columnWidths[col] - 10,
          align: "center"
        });

        x += columnWidths[col];
      });

      y += dynamicHeight;
    });

    logSuccess("PDF generated successfully", {
  rows: data.length
});
    doc.end();

  } catch (err) {
    logError("LEAD DATA PDF ERROR", {
  message: err.message,
  stack: err.stack
});
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});


// ============================================================
// LEAD DATA REPORT → EXPORT EXCEL
// ============================================================

app.post("/api/lead-data-report/export-excel", async (req, res) => {

  const { selectedIndexes, columns, fileName, fullData } = req.body;

  logInfo("LEAD DATA EXCEL EXPORT API HIT", {
  selected: selectedIndexes?.length,
  columns: columns?.length
});

  if (!selectedIndexes || selectedIndexes.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {
logInfo("Starting Excel generation");
    const data = selectedIndexes.map(i => fullData[i]).filter(Boolean);

    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet("Lead Data Report");

    const COLUMN_LABELS = {
      serialNumber: "S. No.",
      BranchName: "Branch Name",
      LeadGeneratedBy: "Lead Generated By",
      LeadAssignedTo: "Lead Assigned To",
      MemberName: "Member Name",
      MemberAddress: "Member Address",
      MemberMobileNumber: "Member Mobile Number",
      ProductCategory: "Product Category",
      InitialProduct: "Initial Product",
      InterestedProduct: "Interested Product",
      DateOfEntry: "Date Of Entry",
      DateOfVisit: "Date Of Visit",
      ActivityStatus: "Activity Status"
    };

    // ===== CREATE HEADERS =====
    sheet.columns = columns.map(col => ({
      header: COLUMN_LABELS[col] || col,
      key: col,
      width: 25
    }));

    // ===== INSERT DATA =====
    data.forEach((row, index) => {

      const newRow = {};

      columns.forEach(col => {

        if (col === "serialNumber") {
          newRow[col] = selectedIndexes[index] + 1;
        } else {
          newRow[col] = row[col] ?? "";
        }

      });

      sheet.addRow(newRow);

    });

    // Header Style
    sheet.getRow(1).font = { bold: true };

    const safeName = (fileName || "Lead_Data_Report")
      .replace(/\s+/g, "_");

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.xlsx"`
    );

    logSuccess("Excel generated successfully", {
  rows: data.length
});
    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {

    logError("EXCEL EXPORT ERROR", {
  message: err.message,
  stack: err.stack
});
    res.status(500).json({ message: "Excel export failed" });

  }

});



// =============================
// LEAD DATA UPLOAD (UPDATED SCHEMA)
// =============================
const parseDate = (value) => {
  if (!value) return null;
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
};

const normalizeText = (value) => {
  if (!value) return null;
  return value.toString().trim();
};

const ALLOWED_LEAD_CATEGORIES = ["Known Lead", "Unknown Lead"];
const ALLOWED_LEAD_TYPES = ["Hot Lead", "Warm Lead", "Cold Lead"];

app.post("/api/leads/upload", async (req, res) => {

  const startTime = Date.now();
  logInfo("Leads upload API triggered");
	
	const userId = req.headers["x-user-id"];
logInfo("User ID received", userId);

if (!userId) {
  logWarn("Unauthorized access - No userId");
  return res.status(401).json({ message: "Unauthorized" });
}

  const leads = req.body;
  logInfo("Leads received", { count: leads?.length });

  if (!Array.isArray(leads) || leads.length === 0) {
  logWarn("No data received in request");
  return res.status(400).json({ message: "No data received" });
}

  const pool = await poolPromise;
  logSuccess("Database connection established");
  
  logInfo("User role query executed");

const userInfo = await pool.request()
  .input("userId", sql.VarChar, userId)
  .query(`
    SELECT Role
    FROM UsersInfo
    WHERE UserId = @userId
  `);

if (!userInfo.recordset.length) {
  logWarn("User not found in DB", userId);
  return res.status(403).json({ message: "User not found" });
}

const { Role } = userInfo.recordset[0];
logInfo("User role fetched", Role);

const isAdmin =
  Role === "Admin" || Role === "Super Admin";

if (!isAdmin) {
  logWarn("Unauthorized role trying to upload", Role);
  return res.status(403).json({
    message: "Only Admin can upload leads"
  });
}
  
  const transaction = new sql.Transaction(pool);

  try {

    await transaction.begin();
    logInfo("Transaction started");
	
    // =============================
    // STEP 2 — INSERT NEW DATA
    // =============================
    for (const lead of leads) {

  logInfo("Processing lead", {
    mobile: lead.MobileNumber,
    branch: lead.BranchCode
  });

      const leadCategory = normalizeText(lead.LeadCategory);
      const leadType = normalizeText(lead.SelectLeadType);
      const leadUserId = normalizeText(lead.UserID || lead.UserId);
      const branchCode = normalizeText(lead.BranchCode);
	  const mobileNumber = normalizeText(lead.MobileNumber);

      if (!ALLOWED_LEAD_CATEGORIES.includes(leadCategory)) {
  logError("Invalid LeadCategory", leadCategory);
  throw new Error(`Invalid LeadCategory`);
}

      if (!ALLOWED_LEAD_TYPES.includes(leadType)) {
        logError("Invalid LeadType", leadType);
        throw new Error(`Invalid SelectLeadType`);
      }

      if (!leadUserId) {
  logError("Invalid userId", leadUserId);
  throw new Error(`UserID missing in upload file`);
}

      if (!branchCode) {
        logError("Invalid branchCode", branchCode);
        throw new Error(`BranchCode missing in upload file`);
      }
	  
	  if (!mobileNumber) {    
      logError("Invalid mobileNumber", mobileNumber);                 
  throw new Error(`MobileNumber missing in upload file`);
}

      // ==================================
      // FETCH CLUSTER FROM BRANCH MASTER
      // ==================================
      logInfo("Cluster query executed", branchCode);

const clusterResult = await new sql.Request(transaction)
  .input("BranchCode", sql.VarChar, branchCode)
  .query(`
    SELECT TOP 1 cluster_name
    FROM smart_call.dbo.Branch_Cluster_Master
    WHERE branch_code = @BranchCode
  `);

      if (!clusterResult.recordset.length) {
  logError("Cluster not found", branchCode);
        throw new Error(`Cluster not found for BranchCode: ${branchCode}`);
      }

      const clusterName = clusterResult.recordset[0].cluster_name;
logSuccess("Cluster fetched", clusterName);

      // =============================
      // CREATE SQL REQUEST
      // =============================
      const request = new sql.Request(transaction);

      request.input("BranchCode", sql.VarChar, branchCode);
      request.input("BranchName", sql.VarChar, normalizeText(lead.BranchName));
      request.input("UserID", sql.VarChar, leadUserId);
      request.input("UserName", sql.VarChar, normalizeText(lead.UserName));
      request.input("LeadCategory", sql.VarChar, leadCategory);
      request.input("FullName", sql.VarChar, normalizeText(lead.FullName || lead.FirstName));
      request.input("MobileNumber", sql.VarChar, mobileNumber);
      request.input("Address", sql.VarChar, normalizeText(lead.Address));
      request.input("PinCode", sql.VarChar, normalizeText(lead.PinCode));
      request.input("DOB", sql.Date, parseDate(lead.DOB));
      request.input("ProductCategory", sql.VarChar, normalizeText(lead.ProductCategory));
      request.input("SelectProduct", sql.VarChar, normalizeText(lead.SelectProduct));
      request.input("SelectLeadType", sql.VarChar, leadType);
      request.input("ClusterName", sql.VarChar, clusterName);

      // =============================
// UPSERT INTO MAIN TABLE
// =============================
logInfo("Upsert operation started", mobileNumber);
await request.query(`

IF EXISTS (
  SELECT 1 
  FROM dbo.Leads_Data 
  WHERE MobileNumber = @MobileNumber
)

BEGIN

  UPDATE dbo.Leads_Data
  SET
    BranchCode = @BranchCode,
    BranchName = @BranchName,
    UserID = @UserID,
    UserName = @UserName,
    LeadCategory = @LeadCategory,
    FullName = @FullName,
    Address = @Address,
    PinCode = @PinCode,
    DOB = @DOB,
    ProductCategory = @ProductCategory,
    SelectProduct = @SelectProduct,
    SelectLeadType = @SelectLeadType,
    ClusterName = @ClusterName,
    TimeStamp = GETDATE()
  WHERE MobileNumber = @MobileNumber

END

ELSE

BEGIN

  INSERT INTO dbo.Leads_Data (
    BranchCode,
    BranchName,
    UserID,
    UserName,
    LeadCategory,
    FullName,
    MobileNumber,
    Address,
    PinCode,
    DOB,
    ProductCategory,
    SelectProduct,
    SelectLeadType,
    TimeStamp,
    ClusterName
  )
  VALUES (
    @BranchCode,
    @BranchName,
    @UserID,
    @UserName,
    @LeadCategory,
    @FullName,
    @MobileNumber,
    @Address,
    @PinCode,
    @DOB,
    @ProductCategory,
    @SelectProduct,
    @SelectLeadType,
    GETDATE(),
    @ClusterName
  )

END

`);
logSuccess("Upsert completed", mobileNumber);

      // =============================
      // INSERT INTO HISTORY TABLE
      // =============================
      logInfo("Inserting into history table", mobileNumber);
      await request.query(`
        INSERT INTO dbo.Leads_Data_History (
          BranchCode,
          BranchName,
          UserID,
          UserName,
          LeadCategory,
          FullName,
          MobileNumber,
          Address,
          PinCode,
          DOB,
          ProductCategory,
          SelectProduct,
          SelectLeadType,
          TimeStamp,
          UploadedAt,
          ClusterName
        )
        VALUES (
          @BranchCode,
          @BranchName,
          @UserID,
          @UserName,
          @LeadCategory,
          @FullName,
          @MobileNumber,
          @Address,
          @PinCode,
          @DOB,
          @ProductCategory,
          @SelectProduct,
          @SelectLeadType,
          GETDATE(),
          GETDATE(),
          @ClusterName
        )
      `);
      logSuccess("History inserted", mobileNumber);

    }

    await transaction.commit();
logSuccess("Transaction committed successfully");

logSuccess("Leads upload completed", { count: leads.length });
logSuccess("API execution time (ms)", Date.now() - startTime);

res.json({
  message: "Leads uploaded successfully",
  count: leads.length
});

  } catch (err) {

  await transaction.rollback();
  logWarn("Transaction rolled back");

  logError("Leads upload error", err);
  logError("API failed in ms", Date.now() - startTime);

  res.status(500).json({
    message: "Upload failed",
    error: err.message
  });

}

});



// =============================
// LEAD LIST
// =============================

app.post("/api/lead/list/search", async (req, res) => {
  logInfo("API HIT: POST /api/lead/list/search", req.body);
  try {
    const {
  memberName,
  mobileNumber,
  pincode,
  cluster,
  branch,
  product,
  leadType,
  assignedTo
} = req.body;
	
	// 🔐 Get logged-in user
const loggedUserId = req.headers["x-user-id"];
if (!loggedUserId) {
  logWarn("Unauthorized access - No userId");
  return res.status(401).json([]);
}

    const pool = await poolPromise;
    const request = pool.request();
	
    logInfo("Fetching logged user info", loggedUserId);
	// 🔐 Get role and branch of logged user
const userInfo = await pool.request()
  .input("userId", sql.VarChar, loggedUserId)
  .query(`
    SELECT Role, BranchName, ClusterName
    FROM smart_call.dbo.UsersInfo
    WHERE UserId = @userId
  `);

  if (!userInfo.recordset.length) {
  logWarn("User not found in DB", loggedUserId);
  return res.status(403).json([]);
}
logSuccess("Logged user info fetched", userInfo.recordset?.[0] || {});

const { Role, BranchName: userBranch, ClusterName: userCluster } = userInfo.recordset[0];
const isBranchManager = Role === "Branch Manager";
const isRegionalManager = Role?.startsWith("Regional Manager");

    let sqlQuery = `
SELECT
  L.SNo,
  L.FullName AS firstName,
  L.MobileNumber AS mobileNumber,
  L.BranchName AS branch,
  L.SelectLeadType AS leadType,

  CASE
    WHEN AL_NOT_INTERESTED.SourceId IS NOT NULL THEN 'NOT INTERESTED'
    WHEN AL_LOS.SourceId IS NOT NULL THEN 'OPEN'
    WHEN AL_ANY.SourceId IS NOT NULL THEN 'WORKING'
    ELSE 'PENDING'
  END AS status

FROM smart_call.dbo.Leads_Data L

LEFT JOIN smart_call.dbo.Lead_Assignments LA
ON L.SNo = LA.LeadSNo

-- Any activity log
LEFT JOIN (
    SELECT DISTINCT SourceId
    FROM smart_call.dbo.Activity_Logs
) AL_ANY
ON AL_ANY.SourceId = CAST(L.SNo AS VARCHAR(50))

-- LOS Captured
LEFT JOIN (
    SELECT DISTINCT SourceId
    FROM smart_call.dbo.Activity_Logs
    WHERE ActionCode = 'LEAD_LOS_CAPTURED'
      AND ActionLabel = 'LOS Number Captured'
) AL_LOS
ON AL_LOS.SourceId = CAST(L.SNo AS VARCHAR(50))

-- Not Interested (Latest Log - Multiple Conditions)
LEFT JOIN (
    SELECT SourceId
    FROM (
        SELECT 
            SourceId,
            ActionCode,
            ActionLabel,
            ROW_NUMBER() OVER (PARTITION BY SourceId ORDER BY CreatedAt DESC) AS rn
        FROM smart_call.dbo.Activity_Logs
    ) t
    WHERE rn = 1
      AND (
(ActionCode = 'LEAD_NO_REQUIREMENT'
             AND ActionLabel = 'Lead Does Not Require Loan')
      )
) AL_NOT_INTERESTED
ON AL_NOT_INTERESTED.SourceId = CAST(L.SNo AS VARCHAR(50))

WHERE 1 = 1
`;

// 🔒 Branch Manager Restriction
if (isBranchManager) {
  sqlQuery += `
    AND LTRIM(RTRIM(LOWER(L.BranchName))) = LOWER(@restrictedBranch)
  `;
  request.input("restrictedBranch", sql.VarChar, userBranch.trim());
}

// 🔒 Regional Manager Restriction
if (isRegionalManager) {
  sqlQuery += `
    AND LTRIM(RTRIM(LOWER(L.ClusterName))) = LOWER(@restrictedCluster)
  `;
  request.input("restrictedCluster", sql.VarChar, userCluster.trim());
}

    let filterApplied = false;

    // 🔎 Member Name
    if (memberName) {
      sqlQuery += " AND L.FullName LIKE @memberName";
      request.input("memberName", sql.VarChar, `%${memberName}%`);
      filterApplied = true;
    }

   // 🔎 Mobile
if (mobileNumber) {
  sqlQuery += " AND CAST(L.MobileNumber AS VARCHAR(20)) LIKE @mobileNumber";
  request.input("mobileNumber", sql.VarChar, `%${mobileNumber}%`);
  filterApplied = true;
}

    // 🔎 Pincode
    if (pincode) {
      sqlQuery += " AND L.PinCode = @pincode";
      request.input("pincode", sql.VarChar, pincode);
      filterApplied = true;
    }

    // 🔎 Cluster
    if (cluster) {
      if (cluster !== "Corporate Office") {
        sqlQuery += " AND LTRIM(RTRIM(LOWER(L.ClusterName))) = LOWER(@cluster)";
        request.input("cluster", sql.VarChar, cluster.trim());
      }
      // Corporate Office = no filter but still considered selected
      filterApplied = true;
    }

    // 🔎 Branch
    if (branch) {
      sqlQuery += " AND LTRIM(RTRIM(LOWER(L.BranchName))) = LOWER(@branch)";
      request.input("branch", sql.VarChar, branch.trim());
      filterApplied = true;
    }

    // 🔎 Product
    if (product) {
      sqlQuery += " AND L.SelectProduct LIKE @product";
      request.input("product", sql.VarChar, `%${product}%`);
      filterApplied = true;
    }

    // 🔎 Lead Type
    if (leadType) {
      sqlQuery += " AND L.SelectLeadType = @leadType";
      request.input("leadType", sql.VarChar, leadType);
      filterApplied = true;
    }
	
	// 🔎 Assigned To
if (assignedTo) {

  // Show only leads assigned to that user
  sqlQuery += " AND LA.LeadAssignedToUserId = @assignedTo";
  request.input("assignedTo", sql.VarChar, assignedTo);
  filterApplied = true;

} else {

  // If Assigned To NOT selected → show only PENDING leads
  sqlQuery += " AND LA.LeadSNo IS NULL";

}
    // ✅ IMPORTANT: If no filter applied → return empty
    if (!filterApplied) {
      logWarn("Search attempted without filters");
      return res.json([]);
    }
	
    sqlQuery += " ORDER BY L.TimeStamp DESC";

    logInfo("Executing Lead Search Query", {
  filters: req.body,
});
    const result = await request.query(sqlQuery);
    logSuccess("Lead list fetched", { count: result.recordset.length });
    res.json(result.recordset);

  } catch (err) {
    logError("Lead List Search Failed", err);
    res.status(500).json([]);
  }
});

// =============================
// LEAD DETAILS
// =============================
app.get("/api/lead/details/:sno", async (req, res) => {
  logInfo("API HIT: GET /api/lead/details", req.params.sno);
  try {

    const { sno } = req.params;

    const pool = await poolPromise;
logInfo("Fetching lead details", sno);
    const result = await pool.request()
      .input("sno", sql.Int, sno)
      .query(`
        SELECT
          FullName,
          MobileNumber,
          Address,
          PinCode,
          DOB,
          SelectProduct
        FROM smart_call.dbo.Leads_Data
        WHERE SNo = @sno
      `);

    if (!result.recordset.length) {
      logWarn("Lead details not found", sno);
      return res.json({});
    }

    logSuccess("Lead details fetched", result.recordset[0]);
    res.json(result.recordset[0]);

  } catch (err) {
    logError("Lead Details API Failed", err);
    res.status(500).json({});
  }
});


// =====================================
// ASSIGN LEADS (LEAD LIST)
// =====================================

app.post("/api/lead/assign", async (req, res) => {
  logInfo("API HIT: POST /api/lead/assign", req.body);

  try {

    const { mobileNumbers, assignedUserId } = req.body;
    const adminUserId = req.headers["x-user-id"];

    if (!adminUserId) {
logWarn("Unauthorized assign attempt");
      return res.status(401).json({ message: "Unauthorized" });
    }

    
    if (!mobileNumbers || mobileNumbers.length === 0) {
      logWarn("Assign attempted with no leads selected");
      return res.json({ message: "No leads selected" });
    }

    // ✅ CONNECT FIRST
   const pool = await poolPromise;

   logInfo("Fetching admin info", adminUserId);
    // 🔐 Get admin role and branch
    const adminInfoFull = await pool.request()
      .input("userId", sql.VarChar, adminUserId)
      .query(`
        SELECT Role, BranchName
        FROM smart_call.dbo.UsersInfo
        WHERE UserId = @userId
      `);
      
    if (!adminInfoFull.recordset.length) {
      logWarn("Admin not found", adminUserId);
      return res.status(403).json({ message: "User not found" });
    }
    logSuccess("Admin info fetched", adminInfoFull.recordset?.[0] || {});

    const { Role, BranchName: adminBranch } = adminInfoFull.recordset[0];
    const isBranchManager = Role === "Branch Manager";

    // Get Admin Info
    const adminInfo = await pool.request()
      .input("userId", sql.VarChar, adminUserId)
      .query(`
        SELECT UserId, UserName
        FROM smart_call.dbo.UsersInfo
        WHERE UserId = @userId
      `);

    const adminName = adminInfo.recordset[0].UserName;

    logInfo("Fetching assigned user info", assignedUserId);
    // Get Assigned User Info
    const userInfo = await pool.request()
      .input("userId", sql.VarChar, assignedUserId)
      .query(`
        SELECT UserId, UserName, BranchCode, BranchName, ClusterName
        FROM smart_call.dbo.UsersInfo
        WHERE UserId = @userId
      `);

    if (!userInfo.recordset.length) {
      logWarn("Assigned user not found", assignedUserId);
      return res.json({ message: "Assigned user not found" });
    }

    const assignedUser = userInfo.recordset[0];
    logSuccess("Assigned user fetched", assignedUser || {});

    let assignedCount = 0;

    for (const mobile of mobileNumbers) {
      logInfo("Processing lead", mobile);

      let leadQuery = `
      SELECT TOP 1
        SNo,
        MobileNumber,
        FullName,
        ProductCategory,
        SelectProduct,
        BranchName
      FROM smart_call.dbo.Leads_Data
      WHERE MobileNumber = @mobile
      `;

      const leadRequest = pool.request();
      leadRequest.input("mobile", sql.VarChar, mobile);

      if (isBranchManager) {
        leadQuery += " AND LOWER(LTRIM(RTRIM(BranchName))) = LOWER(@restrictedBranch)";
        leadRequest.input("restrictedBranch", sql.VarChar, adminBranch.trim());
      }

      const leadData = await leadRequest.query(leadQuery);

      if (!leadData.recordset.length) {
  logWarn("Lead not found", mobile);
  continue;
}

      const lead = leadData.recordset[0];
	  
	  // 🚫 Do not allow assignment if lead is OPEN or NOT INTERESTED
const activityCheck = await pool.request()
  .input("sourceId", sql.VarChar, String(lead.SNo))
  .query(`
    SELECT TOP 1 ActionCode
    FROM smart_call.dbo.Activity_Logs
    WHERE SourceId = @sourceId
    AND ActionCode IN (
  'LEAD_LOS_CAPTURED',
  'LEAD_NOT_INTERESTED_OTHER_REASON',
  'LEAD_NO_REQUIREMENT'
)
  `);

if (activityCheck.recordset.length > 0) {
  logWarn("Lead skipped (already completed)", lead.SNo);
  continue; // skip this lead
}

      await pool.request()
        .input("LeadSNo", sql.Int, lead.SNo)
        .input("LeadMobileNumber", sql.VarChar(20), lead.MobileNumber)
        .input("LeadFullName", sql.VarChar(200), lead.FullName)
        .input("LeadProductCategory", sql.VarChar(100), lead.ProductCategory)
        .input("LeadSelectProduct", sql.VarChar(100), lead.SelectProduct)
        .input("LeadAssignedToUserId", sql.VarChar(50), assignedUser.UserId)
        .input("LeadAssignedToUserName", sql.VarChar(200), assignedUser.UserName)
        .input("LeadAssignedByAdminId", sql.VarChar(50), adminUserId)
        .input("LeadAssignedByAdminName", sql.VarChar(200), adminName)
        .input("BranchCode", sql.VarChar(20), assignedUser.BranchCode)
        .input("BranchName", sql.VarChar(200), assignedUser.BranchName)
        .input("ClusterName", sql.VarChar(200), assignedUser.ClusterName)
        .query(`
          INSERT INTO smart_call.dbo.Lead_Assignments
          (
            LeadSNo,
            LeadMobileNumber,
            LeadFullName,
            LeadProductCategory,
            LeadSelectProduct,
            LeadAssignedToUserId,
            LeadAssignedToUserName,
            LeadAssignedByAdminId,
            LeadAssignedByAdminName,
            BranchCode,
            BranchName,
            ClusterName,
            LeadAssignmentStatus,
            LeadWorkStatus,
            LeadAssignedAt
          )
          VALUES
          (
            @LeadSNo,
            @LeadMobileNumber,
            @LeadFullName,
            @LeadProductCategory,
            @LeadSelectProduct,
            @LeadAssignedToUserId,
            @LeadAssignedToUserName,
            @LeadAssignedByAdminId,
            @LeadAssignedByAdminName,
            @BranchCode,
            @BranchName,
            @ClusterName,
            'ASSIGNED',
            'PENDING',
            GETDATE()
          )
        `);

      assignedCount++;
      logSuccess("Lead assigned", {
  leadSNo: lead.SNo,
  assignedTo: assignedUser.UserId
});

    }

    logSuccess("Assignment completed", { assignedCount });
    res.json({
      message: `${assignedCount} lead(s) assigned successfully`
    });

  } catch (err) {
    logError("Lead Assign Failed", err);
    res.status(500).json({ message: "Assignment failed" });
  }

});

// ============================================================
// LEAD ACTIVITY STATUS PAGE
// ============================================================
app.post("/api/leads-data/search", async (req, res) => {

  logInfo("API HIT: POST /api/leads-data/search", req.body);
const startTime = Date.now();

  const userId = req.headers["x-user-id"];

  if (!userId) {
    logWarn("Unauthorized access - No userId");
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {

    const {
      memberName = "",
      mobileNumber = "",
      pincode = "",
      cluster = "",
      branchName = "",
      product = "",
      leadType = "",
      leadStatus = "",
      assignedTo = "",
      closedBy = "",
	  actionType = ""  
    } = req.body;

    const pool = await poolPromise;

    // 🔒 Get logged-in user role
    const userInfo = await pool.request()
      .input("userId", sql.VarChar, userId)
      .query(`
        SELECT Role, BranchName, ClusterName
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    if (!userInfo.recordset.length) {
  logWarn("User not found in DB", userId);   // ✅ ADD THIS LINE
  return res.status(403).json({ message: "User not found" });
}

logSuccess("User info fetched", userInfo.recordset?.[0] || {});

    const { Role, BranchName: userBranch, ClusterName: userCluster } = userInfo.recordset[0];

const isBranchManager = Role === "Branch Manager";
const isRegionalManager = Role?.startsWith("Regional Manager");

    const request = pool.request();

    let query = `
SELECT

AL.SourceId AS loanAccountNumber,

ISNULL(LD.FullName,'-') AS memberName,
ISNULL(LD.MobileNumber,'-') AS mobileNumber,

COALESCE(LA.BranchName,LD.BranchName) AS branchName,
COALESCE(LA.ClusterName,LD.ClusterName) AS clusterName,

ISNULL(LA.LeadAssignedToUserName,'-') AS assignedTo,

COALESCE(LA.LeadAssignedToUserName,LD.UserName) AS closedBy,

FORMAT(MAX(AL.CreatedAt),'dd-MM-yyyy') AS activityDate,
FORMAT(MAX(AL.CreatedAt),'hh:mm tt') AS activityTime

FROM smart_call.dbo.Activity_Logs AL

INNER JOIN (
  SELECT SourceId, MAX(LogId) AS LatestLogId
  FROM smart_call.dbo.Activity_Logs
  WHERE SourceType = 'LEAD'
  GROUP BY SourceId
) Latest
ON AL.LogId = Latest.LatestLogId

LEFT JOIN smart_call.dbo.Leads_Data LD
ON LD.SNo = AL.SourceId

LEFT JOIN smart_call.dbo.Lead_Assignments LA
ON LA.LeadSNo = AL.SourceId

WHERE AL.SourceType='LEAD'
AND AL.ActionCode NOT IN ('LEAD_REACTIVATED')
`;

// ✅ Past Schedule
if (actionType === "past") {
  query += `
AND TRY_CAST(JSON_VALUE(AL.MetadataJson, '$.date') AS DATE) < CAST(GETDATE() AS DATE)
`;
}

// ✅ Future Schedule
if (actionType === "future") {
  query += `
AND TRY_CAST(JSON_VALUE(AL.MetadataJson, '$.date') AS DATE) >= CAST(GETDATE() AS DATE)
`;
}


    // 🔒 Branch Manager restriction
    if (isBranchManager) {

      query += `
AND COALESCE(LA.BranchName,LD.BranchName)=@restrictedBranch
`;

      request.input("restrictedBranch", sql.VarChar, userBranch);
    }
	
	// 🔒 Regional Manager restriction
if (isRegionalManager) {

  query += `
AND COALESCE(LA.ClusterName,LD.ClusterName)=@restrictedCluster
`;

  request.input("restrictedCluster", sql.VarChar, userCluster);
}	

    // Member Name
    if (memberName) {

      query += `
AND LD.FullName LIKE @memberName
`;

      request.input("memberName", sql.VarChar, `%${memberName}%`);
    }

    // Mobile Number
    if (mobileNumber) {

      query += `
AND LD.MobileNumber LIKE @mobileNumber
`;

      request.input("mobileNumber", sql.VarChar, `%${mobileNumber}%`);
    }

    // Pincode
    if (pincode) {

      query += `
AND LD.PinCode=@pincode
`;

      request.input("pincode", sql.VarChar, pincode);
    }

    // Cluster (Assigned + Unassigned)
    if (cluster && cluster !== "Corporate Office") {

      query += `
AND COALESCE(LA.ClusterName,LD.ClusterName)=@cluster
`;

      request.input("cluster", sql.VarChar, cluster);
    }

    // Branch (Assigned + Unassigned)
    if (branchName) {

      query += `
AND COALESCE(LA.BranchName,LD.BranchName)=@branchName
`;

      request.input("branchName", sql.VarChar, branchName);
    }

    // Product
    if (product) {

      query += `
AND LD.SelectProduct=@product
`;

      request.input("product", sql.VarChar, product);
    }

    // Lead Type
    if (leadType) {

      query += `
AND LD.SelectLeadType=@leadType
`;

      request.input("leadType", sql.VarChar, leadType);
    }

    // Assigned To
    if (assignedTo) {

      query += `
AND LA.LeadAssignedToUserName=@assignedTo
`;

      request.input("assignedTo", sql.VarChar, assignedTo);
    }

    // Closed By
    if (closedBy) {

      query += `
AND COALESCE(LA.LeadAssignedToUserName,LD.UserName)=@closedBy
`;

      request.input("closedBy", sql.VarChar, closedBy);
    }

 // ============================================================
// Lead Status Logic (Activity Logs Based)
// ============================================================

if (leadStatus === "Open") {

  query += `
AND EXISTS (
SELECT 1
FROM smart_call.dbo.Activity_Logs A2
WHERE A2.SourceType='LEAD'
AND A2.SourceId = LD.SNo
AND A2.ActionCode='LEAD_LOS_CAPTURED'
)
`;

}

if (leadStatus === "Closed-Converted") {

  query += `
AND EXISTS (
SELECT 1
FROM smart_call.dbo.Activity_Logs A2
WHERE A2.SourceType='LEAD'
AND A2.SourceId = LD.SNo
AND A2.ActionCode='LEAD_LOS_CAPTURED'
)
`;

}

if (leadStatus === "Closed-Not Converted") {

  query += `
AND EXISTS (
SELECT 1
FROM smart_call.dbo.Activity_Logs A2
WHERE A2.SourceType='LEAD'
AND A2.SourceId = LD.SNo
AND A2.ActionCode='LEAD_NOT_INTERESTED'
)
`;

}

if (leadStatus === "Working") {

  query += `
AND EXISTS (
SELECT 1
FROM smart_call.dbo.Activity_Logs A2
WHERE A2.SourceType='LEAD'
AND A2.SourceId = LD.SNo
)
AND NOT EXISTS (
SELECT 1
FROM smart_call.dbo.Activity_Logs A3
WHERE A3.SourceType='LEAD'
AND A3.SourceId = LD.SNo
AND A3.ActionCode IN ('LEAD_LOS_CAPTURED','LEAD_NOT_INTERESTED')
)
`;

}

    query += `
GROUP BY

AL.SourceId,
LD.FullName,
LD.MobileNumber,
LD.UserName,

LA.LeadAssignedToUserName,

LA.BranchName,
LD.BranchName,

LA.ClusterName,
LD.ClusterName

ORDER BY MAX(AL.CreatedAt) DESC
`;

logInfo("Executing leads activity search query", {
  filters: req.body
});

logInfo("Final query params", {
  filters: req.body,
  role: Role,
  branch: userBranch,
  cluster: userCluster
});

logInfo("Query execution started");
    const result = await request.query(query);

    if (result.recordset.length === 0) {
  logWarn("No records found for filters", req.body);
}

    logSuccess("Leads activity data fetched", {
  count: result.recordset.length,
  timeTaken: `${Date.now() - startTime}ms`
});

    res.json(result.recordset);

  }

  catch (err) {

    logError("Leads Activity Search Failed", {
  error: err.message,
  stack: err.stack,
  userId
});
    res.status(500).json([]);

  }

});

// ============================================================
// LEAD ACTIVITY DETAILS POPUP
// ============================================================

app.post("/api/lead-activity-details", async (req, res) => {

  logInfo("API HIT: POST /api/lead-activity-details", req.body);
const startTime = Date.now();

  const userId = req.headers["x-user-id"];

  if (!userId) {
    logWarn("Unauthorized access - No userId");
    return res.status(401).json([]);
  }

  try {

    const leadSNo = req.body.leadSNo ? String(req.body.leadSNo) : "";

    if (!leadSNo) {
      logWarn("Lead activity details called without leadSNo");
      return res.json([]);
    }

    const pool = await poolPromise;

    // 🔒 Get logged-in user role + branch
    const userInfo = await pool.request()
      .input("userId", sql.VarChar, userId)
      .query(`
        SELECT Role, BranchName, ClusterName
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    if (!userInfo.recordset.length) {
      logWarn("User not found in DB", userId);
      return res.status(403).json([]);
    }
    logSuccess("User info fetched", userInfo.recordset?.[0] || {});

    const { Role, BranchName: userBranch, ClusterName: userCluster } = userInfo.recordset[0];

const isBranchManager = Role === "Branch Manager";
const isRegionalManager = Role?.startsWith("Regional Manager");

    const request = pool.request();

    let query = `
        SELECT
          FORMAT(MAX(AL.CreatedAt),'dd-MM-yyyy') AS activityDate,
          FORMAT(MAX(AL.CreatedAt),'hh:mm tt') AS activityTime,

          MAX(AL.CreatedByUserName) AS userName,

          CASE
  WHEN MAX(AL.ActionCode) IN ('LEAD_SPOKE', 'LEAD_NOT_SPOKE')
  THEN 'Call'
  ELSE MAX(AL.ActionLabel)
END AS activityType,

          STRING_AGG(AL.ActionLabel,' -> ') AS activityStatus,

          MAX(AL.MetadataJson) AS notes

        FROM smart_call.dbo.Activity_Logs AL

        WHERE
          AL.SourceType = 'LEAD'
          AND AL.SourceId = @leadSNo
    `;

    request.input("leadSNo", sql.VarChar, leadSNo);

    // 🔒 Branch Manager restriction
    if (isBranchManager) {

  query += `
    AND EXISTS (
      SELECT 1
      FROM smart_call.dbo.Leads_Data LD
      LEFT JOIN smart_call.dbo.Lead_Assignments LA
      ON LA.LeadSNo = LD.SNo
      WHERE LD.SNo = AL.SourceId
      AND COALESCE(LA.BranchName,LD.BranchName) = @restrictedBranch
    )
  `;

  request.input("restrictedBranch", sql.VarChar, userBranch);
}

// 🔒 Regional Manager restriction
if (isRegionalManager) {

  query += `
    AND EXISTS (
      SELECT 1
      FROM smart_call.dbo.Leads_Data LD
      LEFT JOIN smart_call.dbo.Lead_Assignments LA
      ON LA.LeadSNo = LD.SNo
      WHERE LD.SNo = AL.SourceId
      AND COALESCE(LA.ClusterName,LD.ClusterName) = @restrictedCluster
    )
  `;

  request.input("restrictedCluster", sql.VarChar, userCluster);

}

    query += `
        GROUP BY AL.SessionId
        ORDER BY MAX(AL.CreatedAt) DESC
    `;

logInfo("Executing activity details query", { leadSNo });

    const result = await request.query(query);

  logSuccess("Activity details fetched", {
  count: result.recordset.length,
  timeTaken: `${Date.now() - startTime}ms`
});

    res.json(result.recordset);

  } catch (err) {

    logError("Activity Details API Failed", err);
    res.status(500).json([]);

  }

});

// ============================================================
// REACTIVATE LEADS (PROPER LOG CHAIN)
// ============================================================
app.post("/api/leads/reactivate", async (req, res) => {

  logInfo("API HIT: POST /api/leads/reactivate", req.body);
  const startTime = Date.now();

  const userId = req.headers["x-user-id"];
  const { leadIds } = req.body;

  // 🔐 Validation
  if (!userId || !leadIds || leadIds.length === 0) {
    logWarn("Invalid reactivate request", { userId, leadIds });
    return res.status(400).json({ message: "Invalid request" });
  }

  try {

    const pool = await poolPromise;

    // ✅ Get username
    const userInfo = await pool.request()
      .input("userId", sql.VarChar, userId)
      .query(`
        SELECT UserName 
        FROM UsersInfo 
        WHERE UserId = @userId
      `);

    const userName = userInfo.recordset[0]?.UserName || "System";

    logSuccess("User fetched for reactivation", {
      userId,
      userName
    });

    // 🔁 Loop through leads
    for (const leadId of leadIds) {

      try {

        logInfo("Reactivating lead", leadId);

        await pool.request()
          .input("leadId", sql.BigInt, leadId)
          .input("userId", sql.VarChar, userId)
          .input("userName", sql.VarChar, userName)
          .query(`

INSERT INTO smart_call.dbo.Activity_Logs
(
  SessionId,
  ParentLogId,
  ActionCode,
  ActionLabel,
  MetadataJson,
  CreatedAt,
  CreatedByUserId,
  CreatedByUserName,
  IsPrimaryAction,
  SourceType,
  SourceId
)

SELECT
  AL.SessionId,
  AL.LogId,

  'LEAD_REACTIVATED',
  'Lead Reactivated',

  JSON_MODIFY(
    ISNULL(AL.MetadataJson, '{}'),
    '$.date',
    FORMAT(GETDATE(),'yyyy-MM-dd HH:mm:ss')
  ),

  GETDATE(),
  @userId,
  @userName,
  1,
  'LEAD',
  @leadId

FROM (
  SELECT TOP 1 *
  FROM smart_call.dbo.Activity_Logs
  WHERE SourceId = @leadId
  ORDER BY LogId DESC
) AL

          `);

        logSuccess("Lead reactivated", leadId);

      } catch (err) {

        logError("Lead reactivation failed", {
          leadId,
          error: err.message
        });

      }

    }

    // ✅ Final success log
    logSuccess("Reactivation completed", {
      total: leadIds.length,
      timeTaken: `${Date.now() - startTime}ms`
    });

    res.json({
      message: "Leads reactivated successfully"
    });

  } catch (err) {

    logError("Lead Reactivation Failed", {
      error: err.message,
      stack: err.stack,
      userId
    });

    res.status(500).json({
      message: "Reactivation failed"
    });

  }

});



// ======================================================================
// SMA REPORT UPLOAD (STORE VALUES EXACTLY AS IN EXCEL)
// ======================================================================

function convertExcelDate(value) {

  if (!value) return "";

  if (typeof value === "number") {

    const excelEpoch = new Date(1899, 11, 30);

    const jsDate = new Date(excelEpoch.getTime() + value * 86400000);

    const day = String(jsDate.getDate()).padStart(2,'0');
    const month = String(jsDate.getMonth()+1).padStart(2,'0');
    const year = jsDate.getFullYear();

    return `${day}-${month}-${year}`;
  }

  return value;
}


const multer = require("multer");
const XLSX = require("xlsx");
const path = require("path");

const upload = multer({
  storage: multer.memoryStorage()
});

function safeString(value, maxLength = 255) {

  if (value === undefined || value === null) return "";

  let str = String(value).trim();

  if (str.length > maxLength) {
    str = str.substring(0, maxLength);
  }

  return str;
}

app.post("/api/sma/upload", upload.single("file"), async (req, res) => {
  logInfo("SMA Upload API called");
	
	const userId = req.headers["x-user-id"];
  logInfo("User ID received", userId);

  if (!userId) {
  logWarn("Unauthorized request - No userId");
    return res.status(401).json({ message: "Unauthorized" });
  }
  
  const pool = await poolPromise;

  // 🔒 Check user role
  const userInfo = await pool.request()
    .input("userId", sql.VarChar, userId)
    .query(`
      SELECT Role
      FROM UsersInfo
      WHERE UserId = @userId
    `);

  if (!userInfo.recordset.length) {
  logWarn("User not found in DB");
  return res.status(403).json({ message: "User not found" });
}
  logInfo("User info fetched");

  const { Role } = userInfo.recordset[0];
  logInfo("User role", Role);

  const isAdmin =
    Role === "Admin" || Role === "Super Admin";

    if (isAdmin) {
  logSuccess("Authorized user for upload");
}

  if (!isAdmin) {
  logWarn("Unauthorized upload attempt", Role);
    return res.status(403).json({
      message: "Only Admin can upload SMA file"
    });
  }

  try {
    logInfo("File processing started");

    if (!req.file) {
  logWarn("No file uploaded");
  return res.status(400).json({ message: "No file uploaded" });
}

    const fileBuffer = req.file.buffer;
    logInfo("File buffer received");
    const extension = path.extname(req.file.originalname).toLowerCase();
    logInfo("File extension detected", extension);

    let rows = [];


// ================= READ EXCEL =================

    if (extension === ".xlsx" || extension === ".xls") {
      logInfo("Processing Excel file");

      const workbook = XLSX.read(fileBuffer, { type: "buffer" });
      logSuccess("Excel workbook read");

      const sheetName = workbook.SheetNames[0];
      const sheet = workbook.Sheets[sheetName];

      rows = XLSX.utils.sheet_to_json(sheet, { defval: "" });
      logSuccess("Excel converted to JSON", { count: rows.length });

      rows = rows.filter(r => r["Account Name"] && r["Account No."]);
logInfo("Filtered valid Excel rows", { count: rows.length });
    }


// ================= READ CSV =================


    else if (extension === ".csv") {
      logInfo("Processing CSV file");

      const csvText = fileBuffer.toString("utf8");

      const lines = csvText.split("\n");

      const headers = lines[0].split(",");

      rows = lines.slice(1).map(line => {

        const values = line.split(",");

        let obj = {};

        headers.forEach((h, i) => {
          obj[h.trim()] = values[i] ?? "";
        });

        return obj;
      });
      logSuccess("CSV parsed to JSON", { count: rows.length });

      rows = rows.filter(r => r["Account Name"] && r["Account No."]);
      logInfo("Filtered valid CSV rows", { count: rows.length });
    }

    else {
      logWarn("Invalid file format uploaded");
return res.status(400).json({ message: "Invalid file format" });
    }

// ================= CLEAR OLD DATA =================
logWarn("Deleting old SMA data");
    await pool.request().query(`DELETE FROM dbo.SMA_Report`);
    logSuccess("Old SMA data cleared");


// ================= CREATE BULK TABLE =================

    const table = new sql.Table("SMA_Report");

    table.create = false;

    table.columns.add("SNo.", sql.VarChar(20), { nullable: true });
    table.columns.add("Br Code", sql.VarChar(20), { nullable: true });
    table.columns.add("Branch Name", sql.VarChar(150), { nullable: true });
    table.columns.add("Cluster Code", sql.VarChar(50), { nullable: true });
    table.columns.add("Account No.", sql.VarChar(50), { nullable: true });
    table.columns.add("Account Name", sql.VarChar(200), { nullable: true });
    table.columns.add("Account Type Description", sql.VarChar(200), { nullable: true });

    table.columns.add("Limit", sql.VarChar(50), { nullable: true });
    table.columns.add("Drawing Power", sql.VarChar(50), { nullable: true });
    table.columns.add("Int Rate", sql.VarChar(50), { nullable: true });

    table.columns.add("Theo Balance", sql.VarChar(50), { nullable: true });
    table.columns.add("Cleared Balance", sql.VarChar(50), { nullable: true });
    table.columns.add("Uncleared Balance", sql.VarChar(50), { nullable: true });
    table.columns.add("Outstanding Balance", sql.VarChar(50), { nullable: true });

    table.columns.add("Overdue", sql.VarChar(50), { nullable: true });

    table.columns.add("Sanction Date", sql.VarChar(50), { nullable: true });
    table.columns.add("Expiry Date", sql.VarChar(50), { nullable: true });

    table.columns.add("EMIs Due", sql.VarChar(20), { nullable: true });
    table.columns.add("EMIs Paid", sql.VarChar(20), { nullable: true });
    table.columns.add("EMIs OD", sql.VarChar(20), { nullable: true });

    table.columns.add("NEW IRAC", sql.VarChar(20), { nullable: true });
    table.columns.add("OLD IRAC", sql.VarChar(20), { nullable: true });

    table.columns.add("NPA Date", sql.VarChar(50), { nullable: true });

    table.columns.add("Arrear Condition", sql.VarChar(50), { nullable: true });
    table.columns.add("Arrear Description", sql.VarChar(200), { nullable: true });

    table.columns.add("Loan Type", sql.VarChar(100), { nullable: true });
    table.columns.add("Product Group", sql.VarChar(100), { nullable: true });


// ================= ADD ROWS =================

logInfo("Preparing bulk insert", { totalRows: rows.length });
    rows.forEach((row, index) => {

      table.rows.add(

        safeString(index + 1,20),

        safeString(row["Br Code"],20),
        safeString(row["Branch Name"],150),
        safeString(row["Cluster Code"],50),
        safeString(row["Account No."],50),
        safeString(row["Account Name"],200),
        safeString(row["Account Type Description"],200),

        safeString(row["Limit"],50),
        safeString(row["Drawing Power"],50),
        safeString(row["Int Rate"],50),

        safeString(row["Theo Balance"],50),
        safeString(row["Cleared Balance"],50),
        safeString(row["Uncleared Balance"],50),
        safeString(row["Outstanding Balance"],50),

        safeString(row["Overdue"],50),

       convertExcelDate(row["Sanction Date"]),
        convertExcelDate(row["Expiry Date"]),

        safeString(row["EMIs Due"],20),
        safeString(row["EMIs Paid"],20),
        safeString(row["EMIs OD"],20),

        safeString(row["NEW IRAC"],20),
        safeString(row["OLD IRAC"],20),

        convertExcelDate(row["NPA Date"]),

        safeString(row["Arrear Condition"],50),
        safeString(row["Arrear Description"],200),

        safeString(row["Loan Type"],100),
        safeString(row["Product Group"],100)

      );

    });


    // ================= BULK INSERT =================
    logInfo("Starting bulk insert");

await pool.request().bulk(table);
logSuccess("Bulk insert completed");


// ============================================================
// STEP 1 — Today Upload Count
// ============================================================

const todayCount = rows.length;


// ============================================================
// STEP 2 — Insert Upload Log
// ============================================================

logInfo("Saving upload log");
await pool.request()
  .input("cnt", sql.Int, todayCount)
  .query(`
    INSERT INTO SMA_Upload_Log
    (upload_date, record_count, uploaded_at)
    VALUES
    (CAST(GETDATE() AS DATE), @cnt, GETDATE())
  `);
  logSuccess("Upload log saved");


// ============================================================
// STEP 3 — Get LAST upload BEFORE today (NOT today)
// ============================================================

logInfo("Fetching previous upload data");
const prevRes = await pool.request().query(`
  SELECT TOP 1 record_count
  FROM SMA_Upload_Log
  WHERE upload_date < CAST(GETDATE() AS DATE)
  ORDER BY uploaded_at DESC
`);

const previousCount =
  prevRes.recordset.length
    ? prevRes.recordset[0].record_count
    : 0;

logInfo("Previous count", previousCount);


// ============================================================
// STEP 4 — Calculate Difference
// ============================================================

const archived =
  todayCount < previousCount
    ? previousCount - todayCount
    : 0;

const newRecords =
  todayCount > previousCount
    ? todayCount - previousCount
    : 0;


// ============================================================
// FINAL RESPONSE
// ============================================================

logSuccess("Upload completed", {
  total: todayCount,
  newRecords,
  archived
});
res.json({
  message: `${rows.length} records uploaded successfully`,
  archived,
  uploaded: newRecords,
  history_total: todayCount
});

  }

  catch (error) {

    logError("SMA Upload Error", error);

    res.status(500).json({
      message: "Upload failed"
    });

  }

});

// ============================================================
// SMA FILE UPLOAD STATUS (FINAL CORRECT LOGIC)
// ============================================================

app.get("/api/sma/upload-status", async (req, res) => {
  logInfo("SMA Status API called");
	
  const userId = req.headers["x-user-id"];
  logInfo("User ID received", userId);

  if (!userId) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const pool = await poolPromise;

  const userInfo = await pool.request()
    .input("userId", sql.VarChar, userId)
    .query(`
      SELECT Role
      FROM UsersInfo
      WHERE UserId = @userId
    `);

  if (!userInfo.recordset.length) {
  logWarn("User not found in DB");
    return res.status(403).json({ message: "User not found" });
  }

  const { Role } = userInfo.recordset[0];
  logInfo("User role", Role);

  if (Role !== "Admin" && Role !== "Super Admin") {
    logWarn("Unauthorized status access", Role);
    return res.status(403).json({
      message: "Only Admin can view upload status"
    });
  }

  try {

    // ============================================================
    // 🔹 STEP 1 — Get latest upload
    // ============================================================
    const latestRes = await pool.request().query(`
      SELECT TOP 1 record_count, uploaded_at
      FROM SMA_Upload_Log
      ORDER BY uploaded_at DESC
    `);

    const latestDate = latestRes.recordset.length
      ? latestRes.recordset[0].uploaded_at
      : null;

    const today = latestRes.recordset.length
      ? latestRes.recordset[0].record_count
      : 0;


    // ============================================================
    // 🔹 STEP 2 — Get previous upload from DIFFERENT DATE
    // ============================================================
    const prevRes = await pool.request()
      .input("latestDate", sql.DateTime, latestDate)
      .query(`
        SELECT TOP 1 record_count
        FROM SMA_Upload_Log
        WHERE CAST(uploaded_at AS DATE) < CAST(@latestDate AS DATE)
        ORDER BY uploaded_at DESC
      `);

    const previous = prevRes.recordset.length
      ? prevRes.recordset[0].record_count
      : 0;


    // ============================================================
    // 🔹 STEP 3 — Calculate difference
    // ============================================================
    const archived = today < previous ? previous - today : 0;
    const uploaded = today > previous ? today - previous : 0;


    // ============================================================
    // 🔹 RESPONSE
    // ============================================================
logSuccess("Status response sent", {
  archived,
  uploaded,
  history_total: today
});

    res.json({
      archived,
      uploaded,
      history_total: today
    });

  } catch (err) {

    logError("SMA STATUS ERROR", err);

    res.status(500).json({
      message: "Internal Server Error"
    });

  }

});

// ============================================================
// SMA LIST
// ============================================================

// Cluster mapping
const CLUSTER_MAP = {
  KR: "Krishna",
  GU: "Guntur",
  WG: "West Godavari",
  VS: "Visakhapatnam"
};


// ============================================================
// SMA FILTER DROPDOWNS
// ============================================================
app.get("/api/sma/filters", async (req, res) => {

  logInfo("SMA Filters API called");

  try {

    const pool = await sql.connect(dbConfig);
logSuccess("DB connected for filters");

    const clusters = await pool.request().query(`
      SELECT DISTINCT [Cluster Code] as cluster
      FROM SMA_Report
      WHERE [Cluster Code] IS NOT NULL
	  ORDER BY [Cluster Code]
    `);
    logInfo("Clusters fetched", clusters.recordset.length);

    const branches = await pool.request().query(`
      SELECT DISTINCT [Branch Name] as branch
      FROM SMA_Report
      WHERE [Branch Name] IS NOT NULL
	  ORDER BY [Branch Name]
    `);
    logInfo("Branches fetched", branches.recordset.length);

    const products = await pool.request().query(`
      SELECT DISTINCT [Account Type Description] as product
      FROM SMA_Report
      WHERE [Account Type Description] IS NOT NULL
	  ORDER BY [Account Type Description]
    `);
    logInfo("Products fetched", products.recordset.length);

    const productGroup = await pool.request().query(`
      SELECT DISTINCT [Product Group] as productGroup
      FROM SMA_Report
      WHERE [Product Group] IS NOT NULL
	  ORDER BY [Product Group]
    `);
    logInfo("Product Groups fetched", productGroup.recordset.length);

    const loanType = await pool.request().query(`
      SELECT DISTINCT [Loan Type] as loanType
      FROM SMA_Report
      WHERE [Loan Type] IS NOT NULL
	  ORDER BY [Loan Type]
    `);
    logInfo("Loan Types fetched", loanType.recordset.length);

    const newIrac = [
  { newIrac: "00" },
  { newIrac: "01" },
  { newIrac: "02" },
  { newIrac: "03" },
  { newIrac: "04" },
  { newIrac: "05" },
  { newIrac: "06" },
  { newIrac: "07" }
];

    // Convert cluster codes to full names
    const clusterData = clusters.recordset.map(c => ({
      code: c.cluster,
      name: CLUSTER_MAP[c.cluster] || c.cluster
    }));

    logSuccess("Filters response sent");
    res.json({
      clusters: clusterData,
      branches: branches.recordset,
      products: products.recordset,
      productGroup: productGroup.recordset,
      loanType: loanType.recordset,
      newIrac: newIrac
    });

  } catch (err) {

    logError("SMA filters error", err);
    res.status(500).json({ message: "Server error" });

  }

});


// ============================================================
// SMA SEARCH
// ============================================================
app.post("/api/sma/search", async (req, res) => {
  logInfo("SMA Search API called");
	
	const userId = req.headers["x-user-id"];
logInfo("User ID received", userId);

if (!userId) {
  logWarn("Unauthorized request");
  return res.status(401).json({ message: "Unauthorized" });
}

const pool = await sql.connect(dbConfig);

const userInfo = await pool.request()
  .input("userId", sql.VarChar, userId)
  .query(`
    SELECT Role, ClusterName
    FROM UsersInfo
    WHERE UserId = @userId
  `);

if (!userInfo.recordset.length) {
  logWarn("User not found in DB");
  return res.status(403).json({ message: "User not found" });
}

logInfo("User info fetched", userInfo.recordset[0]);

const { Role } = userInfo.recordset[0];
logInfo("User role", Role);

const isRegionalManager = Role?.startsWith("Regional Manager");

// Extract cluster from role
let userCluster = null;

if (isRegionalManager) {
  const match = Role.match(/\((.*?)\)/);
  if (match) {
    userCluster = match[1];
  }
}

const CLUSTER_CODE_MAP = {
  "Krishna": "KR",
  "Guntur": "GU",
  "West Godavari": "WG",
  "Visakhapatnam": "VS"
};

const userClusterCode = CLUSTER_CODE_MAP[userCluster];
logInfo("User cluster code", userClusterCode);

  const {
  mobileNumber,
  cluster,
  branch,
  accountNumber,
  customerName,
  dataType,   // ✅ NEW
  product,
  productGroup,
  loanType,
  newIrac
} = req.body;

logInfo("Search filters received", req.body);

  try {
    const request = pool.request();
    let query = `
SELECT
  s.[Account No.] as accountNumber,
  s.[Account Name] as customerName,
  s.[Account Type Description] as product,
  s.[Branch Name] as branch,
  s.[Cluster Code] as cluster,

  COALESCE(r.mobileNumber, a.AlternateNumber) as mobileNumber

FROM SMA_Report s

LEFT JOIN Recovery_Raw_Data r
ON s.[Account No.] = r.[loanAccountNumber]

LEFT JOIN Recovery_Alternate_Number a
ON s.[Account No.] = a.[LoanAccountNumber]

WHERE 1=1
`;


if (mobileNumber) {
  logInfo("Filter applied: mobileNumber", mobileNumber);
  query += " AND COALESCE(r.mobileNumber, a.AlternateNumber) LIKE @mobileNumber";
  request.input("mobileNumber", sql.VarChar, `%${mobileNumber}%`);
}

 if (isRegionalManager) {
  logInfo("Filter applied: restricted cluster", userClusterCode);
  query += " AND s.[Cluster Code] = @restrictedCluster";
  request.input("restrictedCluster", sql.VarChar, userClusterCode);

} else if (cluster) {
logInfo("Filter applied: cluster", cluster);
  query += " AND s.[Cluster Code] = @cluster";
  request.input("cluster", sql.VarChar, cluster);

}

    if (branch) {
      logInfo("Filter applied: branch", branch);
      query += " AND [Branch Name] = @branch";
      request.input("branch", sql.VarChar, branch);
    }

    if (accountNumber) {
      logInfo("Filter applied: accountNumber", accountNumber);
      query += " AND [Account No.] = @accountNumber";
      request.input("accountNumber", sql.VarChar, accountNumber);
    }

    if (customerName) {
      logInfo("Filter applied: customerName", customerName);
      query += " AND [Account Name] LIKE @customerName";
      request.input("customerName", sql.VarChar, `%${customerName}%`);
    }

    if (product) {
      logInfo("Filter applied: product", product);
      query += " AND [Account Type Description] = @product";
      request.input("product", sql.VarChar, product);
    }

    if (productGroup) {
      logInfo("Filter applied: productGroup", productGroup);
      query += " AND [Product Group] = @productGroup";
      request.input("productGroup", sql.VarChar, productGroup);
    }

    if (loanType) {
      logInfo("Filter applied: loanType", loanType);
      query += " AND [Loan Type] = @loanType";
      request.input("loanType", sql.VarChar, loanType);
    }
	
// ============================================================
// DATA TYPE FILTER
// ============================================================

if (dataType === "SMA") {
logInfo("Filter applied: dataType SMA");
  query += `
AND s.[NEW IRAC] IN (0,1,2,3)
`;

}

if (dataType === "NPA") {
logInfo("Filter applied: dataType NPA");
  query += `
AND s.[NEW IRAC] IN (4,5,6,7)
`;

}

    if (newIrac) {
logInfo("Filter applied: newIrac", newIrac);
  const iracValue = parseInt(newIrac); // converts "00" → 0

  query += " AND [NEW IRAC] = @newIrac";
  request.input("newIrac", sql.Int, iracValue);

}

logInfo("Executing search query");
    const result = await request.query(query);
    logSuccess("Search results fetched", result.recordset.length);

    logInfo("Sending search response");
    res.json(result.recordset);

  } catch (err) {

    logError("SMA search error", err);
    res.status(500).json({ message: "Server error" });

  }

});


// ============================================================
// SMA VIEW DETAILS
// ============================================================
app.get("/api/sma/details/:accountNumber", async (req, res) => {
  logInfo("SMA Details API called");
	
	const userId = req.headers["x-user-id"];
logInfo("User ID received", userId);

if (!userId) {
  logWarn("Unauthorized request");
  return res.status(401).json({ message: "Unauthorized" });
}

const pool = await sql.connect(dbConfig);

const userInfo = await pool.request()
  .input("userId", sql.VarChar, userId)
  .query(`
    SELECT Role, ClusterName
    FROM UsersInfo
    WHERE UserId = @userId
  `);
  
 if (!userInfo.recordset.length) {
  logWarn("User not found in DB");
  return res.status(403).json({ message: "User not found" });
}

const { Role } = userInfo.recordset[0];
logInfo("User role", Role);

let userCluster = null;

if (Role?.startsWith("Regional Manager")) {
  const match = Role.match(/\((.*?)\)/);
  if (match) {
    userCluster = match[1];
  }
}

const CLUSTER_CODE_MAP = {
  "Krishna": "KR",
  "Guntur": "GU",
  "West Godavari": "WG",
  "Visakhapatnam": "VS"
};

const userClusterCode = CLUSTER_CODE_MAP[userCluster];
logInfo("Cluster restriction", userClusterCode);

const isRegionalManager = Role?.startsWith("Regional Manager");

  const { accountNumber } = req.params;
  logInfo("Fetching details for account", accountNumber);

  try {

    logInfo("Executing details query");
    const result = await pool.request()
  .input("accountNumber", sql.VarChar, accountNumber)
  .input("isRegionalManager", sql.Bit, isRegionalManager ? 1 : 0)
  .input("restrictedCluster", sql.VarChar, userClusterCode)
      .query(`
        SELECT
          [Account Name] as customerName,
          [Branch Name] as branch,
          [Cluster Code] as cluster,
          [Limit] as limit,
          [Drawing Power] as drawingPower,
          [Int Rate] as intRate,
          [Theo Balance] as theoBalance,
          [Cleared Balance] as clearedBalance,
          [Uncleared Balance] as unclearedBalance,
          [Outstanding Balance] as outstandingBalance,
          [Overdue] as overdue,
          [Sanction Date] as sanctionDate,
          [Expiry Date] as expiryDate,
          [EMIs Due] as emisDue,
          [EMIs Paid] as emisPaid,
          [EMIs OD] as emisOD,
          [NEW IRAC] as newIrac,
          [OLD IRAC] as oldIrac,
          [NPA Date] as npaDate,
          [Arrear Condition] as arrearCondition,
          [Arrear Description] as arrearDescription
        FROM SMA_Report
        WHERE [Account No.] = @accountNumber
AND (
  @isRegionalManager = 0
  OR [Cluster Code] = @restrictedCluster
)
      `);
      logSuccess("Details fetched", result.recordset[0]);
logInfo("Sending details response");
    res.json(result.recordset[0]);

  } catch (err) {

    logError("SMA details error", err);
    res.status(500).json({ message: "Server error" });

  }

});

// =======================================
// SMA BRANCHES BY CLUSTER
// =======================================

app.get("/api/sma/branches/:cluster", async (req, res) => {
  logInfo("Branches API called");

  const { cluster } = req.params;
logInfo("Cluster received", cluster);

  try {

    const pool = await sql.connect(dbConfig);
logSuccess("DB connected for branches");

    const result = await pool.request()
      .input("cluster", sql.VarChar, cluster)
      .query(`
        SELECT DISTINCT [Branch Name] as branch
FROM SMA_Report
WHERE (@cluster = '' OR [Cluster Code] = @cluster)
ORDER BY [Branch Name]
      `);
      logSuccess("Branches fetched", result.recordset.length);

      logInfo("Sending branches response");
    res.json(result.recordset);

  } catch (err) {

    logError("Branch fetch error", err);
    res.status(500).json({ message: "Server error" });

  }

});


// ============================================================
// SMA ACTIVITY STATUS SEARCH
// ============================================================

app.post("/api/sma/activity/search", async (req,res)=>{

  logInfo("SMA Activity Search API called");

const {
mobileNumber,
cluster,
branch,
accountNumber,
customerName,
product,
productGroup,
loanType,
newIrac
} = req.body;

logInfo("Search filters received", req.body);

const hasFilter = Object.values(req.body).some(v => v !== "" && v !== null && v !== undefined);

if (!hasFilter) {
  logWarn("Search executed without any filters");
}

try{

  logInfo("Connecting to DB for activity search");
const pool = await sql.connect(dbConfig);
logSuccess("DB connected for activity search");
const request = pool.request();

const userId = req.headers["x-user-id"];
logInfo("Request headers", {
  role: req.headers["x-user-role"],
  branch: req.headers["x-user-branch"],
  cluster: req.headers["x-user-cluster"]
});
logInfo("User ID received", userId);

if (!userId) {
  logWarn("Unauthorized request");
  return res.status(401).json({ message: "Unauthorized" });
}

const roleResult = await pool.request()
  .input("userId", sql.VarChar(50), userId)
  .query(`
    SELECT Role
    FROM UsersInfo
    WHERE UserId = @userId
  `);

if (!roleResult.recordset.length) {
  logWarn("User not found in DB");
  return res.status(403).json({ message: "User not found" });
}

const userRole = roleResult.recordset[0].Role;
logInfo("User role", userRole);

if (userRole === "Branch Manager") {
  logWarn("Access denied for Branch Manager");
  return res.status(403).json({
    message: "Access Denied. Please Contact Admin."
  });
}

let query = `

SELECT
s.[Account No.] AS accountNumber,
s.[Account Name] AS customerName,
s.[Account Type Description] AS product,
s.[Branch Name] AS branch,

COALESCE(r.mobileNumber,a.AlternateNumber) AS mobileNumber,

STRING_AGG(l.ActionLabel, ', ') AS activityDetails

FROM SMA_Report s

INNER JOIN SMA_Activity_Sessions sess
ON sess.SourceType='SMA'
AND sess.SourceId = s.[Account No.]

INNER JOIN SMA_Activity_Logs l
ON l.SessionId = sess.SessionId
AND l.SourceType='SMA'
AND l.SourceId = s.[Account No.]

LEFT JOIN Recovery_Raw_Data r
ON s.[Account No.] = r.loanAccountNumber

LEFT JOIN Recovery_Alternate_Number a
ON s.[Account No.] = a.LoanAccountNumber

WHERE 1=1

`;

if(mobileNumber){
  logInfo("Filter applied: mobileNumber", mobileNumber);
query += " AND COALESCE(r.mobileNumber,a.AlternateNumber) LIKE @mobileNumber";
request.input("mobileNumber",sql.VarChar,`%${mobileNumber}%`);
}

const isRegionalManager = userRole?.startsWith("Regional Manager");

let userCluster = null;

if (isRegionalManager) {
  const match = userRole.match(/\((.*?)\)/);
  if (match) userCluster = match[1];
}

const CLUSTER_CODE_MAP = {
  "Krishna": "KR",
  "Guntur": "GU",
  "West Godavari": "WG",
  "Visakhapatnam": "VS"
};

const userClusterCode = CLUSTER_CODE_MAP[userCluster];

if (isRegionalManager && !userClusterCode) {
  logWarn("Cluster mapping failed", userCluster);
}

if (isRegionalManager) {
logInfo("Filter applied: restricted cluster", userClusterCode);
  query += " AND s.[Cluster Code] = @restrictedCluster";
  request.input("restrictedCluster", sql.VarChar, userClusterCode);

} else if (cluster) {
logInfo("Filter applied: cluster", cluster);
  query += " AND s.[Cluster Code] = @cluster";
  request.input("cluster", sql.VarChar, cluster);

}

if(branch){
  logInfo("Filter applied: branch", branch);
query += " AND s.[Branch Name] = @branch";
request.input("branch",sql.VarChar,branch);
}

if(accountNumber){
  logInfo("Filter applied: accountNumber", accountNumber);
query += " AND s.[Account No.] = @accountNumber";
request.input("accountNumber",sql.VarChar,accountNumber);
}

if(customerName){
  logInfo("Filter applied: customerName", customerName);
query += " AND s.[Account Name] LIKE '%' + @customerName + '%'";
request.input("customerName",sql.VarChar,customerName);
}

if(product){
  logInfo("Filter applied: product", product);
query += " AND s.[Account Type Description] = @product";
request.input("product",sql.VarChar,product);
}

if(productGroup){
  logInfo("Filter applied: productGroup", productGroup);
query += " AND s.[Product Group] = @productGroup";
request.input("productGroup",sql.VarChar,productGroup);
}

if(loanType){
  logInfo("Filter applied: loanType", loanType);
query += " AND s.[Loan Type] = @loanType";
request.input("loanType",sql.VarChar,loanType);
}

if (newIrac !== undefined && newIrac !== "") {
  logInfo("Filter applied: newIrac", newIrac);
query += " AND s.[NEW IRAC] = @newIrac";
request.input("newIrac",sql.Int,parseInt(newIrac));
}

query += `
GROUP BY
s.[Account No.],
s.[Account Name],
s.[Account Type Description],
s.[Branch Name],
COALESCE(r.mobileNumber,a.AlternateNumber)
`;

logInfo("Final query ready");
logInfo("Executing activity search query");
const result = await request.query(query);
logSuccess("Search results fetched", result.recordset.length);

logInfo("Sending search response");
res.json(result.recordset);

}
catch(err){

logError("SMA activity search error", {
  error: err.message,
  filters: req.body,
  userId
});
res.status(500).json({message:"Server error"});

}

});

// =====================================================================
// SMA ACTIVITY DETAILS
// =====================================================================

app.post("/api/sma-activity-details", async (req, res) => {

  logInfo("SMA Activity Details API called");

  const { accountNumber } = req.body;
  logInfo("Account number received", accountNumber);

  if (!accountNumber) {
  logWarn("Account number missing");
    return res.status(400).json([]);
  }

  try {

    const userId = req.headers["x-user-id"];
    logInfo("User ID received", userId);

    if (!userId) {
  logWarn("Unauthorized request");
      return res.status(401).json({ message: "Unauthorized" });
    }

    logInfo("Connecting to DB for activity details");
    const pool = await poolPromise;
    logSuccess("DB connected for activity details");

    // ================= FETCH SESSIONS =================

logInfo("Fetching activity sessions");
    const sessionsResult = await pool.request()
      .input("accountNumber", sql.VarChar, accountNumber)
      .query(`

        SELECT
          s.SessionId,
          CONVERT(varchar, s.StartedAt, 105) AS activityDate,
          FORMAT(s.StartedAt, 'hh:mm tt') AS activityTime,
          s.StartedByUserName AS userName,
          s.SessionType,
          s.SessionStatus

        FROM SMA_Activity_Sessions s

        WHERE s.SourceType = 'SMA'
        AND s.SourceId = @accountNumber

        ORDER BY s.StartedAt DESC

      `);

    const sessions = sessionsResult.recordset;
    logSuccess("Sessions fetched", sessions.length);

    if (sessions.length === 0) {
  logWarn("No sessions found");
      return res.json([]);
    }

    // ================= FETCH LOGS =================

    logInfo("Fetching activity logs");
    const logsResult = await pool.request()
      .input("accountNumber", sql.VarChar, accountNumber)
      .query(`

        SELECT
          SessionId,
          ActionLabel,
          MetadataJson

        FROM SMA_Activity_Logs

        WHERE SourceType = 'SMA'
        AND SourceId = @accountNumber

        ORDER BY CreatedAt

      `);

    const logs = logsResult.recordset;
    logSuccess("Logs fetched", logs.length);

    // ================= GROUP LOGS =================

    const response = sessions.map(session => {

      const sessionLogs = logs.filter(
        l => l.SessionId === session.SessionId
      );

      const actions = sessionLogs
        .map((l, index) => `${index + 1}. ${l.ActionLabel}`)
        .join("\n");

      const notes = sessionLogs
        .map(l => {
          if (!l.MetadataJson) return "";
          try {
            const obj = JSON.parse(l.MetadataJson);
            return Object.values(obj).join(", ");
          } catch {
            return "";
          }
        })
        .filter(Boolean)
        .join("\n");

      return {
        activityDate: session.activityDate,
        activityTime: session.activityTime,
        userName: session.userName,
        activityType: session.SessionType,
        activityStatus: actions || "",
        notes: notes || ""
      };

    });

logSuccess("Activity details response sent", response.length);
logInfo("Sending activity details response");
    res.json(response);

  } catch (err) {

    logError("SMA activity details error", {
  error: err.message,
  accountNumber,
  userId
});
    res.status(500).json([]);

  }

});



// =============================
// FIELD VISIT SUMMARY
// =============================

app.post("/api/field-visit-summary", async (req, res) => {

  try {

    const { user, cluster, branch, fromDate, toDate } = req.body;
    logInfo("FIELD VISIT SUMMARY API HIT", {
  user, cluster, branch, fromDate, toDate
});

    const pool = await sql.connect(dbConfig);
	
	const userId = req.headers["x-user-id"];

logInfo("User ID received", userId);

if (!userId) {
  logError("Unauthorized request - missing userId");
  return res.status(401).json({ message: "Unauthorized" });
}

logInfo("Fetching user role from DB");
// Fetch user role
const roleResult = await pool.request()
  .input("userId", sql.VarChar(50), userId)
  .query(`
    SELECT Role
    FROM UsersInfo
    WHERE UserId = @userId
  `);

if (!roleResult.recordset.length) {
  logWarn("User not found in DB", userId);
  return res.status(403).json({ message: "User not found" });
}

const userRole = roleResult.recordset[0].Role;	
logSuccess("User role fetched", userRole);
    const request = pool.request();

    logInfo("Building SQL query");
    let query = `
SELECT 
    F.UserName,
    U.BranchName,
    COUNT(DISTINCT F.AccountNo) AS AccountCount,
    SUM(ISNULL(F.DistanceTravelled,0)) AS DistanceTravelled

FROM smart_call.dbo.FieldVisitReport F

INNER JOIN smart_call.dbo.UsersInfo U
    ON U.UserId = F.UserID

WHERE 1=1
`;

    // ================= FILTERS =================
	
	if (userRole === "Branch Manager") {
    logInfo("Applying Branch Manager filter");

  const branchResult = await pool.request()
    .input("userId", sql.VarChar(50), userId)
    .query(`
      SELECT BranchName
      FROM UsersInfo
      WHERE UserId = @userId
    `);

  const userBranch = branchResult.recordset[0].BranchName;
  logInfo("Branch Manager branch", userBranch);

  query += " AND U.BranchName = @userBranch";
  request.input("userBranch", sql.VarChar, userBranch);

}

if (userRole.startsWith("Regional Manager")) {
  logInfo("Applying Regional Manager filter", userRole);

  const match = userRole.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";
  logInfo("RM Cluster extracted", rmCluster);

  query += " AND U.ClusterName = @rmCluster";
  request.input("rmCluster", sql.VarChar, rmCluster);

}
	

    if (user) {
  logInfo("Filter applied: user", user);
      query += " AND F.UserID = @UserID";
      request.input("UserID", sql.VarChar, user);
    }

    if (cluster && cluster !== "Corporate Office") {
  logInfo("Filter applied: cluster", cluster);
  query += " AND U.ClusterName = @Cluster";
  request.input("Cluster", sql.VarChar, cluster);
}

    if (branch) {
  logInfo("Filter applied: branch", branch);
      query += " AND U.BranchName = @Branch";
      request.input("Branch", sql.VarChar, branch);
    }

    if (fromDate) {
  logInfo("Filter applied: fromDate", fromDate);
      query += " AND CAST(F.MeetingDate AS DATE) >= @FromDate";
      request.input("FromDate", sql.Date, fromDate);
    }

    if (toDate) {
  logInfo("Filter applied: toDate", toDate);
      query += " AND CAST(F.MeetingDate AS DATE) <= @ToDate";
      request.input("ToDate", sql.Date, toDate);
    }

    // ================= GROUPING =================

    query += `
GROUP BY 
    F.UserName,
    U.BranchName

ORDER BY 
    F.UserName
`;

logInfo("Executing SQL query");
    const result = await request.query(query);
    logSuccess("Query executed", {
  rowCount: result.recordset?.length || 0
});

const finalData = result.recordset || [];

logSuccess("FIELD VISIT SUMMARY API SUCCESS", {
  count: finalData.length
});

res.json(finalData);   // ✅ ONLY THIS

  } catch (error) {

    logError("FIELD VISIT SUMMARY ERROR", {
  message: error.message,
  stack: error.stack
});
    res.status(500).json({ error: "Internal Server Error" });

  }

});


// =============================
// FIELD VISIT SUMMARY EXPORT EXCEL
// =============================

app.post("/api/field-visit-summary/export-excel", async (req, res) => {

  try {

    const { columns, data } = req.body;

    logInfo("SUMMARY EXCEL EXPORT API HIT", {
  columns: columns?.length,
  rows: data?.length
});

    if (!data || data.length === 0) {
      logWarn("No data to export");
      return res.status(400).json({ error: "No data to export" });
    }

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet("Field Visit Summary");

    // ================= HEADERS =================

    const headers = ["S. No.", ...columns];

    worksheet.addRow(headers);

    worksheet.getRow(1).font = { bold: true };

    // ================= DATA =================

    data.forEach((row, index) => {

      const rowData = [
        index + 1,
        ...columns.map(col => row[col] ?? "")
      ];

      worksheet.addRow(rowData);

    });

    // ================= AUTO WIDTH =================

    worksheet.columns.forEach(column => {

      let maxLength = 10;

      column.eachCell({ includeEmpty: true }, cell => {

        const length = cell.value ? cell.value.toString().length : 10;

        if (length > maxLength) {
          maxLength = length;
        }

      });

      column.width = maxLength + 2;

    });

    // ================= DOWNLOAD =================

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );

    res.setHeader(
      "Content-Disposition",
      "attachment; filename=Field_Visit_Summary.xlsx"
    );

    logInfo("Writing Excel file");
    await workbook.xlsx.write(res);
    logSuccess("Excel generated successfully");

    res.end();

  } catch (error) {

    logError("SUMMARY EXCEL EXPORT ERROR", {
  message: error.message,
  stack: error.stack
});

    res.status(500).json({ error: "Excel export failed" });

  }

});


// =============================
// LOGIN API
// =============================

app.post("/api/login", async (req, res) => {
  const { userId, password } = req.body;
  logInfo("Login API hit", { userId: req.body.userId });

  if (!userId || !password) {
    logWarn("Login validation failed - missing fields", { userId });
    return res.status(400).json({ message: "User ID and Password are required" });
  }

  try {
    const pool = await poolPromise;

    // 1️⃣ Check credentials with lock system
logInfo("Checking user credentials", { userId });

const authQuery = await pool.request()
  .input("userId", userId)
  .query(`
    SELECT UserId, AppPassword, FailedAttempts, IsLocked
    FROM UserAuth
    WHERE UserId = @userId
  `);

if (authQuery.recordset.length === 0) {
  logWarn("Invalid login attempt", { userId });
  return res.status(401).json({
    message: "Invalid User ID or Password"
  });
}

const authUser = authQuery.recordset[0];

// Account already locked
if (authUser.IsLocked === true) {
  return res.status(403).json({
    message: "Account locked. Contact Administrator."
  });
}

// Wrong password
if (authUser.AppPassword !== password) {

  const attempts = authUser.FailedAttempts + 1;
  const remaining = 3 - attempts;

  // Lock account after 3 tries
  if (attempts >= 3) {

    await pool.request()
      .input("userId", userId)
      .query(`
        UPDATE UserAuth
        SET FailedAttempts = 3,
            IsLocked = 1
        WHERE UserId = @userId
      `);

    return res.status(403).json({
      message: "Account locked after 3 failed attempts"
    });
  }

  // Update failed attempts
  await pool.request()
    .input("userId", userId)
    .input("attempts", attempts)
    .query(`
      UPDATE UserAuth
      SET FailedAttempts = @attempts
      WHERE UserId = @userId
    `);

  return res.status(401).json({
    message: `Invalid Password. ${remaining} attempts remaining`
  });
}

// Correct password → reset attempts
await pool.request()
  .input("userId", userId)
  .query(`
    UPDATE UserAuth
    SET FailedAttempts = 0,
        IsLocked = 0
    WHERE UserId = @userId
  `);

    // 2️⃣ Get user info
    logInfo("Fetching user info", { userId });
    const infoQuery = await pool.request()
      .input("userId", userId)
      .query(`
        SELECT 
          Role,
          ValidFrom,
          ValidUntil,
          BranchName,
          BranchCode,
          ClusterName
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    if (infoQuery.recordset.length === 0) {
      logWarn("User not registered for dashboard", { userId });
      return res.status(401).json({ message: "User not registered for dashboard access" });
    }

    const user = infoQuery.recordset[0];
    const today = new Date();

    // 3️⃣ Validity Check
    if (new Date(user.ValidFrom) > today || new Date(user.ValidUntil) < today) {
      logWarn("User validity expired or not active", {
  userId,
  validFrom: user.ValidFrom,
  validUntil: user.ValidUntil
});
      return res.status(403).json({ message: "User access expired or not yet active" });
    }

    // 4️⃣ Role Processing
const roles = user.Role.split(",").map(r => r.trim());

let finalRole = null;

// Role Priority
if (roles.includes("Admin")) {
  finalRole = "Admin";
}
else if (roles.includes("Branch Manager")) {
  finalRole = "Branch Manager";
}
else if (
  roles.includes("Regional Manager (Krishna)") ||
  roles.includes("Regional Manager (Guntur)") ||
  roles.includes("Regional Manager (West Godavari)") ||
  roles.includes("Regional Manager (Visakhapatnam)")
) {
  finalRole = roles.find(r =>
    [
      "Regional Manager (Krishna)",
      "Regional Manager (Guntur)",
      "Regional Manager (West Godavari)",
      "Regional Manager (Visakhapatnam)"
    ].includes(r)
  );
}
else if (roles.length === 1 && roles.includes("Calling Agent")) {
  logWarn("Unauthorized role - Calling Agent", { userId });
  return res.status(403).json({ message: "Calling Agent cannot access dashboard" });
}

if (!finalRole) {
  logWarn("User role not authorized", { userId, roles });
  return res.status(403).json({ message: "User role not authorized for dashboard" });
}

    // Extract cluster from role if Regional Manager
let clusterName = user.ClusterName;

if (finalRole.startsWith("Regional Manager")) {
  const match = finalRole.match(/\((.*?)\)/);
  if (match) {
    clusterName = match[1];
  }
}

logSuccess("Login successful", {
  userId,
  role: finalRole,
  branch: user.BranchName,
  branchCode: user.BranchCode,
  cluster: clusterName
});
// 5️⃣ SUCCESS
logInfo("Sending login response", { userId, role: finalRole });
return res.json({
  message: "Login successful",
  userId: userId,
  role: finalRole,
  branchName: user.BranchName,
  branchCode: user.BranchCode,
  clusterName: clusterName
});

  } catch (err) {
    logError("Login API error", { userId, err });
    logInfo("Login error response sent", { userId });
    return res.status(500).json({ message: "Internal server error" });
  }
});


/* ====================================================
   FORGOT PASSWORD – VALIDATE USER ID
   ==================================================== */

app.post("/api/forgot-password/validate-user", async (req, res) => {
  const { userId } = req.body;
  logInfo("Validate-user API hit", { userId: req.body.userId });

 if (!userId) {
  logWarn("Validate-user missing userId");
    return res.status(400).json({ message: "UserId is required" });
  }

  try {
    const pool = await poolPromise;
    const request = pool.request();

    request.input("UserId", sql.VarChar(50), String(userId).trim());

    logInfo("Checking user for forgot password", { userId });
    const result = await request.query(`
      SELECT TOP 1 SecurityQuestion
      FROM UserAuth
      WHERE UserId = @UserId
    `);

    if (result.recordset.length === 0) {
      logWarn("Forgot password user not found", { userId });
      return res.status(401).json({
        message: "User not authorized"
      });
    }

    // ✅ Convert q1/q2/q3 into full question text
    const questionMap = {
      q1: "What is your mother’s maiden name?",
      q2: "What was the name of your first school?",
      q3: "What is your favourite colour?",
      q4: "What is your date of birth?",
      q5: "What is your favourite food?",
      q6: "What is the name of your best friend?",
      q7: "What city were you born in?",
      q8: "What was your first vehicle number?",
      q9: "What is your favourite movie?",
      q10: "What is your pet’s name?",
    };

    const storedValue = result.recordset[0].SecurityQuestion; // ex: "q1"
    const fullQuestion = questionMap[storedValue] || storedValue;

    logSuccess("User validated for forgot password", { userId });
    logInfo("Validate-user response sent", { userId });
    return res.status(200).json({
      securityQuestion: fullQuestion,   // ✅ now frontend gets full sentence
      securityKey: storedValue          // ✅ optional: keep original also
    });

  } catch (err) {
    logError("Validate-user API error", { userId, err });
    return res.status(500).json({
      message: "Internal server error"
    });
  }
});




/* ====================================================
   FORGOT PASSWORD – VERIFY ANSWER & RESET PASSWORD
   ==================================================== */

app.post("/api/forgot-password/reset-password", async (req, res) => {
  const { userId, securityAnswer, newPassword } = req.body;
  logInfo("Reset-password API hit", { userId: req.body.userId });

  if (!userId || !securityAnswer || !newPassword) {
    logWarn("Reset password validation failed", { userId });
    return res.status(400).json({
      message: "UserId, security answer and new password are required"
    });
  }

  try {
    const pool = await poolPromise;

    // 1️⃣ Verify security answer
    const verifyRes = await pool.request()
      .input("UserId", sql.VarChar(50), String(userId).trim())
      .input("SecurityAnswer", sql.VarChar(255), String(securityAnswer).trim())
      .query(`
        SELECT AuthId
        FROM UserAuth
        WHERE UserId = @UserId
          AND SecurityAnswer = @SecurityAnswer
      `);

    if (verifyRes.recordset.length === 0) {
      logWarn("Invalid security answer during reset", { userId });
      return res.status(401).json({
        message: "Invalid security answer"
      });
    }

    // 2️⃣ Update password
    logInfo("Updating password", { userId });
    await pool.request()
      .input("UserId", sql.VarChar(50), String(userId).trim())
      .input("NewPassword", sql.VarChar(255), String(newPassword))
      .query(`
        UPDATE UserAuth
        SET AppPassword = @NewPassword
        WHERE UserId = @UserId
      `);

      logSuccess("Password reset successful", { userId });
      logInfo("Password reset response sent", { userId });
    return res.status(200).json({
      message: "Password updated successfully"
    });

  } catch (err) {
    logError("Reset-password API error", { userId, err });
    return res.status(500).json({
      message: "Internal server error"
    });
  }
});


/* ====================================================
   FORGOT PASSWORD – VERIFY SECURITY ANSWER
   ==================================================== */

app.post("/api/forgot-password/verify-answer", async (req, res) => {
  const { userId, securityAnswer } = req.body;
  logInfo("Verify-answer API hit", { userId: req.body.userId });

  if (!userId || !securityAnswer) {
    logWarn("Verify-answer validation failed", { userId });
    return res.status(400).json({
      message: "UserId and security answer are required"
    });
  }

  try {
    const pool = await poolPromise;

    const result = await pool.request()
      .input("UserId", sql.VarChar(50), String(userId).trim())
      .input("SecurityAnswer", sql.VarChar(255), String(securityAnswer).trim())
      .query(`
        SELECT AuthId
        FROM UserAuth
        WHERE UserId = @UserId
          AND SecurityAnswer = @SecurityAnswer
      `);

    if (result.recordset.length === 0) {
      logWarn("Security answer incorrect", { userId });
      return res.status(401).json({
        message: "Invalid security answer"
      });
    }

    // ✅ Answer is correct
    logSuccess("Security answer verified", { userId });
    logInfo("Verify-answer response sent", { userId });
    return res.status(200).json({
      message: "Security answer verified"
    });

  } catch (err) {
    logError("Verify-answer API error", { userId, err });
    return res.status(500).json({
      message: "Internal server error"
    });
  }
});


// ======================
// Accounts Unlock
// ======================

app.get("/api/locked-users", async (req, res) => {
  const userId = req.headers.userid;

  const allowedUsers = [
    "IT_099_1011",
    "IT_099_1009",
    "IT_099_866"
  ];

  if (!allowedUsers.includes(userId)) {
    return res.status(403).json({
      message: "Access denied"
    });
  }
  
  try {
    const pool = await poolPromise;

    const result = await pool.request().query(`
      SELECT
        UA.UserId,
        ISNULL(UI.UserName, '') AS UserName,
        UA.FailedAttempts,
        UA.IsLocked
      FROM UserAuth UA
      LEFT JOIN UsersInfo UI
        ON UA.UserId = UI.UserId
      WHERE UA.IsLocked = 1
      ORDER BY UA.UserId
    `);

    return res.status(200).json(
      result.recordset.map(row => ({
        userId: row.UserId,
        userName: row.UserName,
        failedAttempts: row.FailedAttempts,
        isLocked: row.IsLocked
      }))
    );

  } catch (err) {
    console.error("Locked users error:", err);
    return res.status(500).json({
      message: "Internal server error"
    });
  }
});


app.post("/api/unlock-user", async (req, res) => {
  const loginUserId = req.headers.userid;

  const allowedUsers = [
    "IT_099_1011",
    "IT_099_1009",
    "IT_099_866"
  ];

  if (!allowedUsers.includes(loginUserId)) {
    return res.status(403).json({
      message: "Access denied"
    });
  }

  const { userId, newPassword } = req.body;

  if (!userId || !newPassword) {
    return res.status(400).json({
      message: "User ID and Password required"
    });
  }

  try {
    const pool = await poolPromise;

    await pool.request()
      .input("userId", sql.VarChar(50), userId)
      .input("newPassword", sql.VarChar(255), newPassword)
      .query(`
        UPDATE UserAuth
        SET
          AppPassword = @newPassword,
          FailedAttempts = 0,
          IsLocked = 0,
          LastLoginAt = GETDATE()
        WHERE UserId = @userId
      `);

    return res.status(200).json({
      message: "Account unlocked successfully"
    });

  } catch (err) {
    console.error("Unlock user error:", err);

    return res.status(500).json({
      message: "Internal server error"
    });
  }
});



// ======================
// HOME USER DETAILS
// ======================
app.get("/api/user/:userId", async (req, res) => {
  try {

    const pool = await poolPromise;

    const result = await pool.request()
      .input("UserId", sql.VarChar, req.params.userId)
      .query(`
        SELECT 
          UserId,
          UserName,
          ClusterName,
          BranchCode,
          BranchName,
          Role,
		  Designation
        FROM UsersInfo
        WHERE UserId = @UserId
      `);

    res.json(result.recordset[0]);

  } catch (error) {

    console.error("User Fetch Error:", error);
    res.status(500).send("Server Error");

  }
});



// ===============================================================================================================================================================================================
//                           ACTIVITY LOGGING APIs
// ==================================================================================================================================================================================================

// =============================== ACTIVITY START ===========================================

app.post("/api/activity/session/start", async (req, res) => {
console.log("📥 [SESSION_START_API] request", {
  userId: req.body?.userId,
  userName: req.body?.userName,
  sourceType: req.body?.sourceType,
  sourceId: req.body?.sourceId,
  sessionType: req.body?.sessionType
});
  const {
    loanAccountNumber,
    sessionType,
    userId,
    userName,
    sourceType,
    sourceId,
  } = req.body;

  if (!sessionType || !userId || !userName || !sourceType) {
	  console.log("⚠️ [SESSION_START_API] missing required fields", {
  userId,
  sourceType,
  sessionType
});
    return res.status(400).json({ message: "Missing required fields" });
  }

  if (sourceType === "NPA" && !loanAccountNumber) {
	  console.log("⚠️ [SESSION_START_API] NPA without loanAccountNumber", {
  userId
});
    return res.status(400).json({ message: "LoanAccountNumber required for NPA" });
  }

  try {
    const pool = await poolPromise;
console.log("📊 [SESSION_START_API] creating session", {
  userId,
  sourceType
});
    let assignmentId = null;

    if (sourceType === "NPA") {
		console.log("📊 [SESSION_START_API] fetching assignment", {
  loanAccountNumber,
  userId
});
      const assignRes = await pool.request()
        .input("LoanAccountNumber", sql.VarChar(50), loanAccountNumber)
        .input("UserId", sql.VarChar(50), String(userId))
        .query(`
          SELECT TOP 1 AssignmentId
          FROM Account_Assignments
          WHERE LoanAccountNumber = @LoanAccountNumber
            AND AssignedToUserId = @UserId
            AND AssignmentStatus = 'Assigned'
          ORDER BY AssignedAt DESC
        `);

      if (assignRes.recordset.length === 0) {
		  			console.log("⚠️ [SESSION_START_API] assignment not found", {
  loanAccountNumber,
  userId
});
        return res.status(404).json({

          message: "Assignment not found for this loan and user",
        });
      }

      assignmentId = assignRes.recordset[0].AssignmentId;
    }

    const result = await pool.request()
  .input("AssignmentId", sql.BigInt, assignmentId || null)
  .input(
    "LoanAccountNumber",
    sql.VarChar(50),
    sourceType === "LEAD"
      ? `LEAD-${sourceId}`
      : loanAccountNumber
  )
  .input("SessionType", sql.VarChar(20), sessionType)
  .input("StartedByUserId", sql.VarChar(50), String(userId))
  .input("StartedByUserName", sql.VarChar(100), userName)
  .input("SourceType", sql.VarChar(20), sourceType || null)
  .input("SourceId", sql.VarChar(50), sourceId ? String(sourceId) : null)
  .query(`
    INSERT INTO Activity_Sessions (
      AssignmentId,
      LoanAccountNumber,
      SessionType,
      SessionStatus,
      StartedByUserId,
      StartedByUserName,
      SourceType,
      SourceId,
      IsActive
    )
    OUTPUT INSERTED.SessionId
    VALUES (
      @AssignmentId,
      @LoanAccountNumber,
      @SessionType,
      'ACTIVE',
      @StartedByUserId,
      @StartedByUserName,
      @SourceType,
      @SourceId,
      1
    )
  `);

console.log("✅ [SESSION_START_API] session created", {
  sessionId: result.recordset[0].SessionId,
  sourceType
});

    return res.status(200).json({
      sessionId: result.recordset[0].SessionId,
      assignmentId,
    });

  } catch (err) {
    console.error("❌ [SESSION_START_API] error:", {
  message: err.message,
  stack: err.stack,
  userId: req.body?.userId,
  sourceType: req.body?.sourceType
});
    return res.status(500).json({ message: "Failed to start session" });
  }
});

//============================================= ACTIVITY LOGS =======================================================

app.post("/api/activity/log", async (req, res) => {

  console.log("📥 [ACTIVITY_LOG_API] request", {
  sessionId: req.body?.sessionId,
  actionCode: req.body?.actionCode,
  sourceType: req.body?.sourceType,
  sourceId: req.body?.sourceId
});

  const {
    sessionId,
    actionCode,
    actionLabel,
    reasonCode = null,
    metadata = null,
    noteText = null,
    userId,
    userName,
    sourceType,
    sourceId,
  } = req.body;

  try {

    const pool = await poolPromise;

    let sessionIdToUse = sessionId;

    // ⭐ Recover session if mobile lost it
    if (!sessionIdToUse) {
console.log("🔄 [ACTIVITY_LOG_API] session recovering", {
  userId,
  sourceId
});
      const result = await pool.request()
        .input("userId", sql.VarChar(50), String(userId))
        .input("loanAccountNumber", sql.VarChar(50), String(sourceId))
        .query(`
          SELECT TOP 1 SessionId
          FROM Activity_Sessions
          WHERE StartedByUserId = @userId
          AND LoanAccountNumber = @loanAccountNumber
          AND IsActive = 1
          ORDER BY StartedAt DESC
        `);

if (result.recordset.length > 0) {
  sessionIdToUse = result.recordset[0].SessionId;

  console.log("✅ [ACTIVITY_LOG_API] session recovered", {
    sessionId: sessionIdToUse
  });
}
}
    // validation
    if (!Number(sessionIdToUse)) {
console.log("⚠️ [ACTIVITY_LOG_API] invalid sessionId", {
  sessionId: sessionIdToUse
});
      return res.status(400).json({ message: "Invalid sessionId" });
    }

    if (!sessionIdToUse || !actionCode || !actionLabel || !userId) {
console.log("⚠️ [ACTIVITY_LOG_API] missing fields", {
  actionCode,
  sessionId: sessionIdToUse
});
      return res.status(400).json({ message: "Missing required fields" });
    }

    // 1️⃣ Get last log for hierarchy
    const parentResult = await pool
      .request()
      .input("SessionId", sql.BigInt, parseInt(sessionIdToUse))
      .query(`
        SELECT TOP 1 LogId
        FROM Activity_Logs
        WHERE SessionId = @SessionId
        ORDER BY CreatedAt DESC
      `);

    const parentLogId =
      parentResult.recordset.length > 0
        ? parentResult.recordset[0].LogId
        : null;
console.log("📊 [ACTIVITY_LOG_API] inserting log", {
  sessionId: sessionIdToUse,
  actionCode
});
    // 2️⃣ Insert Activity Log
    const logResult = await pool
      .request()
      .input("SessionId", sql.BigInt, parseInt(sessionIdToUse))
      .input("ParentLogId", sql.BigInt, parentLogId)
      .input("ActionCode", sql.VarChar(100), actionCode)
      .input("ActionLabel", sql.VarChar(200), actionLabel)
      .input("ReasonCode", sql.VarChar(50), reasonCode)
      .input("SourceType", sql.VarChar(20), sourceType || null)
      .input("SourceId", sql.VarChar(50), sourceId ? String(sourceId) : null)
      .input(
        "MetadataJson",
        sql.NVarChar(sql.MAX),
        metadata ? JSON.stringify(metadata) : null
      )
      .input("CreatedByUserId", sql.VarChar(50), String(userId))
      .input("CreatedByUserName", sql.VarChar(100), userName)
      .query(`
        INSERT INTO Activity_Logs (
          SessionId,
          ParentLogId,
          ActionCode,
          ActionLabel,
          ReasonCode,
          MetadataJson,
          CreatedByUserId,
          CreatedByUserName,
          SourceType,
          SourceId
        )
        OUTPUT INSERTED.LogId
        VALUES (
          @SessionId,
          @ParentLogId,
          @ActionCode,
          @ActionLabel,
          @ReasonCode,
          @MetadataJson,
          @CreatedByUserId,
          @CreatedByUserName,
          @SourceType,
          @SourceId
        )
      `);

    const logId = logResult.recordset[0].LogId;
console.log("✅ [ACTIVITY_LOG_API] log inserted", {
  logId,
  actionCode,
  userId,
  userName
});
    // ✅ Only these actions should affect status table + schedule flags
    const statusActionCodes = [
      "CALL_BUSY",
      "CALL_NOT_REACHABLE",

      "CALL_BACK_LATER",
      "SCHEDULE_CALL",
      "SCHEDULE_VISIT",
      "SCHEDULE_VISIT_FOR_COLLECTION",
      "INVALID_NUMBER_VISIT",
      "PHYSICAL_VISIT",
      "SCHEDULED",

      "ACCOUNT_CLOSED_YES",
      "CALL_COMPLETED",
      "SUBMITTED",

      "VISIT_FOLLOWUP_SCHEDULED",
      "VISIT_COMPLETED",
    ];

    if (!statusActionCodes.includes(actionCode)) {
      console.log("⏩ Skipping status updates for:", actionCode);
    } else {
      // ✅ Fetch LoanAccountNumber + AssignmentId from session
      const sessionRes = await pool
        .request()
        .input("SessionId", sql.BigInt, parseInt(sessionIdToUse))
        .query(`
          SELECT TOP 1 LoanAccountNumber, AssignmentId
          FROM Activity_Sessions
          WHERE SessionId = @SessionId
        `);

      if (sessionRes.recordset.length > 0) {
        const { LoanAccountNumber, AssignmentId } = sessionRes.recordset[0];

        let scheduleCallDate = null;
        let scheduleCallTime = null;

        let scheduleVisitDate = null;
        let scheduleVisitTime = null;

        const parseTimeTo24Hr = (timeStr) => {
          if (!timeStr) return null;

          const parts = timeStr.trim().split(" ");
          if (parts.length < 2) return timeStr;

          const [hm, ap] = parts;
          let [h, m] = hm.split(":").map(Number);
          const ampm = ap.toUpperCase();

          if (ampm === "PM" && h < 12) h += 12;
          if (ampm === "AM" && h === 12) h = 0;

          return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
        };

        // =====================================================
        // ✅ BUILD TIMESTAMP ONLY FOR actionCode = SCHEDULED
        // =====================================================
        if (actionCode === "SCHEDULED" && metadata?.date && metadata?.time) {
          console.log("✅ SCHEDULED meta:", metadata, "mode:", metadata?.mode);

          // ✅ CALL schedule modes
          if (
            metadata.mode === "READY_CALL" ||
            metadata.mode === "SCHEDULE_CALL" ||
            metadata.mode === "CALL_BACK_LATER" ||
            metadata.mode === "LUMPSUM_CALL" ||
            metadata.mode === "CLOSE_ACCOUNT_NO_CALL" ||
            metadata.mode === "FO_NOT_VISITED_CALL" ||
            metadata.mode === "NOT_TAKEN_LOAN_CALL" ||
            metadata.mode === "LOAN_BY_RELATIVE_CALL" ||
            metadata.mode === "RELATIVE_CALL" ||
            metadata.mode === "NOT_READY_OTHERS_CALL" ||
            metadata.mode === "REASON_CALL"
          ) {
            scheduleCallDate = metadata.date;
            scheduleCallTime = parseTimeTo24Hr(metadata.time);
          }

          // ✅ VISIT schedule modes
          if (
            metadata.mode === "READY_VISIT" ||
            metadata.mode === "PHYSICAL_VISIT" ||
            metadata.mode === "INVALID_NUMBER_VISIT" ||
            metadata.mode === "SCHEDULE_VISIT" ||
            metadata.mode === "SCHEDULE_VISIT_FOR_COLLECTION" ||
            metadata.mode === "LUMPSUM_VISIT" ||
            metadata.mode === "CLOSE_ACCOUNT_NO_VISIT" ||
            metadata.mode === "FO_NOT_VISITED_VISIT" ||
            metadata.mode === "NOT_TAKEN_LOAN_VISIT" ||
            metadata.mode === "LOAN_BY_RELATIVE_VISIT" ||
            metadata.mode === "RELATIVE_VISIT" ||
            metadata.mode === "NOT_READY_OTHERS_VISIT" ||
            metadata.mode === "REASON_VISIT"
          ) {
            scheduleVisitDate = metadata.date;
            scheduleVisitTime = parseTimeTo24Hr(metadata.time);
          }
        }

        // =====================================================
        // ✅ UNSCHEDULE VISIT FLOW (VISIT_FOLLOWUP_SCHEDULED)
        // =====================================================
        if (
          actionCode === "VISIT_FOLLOWUP_SCHEDULED" &&
          metadata?.type &&
          metadata?.date &&
          metadata?.time
        ) {
          console.log("✅ VISIT_FOLLOWUP_SCHEDULED meta:", metadata);

          if (metadata.type === "CALL") {
            scheduleCallDate = metadata.date;
            scheduleCallTime = parseTimeTo24Hr(metadata.time);
          }

          if (metadata.type === "VISIT") {
            scheduleVisitDate = metadata.date;
            scheduleVisitTime = parseTimeTo24Hr(metadata.time);
          }
        }

        // ✅ 1) Update CallRecovery_Status main flags + timestamps
        try {
console.log("📊 [ACTIVITY_LOG_API] updating recovery status", {
  actionCode,
  LoanAccountNumber
});
          await pool
            .request()
            .input("LoanAccountNumber", sql.VarChar(50), LoanAccountNumber)
            .input("AssignmentId", sql.BigInt, AssignmentId)
            .input("UserId", sql.VarChar(50), String(userId))
            .input("ActionCode", sql.VarChar(100), actionCode)
            .input("ActionLabel", sql.VarChar(200), actionLabel)
            .input("ScheduleCallDate", sql.VarChar(10), scheduleCallDate)
            .input("ScheduleCallTime", sql.VarChar(5), scheduleCallTime)
            .input("ScheduleVisitDate", sql.VarChar(10), scheduleVisitDate)
            .input("ScheduleVisitTime", sql.VarChar(5), scheduleVisitTime)
            .execute("sp_UpdateCallRecoveryStatus");
        } catch (e) {
          console.error("❌ CallRecovery_Status update failed:", e);
        }

        // ✅ 2) Update Schedule For The Day flags (Pending/Completed)
        try {
          // ✅ FINAL FIX ✅: perfect Mode support for BOTH flows
          // priority:
          // 1) metadata.source ("CALL"/"VISIT") ✅ BEST FOR ACCOUNT_CLOSED_YES
          // 2) metadata.mode (READY_CALL / REASON_VISIT etc)
          // 3) metadata.type (CALL/VISIT)
          // 4) fallback "CALL"
          const derivedMode =
            metadata?.source ||
            metadata?.mode ||
            metadata?.type ||
            "CALL";
console.log("📊 [ACTIVITY_LOG_API] updating schedule flags", {
  actionCode,
  mode: derivedMode
});
          await pool
            .request()
            .input("LoanAccountNumber", sql.VarChar(50), LoanAccountNumber)
            .input("UserId", sql.VarChar(50), String(userId))
            .input("ActionCode", sql.VarChar(100), actionCode)
            .input("Mode", sql.VarChar(50), derivedMode)
            .execute("sp_UpdateScheduleForDayFlags");
        } catch (e) {
          console.error("❌ ScheduleForDay flags update failed:", e);
        }
      }
    }

    // 3️⃣ Insert note ONLY if provided
    if (noteText && noteText.trim() !== "") {
console.log("📝 [ACTIVITY_LOG_API] inserting note", {
  logId
});
      await pool
        .request()
        .input("LogId", sql.BigInt, logId)
        .input("NoteText", sql.NVarChar(sql.MAX), noteText)
        .input("CreatedByUserId", sql.VarChar(50), String(userId))
        .input("CreatedByUserName", sql.VarChar(100), userName)
        .query(`
          INSERT INTO Activity_Notes (
            LogId,
            NoteText,
            CreatedByUserId,
            CreatedByUserName
          )
          VALUES (
            @LogId,
            @NoteText,
            @CreatedByUserId,
            @CreatedByUserName
          )
        `);
    }
console.log("📤 [ACTIVITY_LOG_API] response sent", {
  logId
});
    return res.status(200).json({
      success: true,
      logId,
      message: "Activity log saved + status updated",
    });
  } catch (err) {
    console.error("❌ [ACTIVITY_LOG_API] error:", {
  message: err.message,
  stack: err.stack,
  actionCode: req.body?.actionCode,
  sessionId: req.body?.sessionId
});
    return res.status(500).json({ message: "Failed to insert activity log" });
  }
});

//======================== ACTIVITY END ================================================

app.post("/api/activity/session/end", async (req, res) => {

console.log("📥 [SESSION_END_API] request", {
  sessionId: req.body?.sessionId,
  userId: req.body?.userId,
  userName: req.body?.userName
});

  const { sessionId } = req.body;

  if (!sessionId) {
    console.log("⚠️ [SESSION_END_API] missing sessionId");
    return res.status(400).json({ message: "SessionId is required" });
  }

  try {
    const pool = await poolPromise;

    console.log("📊 [SESSION_END_API] ending session", {
      sessionId
    });

    await pool.request()
      .input("SessionId", sql.BigInt, parseInt(sessionId))
      .query(`
        UPDATE Activity_Sessions
        SET SessionStatus = 'COMPLETED',
            EndedAt = SYSDATETIME()
        WHERE SessionId = @SessionId
      `);

    console.log("✅ [SESSION_END_API] session ended", {
      sessionId
    });

    return res.status(200).json({ success: true });

  } catch (err) {
    console.error("❌ [SESSION_END_API] error:", {
      message: err.message,
      stack: err.stack,
      sessionId: req.body?.sessionId
    });
    return res.status(500).json({ message: "Failed to end session" });
  }
});

// ======================
// Activity Status
// ======================

app.post("/api/activity-status/search", async (req, res) => {

  const {
    mobileNumber = "",
    pincode = "",
    branchName = "",
    product = "",
    assignedTo = "",
    loanAccount = "",
    memberName = "",
    cluster = "",
	queue = "",
    dpdQueue = ""
  } = req.body;
  
   logInfo("SEARCH API HIT", {
  mobileNumber,
  pincode,
  branchName,
  product,
  assignedTo,
  loanAccount,
  memberName,
  cluster,
  queue,
  dpdQueue
});

  try {
	  
	const userId = req.headers["x-user-id"];
  logInfo("User ID received", userId);
if (!userId) {
  logWarn("Unauthorized access attempt");
  return res.status(401).json({ message: "Unauthorized" });
}

const pool = await poolPromise;

const roleResult = await pool.request()
  .input("userId", sql.VarChar, userId)
  .query(`
    SELECT Role, BranchName, ClusterName
    FROM UsersInfo
    WHERE UserId = @userId
  `);

const userInfo = roleResult.recordset[0];
logSuccess("User info fetched", userInfo);
    const request = pool.request();

    let query = `
      SELECT DISTINCT
  R.firstname AS memberName,
  R.loanAccountNumber,
  R.mobileNumber,
  R.branchName,
  A.AssignedToUserName AS assignedTo
      FROM Recovery_Raw_Data R
      INNER JOIN Account_Assignments A
        ON A.LoanAccountNumber = R.loanAccountNumber
       AND A.AssignmentStatus = 'Assigned'
      WHERE 1 = 1
    `;
	
	if (userInfo.Role === "Branch Manager") {
  query += ` AND R.branchName = @userBranch`;
  request.input("userBranch", userInfo.BranchName);
}

const isRegionalManager = userInfo.Role?.startsWith("Regional Manager");

if (isRegionalManager) {
  query += `
    AND R.branchName IN (
      SELECT branch_name
      FROM Branch_Cluster_Master
      WHERE cluster_name = @restrictedCluster
    )
  `;

  request.input("restrictedCluster", sql.VarChar, userInfo.ClusterName);
}
  

    if (mobileNumber) {
      query += ` AND R.mobileNumber = @mobileNumber`;
      request.input("mobileNumber", mobileNumber);
    }

    if (pincode) {
      query += ` AND R.pincode = @pincode`;
      request.input("pincode", pincode);
    }

    if (branchName) {
      query += ` AND R.branchName = @branchName`;
      request.input("branchName", branchName);
    }

    if (product) {
      query += ` AND R.product = @product`;
      request.input("product", product);
    }
	
	// ================= Queue Filter =================
if (queue === "NPA") {
  query += ` AND R.dpdQueue >= '04'`;
}
else if (queue === "Marketing") {
  query += ` AND R.QueueType = 'Marketing'`;
}
else if (queue === "Welcome Call") {
  query += ` AND R.QueueType = 'Welcome Call'`;
}

// ================= DPD Queue Filter =================
if (dpdQueue) {

  if (dpdQueue === "0-30") {
    query += ` AND R.dpdQueue = '01'`;
  }

  else if (dpdQueue === "31-60") {
    query += ` AND R.dpdQueue = '02'`;
  }

  else if (dpdQueue === "61-90") {
    query += ` AND R.dpdQueue = '03'`;
  }

  else if (dpdQueue === "90+") {
    query += ` AND R.dpdQueue >= '04'`;
  }
}

    if (loanAccount) {
      query += ` AND R.loanAccountNumber = @loanAccount`;
      request.input("loanAccount", loanAccount);
    }

    if (memberName) {
      query += ` AND R.firstname LIKE '%' + @memberName + '%'`;
      request.input("memberName", memberName);
    }

    if (assignedTo) {
      query += ` AND A.AssignedToUserId = @assignedTo`;
      request.input("assignedTo", assignedTo);
    }

   if (cluster && cluster !== "Corporate Office") {
  query += `
    AND R.branchName IN (
      SELECT branch_name
      FROM Branch_Cluster_Master
      WHERE cluster_name = @cluster
    )
  `;
  request.input("cluster", cluster);
}

logInfo("Executing search query with filters", {
  mobileNumber,
  branchName,
  product,
  assignedTo,
  cluster,
  queue,
  dpdQueue
});
    const result = await request.query(query);
    logSuccess("Search result count", result.recordset.length);
    return res.json(result.recordset);

  } catch (err) {
    logError("ACTIVITY STATUS SEARCH ERROR", err);
    return res.status(500).json({ message: "Search failed" });
  }
});

// =====================================================================
// ACTIVITY DETAILS
// =====================================================================

app.post("/api/npa-activity-details", async (req, res) => {

  logInfo("ACTIVITY DETAILS API HIT", req.body);

  const { loanAccountNumber } = req.body;

  if (!loanAccountNumber) {
    logWarn("Loan account number missing");
    return res.status(400).json([]);
  }

  try {

    const userId = req.headers["x-user-id"];
    logInfo("User ID received", userId);
    if (!userId) {
  logWarn("Unauthorized access - search API");
  return res.status(401).json({ message: "Unauthorized" });
}

    const pool = await poolPromise;

    const roleResult = await pool.request()
      .input("userId", sql.VarChar, userId)
      .query(`
        SELECT Role, BranchName, ClusterName
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    const userInfo = roleResult.recordset[0];

// ================= BRANCH MANAGER RESTRICTION =================

if (userInfo.Role === "Branch Manager") {

  const check = await pool.request()
    .input("loanAccountNumber", sql.VarChar, loanAccountNumber)
    .input("branch", sql.VarChar, userInfo.BranchName)
    .query(`
      SELECT 1
      FROM Recovery_Raw_Data
      WHERE loanAccountNumber = @loanAccountNumber
      AND branchName = @branch
    `);

  if (check.recordset.length === 0) {
    logWarn("Access denied for Branch Manager", loanAccountNumber);
    return res.status(403).json({ message: "Access denied" });
  }
}

// ================= REGIONAL MANAGER RESTRICTION =================

const isRegionalManager = userInfo.Role?.startsWith("Regional Manager");

if (isRegionalManager) {

  const check = await pool.request()
    .input("loanAccountNumber", sql.VarChar, loanAccountNumber)
    .input("cluster", sql.VarChar, userInfo.ClusterName)
    .query(`
      SELECT 1
      FROM Recovery_Raw_Data R
      WHERE R.loanAccountNumber = @loanAccountNumber
      AND R.branchName IN (
        SELECT branch_name
        FROM Branch_Cluster_Master
        WHERE cluster_name = @cluster
      )
    `);

  if (check.recordset.length === 0) {
    logWarn("Access denied for Regional Manager", loanAccountNumber);
    return res.status(403).json({ message: "Access denied" });
  }
}

    // ================= FETCH SESSIONS =================

    const request = pool.request()
      .input("loanAccountNumber", sql.VarChar, loanAccountNumber);

    const sessionsResult = await request.query(`
      SELECT
        s.SessionId,
        CONVERT(varchar, s.StartedAt, 105) AS activityDate,
        FORMAT(s.StartedAt, 'hh:mm tt') AS activityTime,
        s.StartedByUserName AS userName,
        s.SessionType,
        s.SessionStatus
      FROM Activity_Sessions s
      WHERE s.LoanAccountNumber = @loanAccountNumber
      AND ISNULL(s.SourceType,'NPA') = 'NPA'
      ORDER BY s.StartedAt DESC
    `);

    const sessions = sessionsResult.recordset;
    logSuccess("Sessions fetched", sessions.length);

    if (sessions.length === 0) {
  logWarn("No sessions found", loanAccountNumber);
  return res.json([]);
}

    // ================= FETCH LOGS =================

    const sessionIds = sessions.map(s => s.SessionId);

const requestLogs = pool.request();

sessionIds.forEach((id, index) => {
  requestLogs.input(`sid${index}`, sql.VarChar, id);
});

const logsResult = await requestLogs.query(`
  SELECT 
    L.SessionId,
    L.LogId,
    L.ActionLabel,
    N.NoteText
  FROM Activity_Logs L
  LEFT JOIN Activity_Notes N
    ON L.LogId = N.LogId
  WHERE L.SessionId IN (${sessionIds.map((_, i) => `@sid${i}`).join(",")})
  ORDER BY L.CreatedAt
`);

const logs = logsResult.recordset;
logSuccess("Logs fetched", logs.length);

    // ================= GROUP LOGS =================

    const response = sessions.map(session => {

  const sessionLogs = logs.filter(
    l => l.SessionId === session.SessionId
  );

  const actions = sessionLogs
    .map((l, index) => `${index + 1}. ${l.ActionLabel}`)
    .join("\n");

  let notes = sessionLogs
  .map(log => log.NoteText || "")
  .filter(n => n.trim() !== "")
  .join("\n");

  return {
    activityDate: session.activityDate,
    activityTime: session.activityTime,
    userName: session.userName,
    activityType: session.SessionType,
    activityStatus: actions || "",
    notes
  };

});

logSuccess("Activity details response sent");
    res.json(response);

  } catch (err) {

    logError("ACTIVITY DETAILS ERROR", err);
    res.status(500).json([]);

  }
});

// ============================================================
// ACTIVITY STATUS → EXPORT PDF (MATCHES TRANSACTION FORMAT)
// ============================================================

app.post("/api/activity-status/export-pdf", async (req, res) => {
  logInfo("EXPORT PDF API HIT", req.body);
  const { selectedIds, columns, fileName, serialData } = req.body;

  if (!selectedIds || selectedIds.length === 0) {
    logWarn("No records selected for PDF");
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {
    
	const userId = req.headers["x-user-id"];
  logInfo("User ID received", userId);
if (!userId) return res.status(401).json({ message: "Unauthorized" });

const pool = await poolPromise;

const roleResult = await pool.request()
  .input("userId", sql.Int, userId)
  .query(`
    SELECT Role, BranchName
    FROM UsersInfo
    WHERE UserId = @userId
  `);

const userInfo = roleResult.recordset[0];
    const request = pool.request();

    selectedIds.forEach((id, index) => {
      request.input(`id${index}`, sql.VarChar, id);
    });

    // 🔥 Preserve exact selected order
    const orderCase = selectedIds
      .map((id, index) => `WHEN R.loanAccountNumber = @id${index} THEN ${index}`)
      .join(" ");

      logInfo("Executing PDF query", selectedIds);
    const result = await request.query(`
      SELECT 
        R.firstname AS memberName,
        R.loanAccountNumber,
        R.mobileNumber,
        R.branchName,
        A.AssignedToUserName AS assignedTo,
        S.SessionId,
        CONVERT(varchar, S.StartedAt, 105) AS activityDate,
        FORMAT(S.StartedAt, 'hh:mm tt') AS activityTime,
        S.SessionType,
        S.SessionStatus,
        L.ActionLabel
      FROM dbo.Recovery_Raw_Data R
      INNER JOIN Account_Assignments A
        ON A.LoanAccountNumber = R.loanAccountNumber
      LEFT JOIN Activity_Sessions S
        ON S.LoanAccountNumber = R.loanAccountNumber
      LEFT JOIN Activity_Logs L
        ON L.SessionId = S.SessionId
      WHERE R.loanAccountNumber IN (${selectedIds.map((_, i) => `@id${i}`).join(",")})
      ORDER BY CASE ${orderCase} END, S.StartedAt DESC
    `);
	
	if (userInfo.Role === "Branch Manager") {
  query += ` AND R.branchName = @userBranch`;
  request.input("userBranch", userInfo.BranchName);
}
 
if (!result.recordset.length) {
  logWarn("No data found for PDF");
  return res.status(400).json({ message: "No records found for PDF" });
}

    // ================= GROUP DATA =================

    const grouped = {};

    result.recordset.forEach(row => {

      if (!grouped[row.loanAccountNumber]) {
        grouped[row.loanAccountNumber] = {
          memberName: row.memberName,
          loanAccountNumber: row.loanAccountNumber,
          mobileNumber: row.mobileNumber,
          branchName: row.branchName,
          assignedTo: row.assignedTo,
          sessions: {}
        };
      }

      if (row.SessionId) {

        if (!grouped[row.loanAccountNumber].sessions[row.SessionId]) {
          grouped[row.loanAccountNumber].sessions[row.SessionId] = {
            date: row.activityDate,
            time: row.activityTime,
            type: row.SessionType,
            status: row.SessionStatus,
            logs: new Set()
          };
        }

        if (row.ActionLabel) {
          grouped[row.loanAccountNumber]
            .sessions[row.SessionId]
            .logs.add(row.ActionLabel);
        }
      }
    });

    const data = Object.values(grouped);

    // Attach serial from frontend
    if (serialData && Array.isArray(serialData)) {
      const serialMap = {};
      serialData.forEach(item => {
        serialMap[item.loanAccountNumber] = item.serialNumber;
      });

      data.forEach(row => {
        row.serialNumber = serialMap[row.loanAccountNumber] || "";
      });
    }

    // Build activity text
    data.forEach(row => {
      const activityText = Object.values(row.sessions)
        .map(session => {
          const logs = [...session.logs]
            .map(l => `• ${l}`)
            .join("\n");

          return `Date: ${session.date}
Time: ${session.time}
Type: ${session.type}
Status: ${session.status}
${logs}`;
        })
        .join("\n\n");

      row.activityDetails = activityText || "No Activity";
    });

    // ================= PDF START =================

    const PDFDocument = require("pdfkit");

    const doc = new PDFDocument({
      size: "A4",
      layout: "landscape",
      margin: 40
    });

    const safeName = (fileName || "Activity_Report").replace(/\s+/g, "_");

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.pdf"`
    );

    doc.pipe(res);

    // ================= TITLE =================
    doc.font("Helvetica-Bold")
       .fontSize(16)
       .text("Activity Status Report", { align: "center" });

    doc.moveDown(1);

    const pageWidth =
      doc.page.width - doc.page.margins.left - doc.page.margins.right;

    // ===== SAME COLUMN WIDTH LOGIC AS TRANSACTION =====

    const columnWidths = {};

    columns.forEach(col => {
      if (col === "serialNumber") {
        columnWidths[col] = 50;
      } else {
        columnWidths[col] = null;
      }
    });

    const usedWidth = Object.values(columnWidths)
      .filter(w => w !== null)
      .reduce((a, b) => a + b, 0);

    const remainingCols = columns.filter(col => columnWidths[col] === null);
    const equalWidth = (pageWidth - usedWidth) / remainingCols.length;

    remainingCols.forEach(col => {
      columnWidths[col] = equalWidth;
    });

    const rowHeight = 22;

    const COLUMN_LABELS = {
      serialNumber: "S. No.",
      memberName: "Member",
      loanAccountNumber: "Loan A/c #",
      mobileNumber: "Mobile",
      branchName: "Branch",
      assignedTo: "Assigned To",
      activityDetails: "Activity Details"
    };

    let y = doc.y;

    const drawHeader = () => {
      let x = doc.page.margins.left;

      doc.font("Helvetica-Bold").fontSize(10);

      columns.forEach(col => {
        doc.rect(x, y, columnWidths[col], rowHeight)
           .fillAndStroke("#e2e8f0", "#94a3b8");

        doc.fillColor("#000")
           .text(COLUMN_LABELS[col], x + 5, y + 6, {
             width: columnWidths[col] - 10,
             align: "center"
           });

        x += columnWidths[col];
      });

      y += rowHeight;
      doc.font("Helvetica").fontSize(9);
    };

    drawHeader();

    // ================= ROWS =================

    data.forEach((row, index) => {

      let x = doc.page.margins.left;
      let dynamicHeight = 20;

      columns.forEach(col => {
        const text = String(row[col] ?? "");
        const textHeight = doc.heightOfString(text, {
          width: columnWidths[col] - 10
        });
        dynamicHeight = Math.max(dynamicHeight, textHeight + 10);
      });

      if (y + dynamicHeight > doc.page.height - 40) {
        doc.addPage({
          size: "A4",
          layout: "landscape",
          margin: 40
        });
        y = doc.page.margins.top;
        drawHeader();
      }

      if (index % 2 === 0) {
        doc.rect(x, y, pageWidth, dynamicHeight)
           .fill("#f8fafc");
      }

      columns.forEach(col => {
        doc.rect(x, y, columnWidths[col], dynamicHeight).stroke();

        doc.fillColor("#000")
           .text(String(row[col] ?? ""), x + 5, y + 5, {
             width: columnWidths[col] - 10
           });

        x += columnWidths[col];
      });

      y += dynamicHeight;
    });

    logSuccess("PDF generated successfully");
    doc.end();

  } catch (err) {
    logError("ACTIVITY PDF ERROR", err);
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});

// ==========================================================
// ACTIVITY STATUS ACTION API (Past / Future / Completed / Reactivate)
// ==========================================================
app.post("/api/activity-status/action", async (req, res) => {

  logInfo("ACTION API HIT", req.body);

  const {
    actionType,
    selectedIds = [],
    mobileNumber = "",
    pincode = "",
    branchName = "",
    product = "",
    assignedTo = "",
    loanAccount = "",
    memberName = "",
    cluster = "",
    queue = "",
    dpdQueue = ""
  } = req.body;

  if (!actionType) {
    logWarn("Action type missing");
    return res.status(400).json({ message: "actionType is required" });
  }

  try {
	  
	const userId = req.headers["x-user-id"];
  logInfo("User ID received", userId);

if (!userId) {
  return res.status(401).json({ message: "Unauthorized" });
}

const pool = await poolPromise;

const roleResult = await pool.request()
  .input("userId", sql.VarChar, userId)
  .query(`
    SELECT Role, BranchName
    FROM UsersInfo
    WHERE UserId = @userId
  `);

const userInfo = roleResult.recordset[0];    
    const request = pool.request();

    // ================= BASE QUERY =================
    let baseQuery = `
      FROM Account_Assignments A
      INNER JOIN Recovery_Raw_Data R
        ON R.loanAccountNumber = A.LoanAccountNumber
      INNER JOIN CallRecovery_Status CRS
        ON CRS.LoanAccountNumber = A.LoanAccountNumber
      WHERE A.AssignmentStatus = 'Assigned'
    `;
	
	  if (userInfo.Role === "Branch Manager") {
    baseQuery += ` AND R.branchName = @userBranch`;
    request.input("userBranch", userInfo.BranchName);
  }
    // ================= COMMON FILTERS =================

    if (mobileNumber) {
      baseQuery += ` AND R.mobileNumber = @mobileNumber`;
      request.input("mobileNumber", mobileNumber);
    }

    if (pincode) {
      baseQuery += ` AND R.pincode = @pincode`;
      request.input("pincode", pincode);
    }

    if (branchName) {
      baseQuery += ` AND R.branchName = @branchName`;
      request.input("branchName", branchName);
    }

    if (product) {
      baseQuery += ` AND R.product = @product`;
      request.input("product", product);
    }

    if (loanAccount) {
      baseQuery += ` AND R.loanAccountNumber = @loanAccount`;
      request.input("loanAccount", loanAccount);
    }

    if (memberName) {
      baseQuery += ` AND R.firstname LIKE '%' + @memberName + '%'`;
      request.input("memberName", memberName);
    }

    if (assignedTo) {
      baseQuery += ` AND A.AssignedToUserId = @assignedTo`;
      request.input("assignedTo", assignedTo);
    }

    if (cluster && cluster !== "Corporate Office") {
      baseQuery += `
        AND R.branchName IN (
          SELECT branch_name
          FROM Branch_Cluster_Master
          WHERE cluster_name = @cluster
        )
      `;
      request.input("cluster", cluster);
    }

    // ================= Queue Filter =================
    if (queue === "NPA") {
      baseQuery += ` AND R.dpdQueue >= '04'`;
    }
    else if (queue === "Marketing") {
      baseQuery += ` AND R.QueueType = 'Marketing'`;
    }
    else if (queue === "Welcome Call") {
      baseQuery += ` AND R.QueueType = 'Welcome Call'`;
    }

    // ================= DPD Queue Filter =================
    if (dpdQueue === "0-30") {
      baseQuery += ` AND R.dpdQueue = '01'`;
    }
    else if (dpdQueue === "31-60") {
      baseQuery += ` AND R.dpdQueue = '02'`;
    }
    else if (dpdQueue === "61-90") {
      baseQuery += ` AND R.dpdQueue = '03'`;
    }
    else if (dpdQueue === "90+") {
      baseQuery += ` AND R.dpdQueue >= '04'`;
    }

    // ======================================================
    // 1️⃣ PAST SCHEDULE
    // ======================================================
    if (actionType === "past") {

      const query = `
        SELECT DISTINCT
          R.firstname AS memberName,
          R.loanAccountNumber,
          R.mobileNumber,
          R.branchName,
          A.AssignedToUserName AS assignedTo,
          CRS.ScheduleCallTimestamp,
          CRS.ScheduleVisitTimestamp
        ${baseQuery}
        AND (
      (CRS.ScheduleCallTimestamp IS NOT NULL 
       AND CONVERT(date, CRS.ScheduleCallTimestamp) < CONVERT(date, GETDATE()))
      OR
      (CRS.ScheduleVisitTimestamp IS NOT NULL 
       AND CONVERT(date, CRS.ScheduleVisitTimestamp) < CONVERT(date, GETDATE()))
    )
AND ISNULL(CRS.CompleteFlag,0) = 0
AND ISNULL(CRS.Submitted,0) = 0
      `;

      logInfo("Executing PAST action");
      const result = await request.query(query);
      
      return res.json(result.recordset);
    }

    // ======================================================
    // 2️⃣ FUTURE SCHEDULE
    // ======================================================
    if (actionType === "future") {
      logInfo("Executing FUTURE action");

      const query = `
        SELECT DISTINCT
          R.firstname AS memberName,
          R.loanAccountNumber,
          R.mobileNumber,
          R.branchName,
          A.AssignedToUserName AS assignedTo,
          CRS.ScheduleCallTimestamp,
          CRS.ScheduleVisitTimestamp
        ${baseQuery}
        AND (
              (CRS.ScheduleCallTimestamp IS NOT NULL AND CRS.ScheduleCallTimestamp > GETDATE())
              OR
              (CRS.ScheduleVisitTimestamp IS NOT NULL AND CRS.ScheduleVisitTimestamp > GETDATE())
            )
        AND ISNULL(CRS.CompleteFlag,0) = 0
        AND ISNULL(CRS.Submitted,0) = 0
      `;

      const result = await request.query(query);
      return res.json(result.recordset);
    }

 // ======================================================
// 3️⃣ COMPLETED ACTIVITIES (FINAL FIXED)
// ======================================================
if (actionType === "completed") {

  logInfo("Executing COMPLETED action");

  let query = `
    SELECT DISTINCT
      COALESCE(R.firstname, RH.firstname, 'Data Not Available') AS memberName,
      A.LoanAccountNumber AS loanAccountNumber,
      COALESCE(R.mobileNumber, RH.mobileNumber, 'Data Not Available') AS mobileNumber,
      COALESCE(R.branchName, RH.branchName, 'Data Not Available') AS branchName,
      A.AssignedToUserName AS assignedTo

    FROM Account_Assignments A

    LEFT JOIN Recovery_Raw_Data R
      ON R.loanAccountNumber = A.LoanAccountNumber

    LEFT JOIN (
      SELECT *,
             ROW_NUMBER() OVER (
               PARTITION BY loanAccountNumber
               ORDER BY uploadtimestamp DESC
             ) AS rn
      FROM Recovery_Raw_Data_history
    ) RH
      ON RH.loanAccountNumber = A.LoanAccountNumber
     AND RH.rn = 1

    INNER JOIN CallRecovery_Status CRS
      ON CRS.LoanAccountNumber = A.LoanAccountNumber

    WHERE A.AssignmentStatus = 'Assigned'
  `;

  // ================= ROLE RESTRICTIONS =================

  // 🔒 Branch Manager
  if (userInfo.Role === "Branch Manager") {
    query += ` AND COALESCE(R.branchName, RH.branchName) = @userBranch`;
  }

  // 🔒 Regional Manager
  if (userInfo.Role?.startsWith("Regional Manager")) {
    query += `
      AND COALESCE(R.branchName, RH.branchName) IN (
        SELECT branch_name
        FROM Branch_Cluster_Master
        WHERE cluster_name = @clusterRestriction
      )
    `;
  }

  // ================= FILTERS =================

  if (mobileNumber) {
    query += ` AND COALESCE(R.mobileNumber, RH.mobileNumber) = @mobileNumber`;
  }

  if (pincode) {
    query += ` AND R.pincode = @pincode`;
  }

  if (branchName) {
    query += ` AND COALESCE(R.branchName, RH.branchName) = @branchName`;
  }

  if (product) {
    query += ` AND R.product = @product`;
  }

  if (loanAccount) {
    query += ` AND A.LoanAccountNumber = @loanAccount`;
  }

  if (memberName) {
    query += ` AND COALESCE(R.firstname, RH.firstname) LIKE '%' + @memberName + '%'`;
  }

  if (assignedTo) {
    query += ` AND A.AssignedToUserId = @assignedTo`;
  }

  if (cluster && cluster !== "Corporate Office") {
    query += `
      AND COALESCE(R.branchName, RH.branchName) IN (
        SELECT branch_name
        FROM Branch_Cluster_Master
        WHERE cluster_name = @cluster
      )
    `;
  }

  // ================= QUEUE FILTER =================

  if (queue === "NPA") {
    query += ` AND R.dpdQueue >= '04'`;
  } 
  else if (queue === "Marketing") {
    query += ` AND R.QueueType = 'Marketing'`;
  } 
  else if (queue === "Welcome Call") {
    query += ` AND R.QueueType = 'Welcome Call'`;
  }

  // ================= DPD FILTER =================

  if (dpdQueue === "0-30") {
    query += ` AND R.dpdQueue = '01'`;
  } 
  else if (dpdQueue === "31-60") {
    query += ` AND R.dpdQueue = '02'`;
  } 
  else if (dpdQueue === "61-90") {
    query += ` AND R.dpdQueue = '03'`;
  } 
  else if (dpdQueue === "90+") {
    query += ` AND R.dpdQueue >= '04'`;
  }

  // ================= COMPLETED CONDITION =================

  query += `
    AND (
      ISNULL(CRS.CompleteFlag,0) = 1
      OR ISNULL(CRS.Submitted,0) = 1
    )
  `;

  // ================= FINAL EXECUTION =================

  const completedRequest = pool.request();

  // 🔁 ADD INPUTS ONLY ONCE
  if (mobileNumber) completedRequest.input("mobileNumber", mobileNumber);
  if (pincode) completedRequest.input("pincode", pincode);
  if (branchName) completedRequest.input("branchName", branchName);
  if (product) completedRequest.input("product", product);
  if (loanAccount) completedRequest.input("loanAccount", loanAccount);
  if (memberName) completedRequest.input("memberName", memberName);
  if (assignedTo) completedRequest.input("assignedTo", assignedTo);

  if (cluster && cluster !== "Corporate Office") {
    completedRequest.input("cluster", cluster);
  }

  if (userInfo.Role === "Branch Manager") {
    completedRequest.input("userBranch", userInfo.BranchName);
  }

  if (userInfo.Role?.startsWith("Regional Manager")) {
    completedRequest.input("clusterRestriction", userInfo.ClusterName);
  }

  const result = await completedRequest.query(query);

  return res.json(result.recordset);
}
 
 
// ======================================================
// 4️⃣ RE-ACTIVATE (Update Only - No Delete)
// ======================================================
if (actionType === "reactivate") {

  if (!selectedIds || selectedIds.length === 0) {
    return res.status(400).json({ message: "No accounts selected" });
  }

  for (const loanAccount of selectedIds) {
    logInfo("Reactivating account", loanAccount);

    // ✅ Update CallRecovery_Status (Update Only Existing Timestamp Column)
await pool.request()
  .input("loanAccountNumber", loanAccount)
  .query(`
    UPDATE CallRecovery_Status
    SET
      ScheduleCallTimestamp =
        CASE
          WHEN ScheduleCallTimestamp IS NOT NULL
          THEN GETDATE()
          ELSE ScheduleCallTimestamp
        END,

      ScheduleVisitTimestamp =
        CASE
          WHEN ScheduleVisitTimestamp IS NOT NULL
          THEN GETDATE()
          ELSE ScheduleVisitTimestamp
        END,

      PendingFlag = 1,
      InProcessFlag = 0,
      CompleteFlag = 0,
      Submitted = 0,
      UpdatedAt = GETDATE()

    WHERE LoanAccountNumber = @loanAccountNumber
  `);

    // ✅ Insert into History Table
    await pool.request()
      .input("loanAccountNumber", loanAccount)
      .query(`
        INSERT INTO CallRecovery_Status_History
        (
          LoanAccountNumber,
          ScheduleCallTimestamp,
          ScheduleVisitTimestamp,
          PendingFlag,
          InProcessFlag,
          CompleteFlag,
          Submitted,
          UpdatedTimeStamp
        )
        SELECT
          LoanAccountNumber,
          ScheduleCallTimestamp,
          ScheduleVisitTimestamp,
          PendingFlag,
          InProcessFlag,
          CompleteFlag,
          Submitted,
          GETDATE()
        FROM CallRecovery_Status
        WHERE LoanAccountNumber = @loanAccountNumber
      `);

    // ✅ Update Assignment
    await pool.request()
      .input("loanAccountNumber", loanAccount)
      .query(`
        UPDATE Account_Assignments
        SET
          WorkStatus = 'Reactivated',
          WorkUpdatedAt = GETDATE()
        WHERE LoanAccountNumber = @loanAccountNumber
      `);
  }

logSuccess("Reactivation completed");
  return res.json({ message: "Accounts reactivated successfully" });
}
    return res.status(400).json({ message: "Invalid actionType" });

  } catch (err) {
    logError("ACTIVITY STATUS ACTION ERROR", err);
    res.status(500).json({ message: "Server error" });
  }
});


// ======================================================
// 1️⃣ GET ROLES (POST METHOD - SEARCH + PAGINATION)
// ======================================================
app.post("/api/roles/list", async (req, res) => {

  const { name = "", page = 1, fetchAll = false } = req.body;

  const pageNumber = parseInt(page);
  const pageSize = 15;
  const offset = (pageNumber - 1) * pageSize;

  try {
    const pool = await poolPromise;

    // ==================================================
    // 🔹 FETCH ALL (Used for Select All Across Pages)
    // ==================================================
    if (fetchAll === true) {

      const allResult = await pool.request()
        .input("name", sql.VarChar, `%${name}%`)
        .query(`
          SELECT RoleId
          FROM smart_call.dbo.Roles
          WHERE (@name = '%%' OR RoleName LIKE @name)
          ORDER BY RoleId ASC
        `);

      return res.status(200).json({
        records: allResult.recordset
      });
    }

    // ==================================================
    // 🔹 NORMAL PAGINATION FETCH
    // ==================================================
    const result = await pool.request()
      .input("name", sql.VarChar, `%${name}%`)
      .input("offset", sql.Int, offset)
      .input("pageSize", sql.Int, pageSize)
      .query(`
        SELECT 
          RoleId,
          RoleName,
          ValidFrom,
          ValidTo,
          CreatedAt
        FROM smart_call.dbo.Roles
        WHERE (@name = '%%' OR RoleName LIKE @name)
        ORDER BY RoleId ASC
        OFFSET @offset ROWS
        FETCH NEXT @pageSize ROWS ONLY
      `);

    // 🔹 Total Count
    const countResult = await pool.request()
      .input("name", sql.VarChar, `%${name}%`)
      .query(`
        SELECT COUNT(*) AS total
        FROM smart_call.dbo.Roles
        WHERE (@name = '%%' OR RoleName LIKE @name)
      `);

    res.status(200).json({
      records: result.recordset,
      total: countResult.recordset[0].total,
      page: pageNumber,
      pageSize
    });

  } catch (err) {
    console.error("❌ LIST ROLES ERROR:", err);
    res.status(500).json({ message: "Failed to fetch roles" });
  }
});



// ======================================================
// 2️⃣ ADD ROLE
// ======================================================
app.post("/api/roles", async (req, res) => {

  const { roleName, validFrom, validTo } = req.body;

  if (!roleName || roleName.trim() === "") {
    return res.status(400).json({ message: "Role name is required" });
  }

  try {
    const pool = await poolPromise;

    // 🔹 Duplicate Check
    const exists = await pool.request()
      .input("roleName", sql.VarChar, roleName.trim())
      .query(`
        SELECT COUNT(*) AS cnt
        FROM smart_call.dbo.Roles
        WHERE RoleName = @roleName
      `);

    if (exists.recordset[0].cnt > 0) {
      return res.status(409).json({ message: "Role already exists" });
    }

    // 🔹 Insert Role
    await pool.request()
      .input("roleName", sql.VarChar, roleName.trim())
      .input("validFrom", sql.Date, validFrom || null)
      .input("validTo", sql.Date, validTo || null)
      .query(`
        INSERT INTO smart_call.dbo.Roles
        (
          RoleName,
          ValidFrom,
          ValidTo,
          CreatedAt
        )
        VALUES
        (
          @roleName,
          @validFrom,
          @validTo,
          GETDATE()
        )
      `);

    res.status(201).json({ message: "Role added successfully" });

  } catch (err) {
    console.error("❌ ADD ROLE ERROR:", err);
    res.status(500).json({ message: "Failed to add role" });
  }
});



// ======================================================
// 3️⃣ DELETE ROLES (MULTIPLE DELETE)
// ======================================================
app.post("/api/roles/delete", async (req, res) => {

  const { ids } = req.body;

  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ message: "No roles selected" });
  }

  try {
    const pool = await poolPromise;
    const request = pool.request();

    ids.forEach((id, index) => {
      request.input(`id${index}`, sql.Int, id);
    });

    await request.query(`
      DELETE FROM smart_call.dbo.Roles
      WHERE RoleId IN (${ids.map((_, i) => `@id${i}`).join(",")})
    `);

    res.status(200).json({ message: "Roles deleted successfully" });

  } catch (err) {
    console.error("❌ DELETE ROLE ERROR:", err);
    res.status(500).json({ message: "Failed to delete roles" });
  }
});

// ======================================================
// 4️⃣ UPDATE ROLE
// ======================================================
app.put("/api/roles/:id", async (req, res) => {

  const { id } = req.params;
  const { roleName, validFrom, validTo } = req.body;

  if (!roleName || roleName.trim() === "") {
    return res.status(400).json({ message: "Role name is required" });
  }

  try {
    const pool = await poolPromise;

    await pool.request()
      .input("id", sql.Int, id)
      .input("roleName", sql.VarChar, roleName.trim())
      .input("validFrom", sql.Date, validFrom || null)
      .input("validTo", sql.Date, validTo || null)
      .query(`
        UPDATE smart_call.dbo.Roles
        SET
          RoleName = @roleName,
          ValidFrom = @validFrom,
          ValidTo = @validTo
        WHERE RoleId = @id
      `);

    res.status(200).json({ message: "Role updated successfully" });

  } catch (err) {
    console.error("❌ UPDATE ROLE ERROR:", err);
    res.status(500).json({ message: "Failed to update role" });
  }
});

// ======================
// ROLES - POST
// ======================
app.post("/api/roles/list", async (req, res) => {
  try {
    const pool = await poolPromise;

    const result = await pool.request().query(`
      SELECT 
        RoleId,
        RoleName,
        ValidFrom,
        ValidTo,
        CreatedAt
      FROM Roles
      WHERE (ValidTo IS NULL OR ValidTo >= GETDATE())
      ORDER BY RoleName ASC
    `);

    res.json({
      records: result.recordset
    });

  } catch (err) {
    console.error("GET ROLES ERROR:", err);
    res.status(500).json({ message: "Failed to fetch roles" });
  }
});

// ===============================
// GET BRANCHES (WITH FILTER + ORDER)
// ===============================

app.get("/api/branch-master", async (req, res) => {
  try {
    const pool = await poolPromise;

    const { name, code } = req.query;

    let query = `
  SELECT 
    BranchCode AS branchCode,
    BranchName AS branchName,
    BranchEmailId AS branchEmailId,
    Status AS status,
    BranchCategory AS branchCategory,
    BranchType AS branchType,
    ParentBranch AS parentBranch,
    Address AS address,
    Pincode AS pincode,
    TimeStamp AS timeStamp,
    Location AS location
  FROM smart_call.dbo.Branches
  WHERE 1 = 1
`;

    if (name) {
      query += ` AND BranchName LIKE '%' + @BranchName + '%' `;
    }

    if (code) {
      query += ` AND BranchCode LIKE '%' + @BranchCode + '%' `;
    }

    query += ` ORDER BY BranchCode ASC `;   // 🔥 THIS FIXES JUMBLING

    const request = pool.request();

    if (name)
      request.input("BranchName", sql.VarChar, name);

    if (code)
      request.input("BranchCode", sql.VarChar, code);

    const result = await request.query(query);

    res.json(result.recordset);

  } catch (err) {
    console.error("GET ERROR:", err);
    res.status(500).json({ message: "Fetch failed" });
  }
});

// ===============================
// ADD BRANCH
// ===============================

app.post("/api/branch-master", async (req, res) => {
  try {
    const pool = await poolPromise;

    const {
      BranchCode,
      BranchName,
      BranchEmailId,
      BranchCategory,
      BranchType,
      ParentBranch,
      Address,
      Pincode,
      Status,
      Location
    } = req.body;

    // Duplicate Check
    const exists = await pool.request()
      .input("BranchCode", sql.VarChar, BranchCode)
      .query(`
        SELECT COUNT(*) AS cnt
        FROM smart_call.dbo.Branches
        WHERE BranchCode = @BranchCode
      `);

    if (exists.recordset[0].cnt > 0) {
      return res.status(409).json({ message: "Branch Code already exists" });
    }

    await pool.request()
      .input("BranchCode", sql.VarChar, BranchCode)
      .input("BranchName", sql.VarChar, BranchName)
      .input("BranchEmailId", sql.VarChar, BranchEmailId)
      .input("BranchCategory", sql.VarChar, BranchCategory)
      .input("BranchType", sql.VarChar, BranchType)
      .input("ParentBranch", sql.VarChar, ParentBranch)
      .input("Address", sql.VarChar, Address)
      .input("Pincode", sql.VarChar, Pincode)
      .input("Status", sql.Bit, Status ?? 1)
      .input("Location", sql.VarChar, Location)
      .query(`
        INSERT INTO smart_call.dbo.Branches
        (BranchCode, BranchName, BranchEmailId, BranchCategory,
         BranchType, ParentBranch, Address, Pincode, Status, Location)
        VALUES
        (@BranchCode, @BranchName, @BranchEmailId, @BranchCategory,
         @BranchType, @ParentBranch, @Address, @Pincode, @Status, @Location)
      `);

    res.status(201).json({
      branchCode: BranchCode,
      branchName: BranchName,
      branchEmailId: BranchEmailId,
      branchCategory: BranchCategory,
      branchType: BranchType,
      parentBranch: ParentBranch,
      address: Address,
      pincode: Pincode,
      status: 1,
      location: Location
    });

  } catch (err) {
    console.error("INSERT ERROR:", err);
    res.status(500).json({ message: "Insert failed" });
  }
});

// ===============================
// UPDATE BRANCH
// ===============================

app.put("/api/branch-master/:code", async (req, res) => {
  try {
    const pool = await poolPromise;
    const branchCode = req.params.code;

    const {
      BranchName,
      BranchEmailId,
      BranchCategory,
      BranchType,
      ParentBranch,
      Address,
      Pincode,
      Location
    } = req.body;

    await pool.request()
      .input("BranchCode", sql.VarChar, branchCode)
      .input("BranchName", sql.VarChar, BranchName)
      .input("BranchEmailId", sql.VarChar, BranchEmailId)
      .input("BranchCategory", sql.VarChar, BranchCategory)
      .input("BranchType", sql.VarChar, BranchType)
      .input("ParentBranch", sql.VarChar, ParentBranch)
      .input("Address", sql.VarChar, Address)
      .input("Pincode", sql.VarChar, Pincode)
      .input("Location", sql.VarChar, Location)
      .query(`
        UPDATE smart_call.dbo.Branches
        SET BranchName = @BranchName,
            BranchEmailId = @BranchEmailId,
            BranchCategory = @BranchCategory,
            BranchType = @BranchType,
            ParentBranch = @ParentBranch,
            Address = @Address,
            Pincode = @Pincode,
            Location = @Location,
			TimeStamp = GETDATE()
        WHERE BranchCode = @BranchCode
      `);

    res.json({ message: "Branch updated successfully" });

  } catch (err) {
    console.error("UPDATE ERROR:", err);
    res.status(500).json({ message: "Update failed" });
  }
});

// ===============================
// DELETE BRANCH
// ===============================

app.delete("/api/branch-master/:code", async (req, res) => {
  try {
    const pool = await poolPromise;
    const branchCode = req.params.code;

    await pool.request()
      .input("BranchCode", sql.VarChar, branchCode)
      .query(`
        DELETE FROM smart_call.dbo.Branches
        WHERE BranchCode = @BranchCode
      `);

    res.json({ message: "Branch deleted successfully" });

  } catch (err) {
    console.error("DELETE ERROR:", err);
    res.status(500).json({ message: "Delete failed" });
  }
});


/* ======================================================
   GET PRODUCT MASTER (WITH FILTER + ORDER)
====================================================== */
app.get("/api/product-master", async (req, res) => {
  try {
    const pool = await poolPromise;
    const { name, code } = req.query;

    let query = `
      SELECT
        SNo,
        ProductCategory,
        ProductType,
        ProductCode,
        ProductName,
        MaxTenure,
        MinTenure,
        MaxLimit,
        MinLimit,
        ValidFrom,
        ValidTo,
        Status
      FROM smart_call.dbo.ProductMaster
      WHERE 1 = 1
    `;

    const request = pool.request();

    if (name) {
      query += " AND ProductName LIKE @name";
      request.input("name", `%${name}%`);
    }

    if (code) {
      query += " AND ProductCode LIKE @code";
      request.input("code", `%${code}%`);
    }

    query += " ORDER BY ProductCode ASC";

    const result = await request.query(query);

    res.json(result.recordset);

  } catch (err) {
    console.error("GET PRODUCT MASTER ERROR:", err);
    res.status(500).json({ message: "Error fetching product master" });
  }
});



/* ======================================================
   ADD PRODUCT MASTER (POST)
====================================================== */
app.post("/api/product-master", async (req, res) => {
  try {
    const pool = await poolPromise;

    const {
      productCategory,
      productType,
      productCode,
      productName,
      maxTenure,
      minTenure,
      maxLimit,
      minLimit,
      validFrom,
      validTo
    } = req.body;

    // 🔎 Duplicate Check
    const exists = await pool.request()
      .input("ProductCode", productCode)
      .query(`
        SELECT COUNT(*) AS cnt
        FROM smart_call.dbo.ProductMaster
        WHERE ProductCode = @ProductCode
      `);

    if (exists.recordset[0].cnt > 0) {
      return res.status(409).json({ message: "Product Code already exists" });
    }

    await pool.request()
      .input("ProductCategory", productCategory)
      .input("ProductType", productType || "")
      .input("ProductCode", productCode)
      .input("ProductName", productName)
      .input("MaxTenure", maxTenure || 0)
      .input("MinTenure", minTenure || 0)
      .input("MaxLimit", maxLimit || 0)
      .input("MinLimit", minLimit || 0)
      .input("ValidFrom", validFrom || null)
      .input("ValidTo", validTo || null)
      .input("Status", "Active")
      .query(`
        INSERT INTO smart_call.dbo.ProductMaster
        (
          ProductCategory,
          ProductType,
          ProductCode,
          ProductName,
          MaxTenure,
          MinTenure,
          MaxLimit,
          MinLimit,
          ValidFrom,
          ValidTo,
          Status,
          Timestamp
        )
        VALUES
        (
          @ProductCategory,
          @ProductType,
          @ProductCode,
          @ProductName,
          @MaxTenure,
          @MinTenure,
          @MaxLimit,
          @MinLimit,
          @ValidFrom,
          @ValidTo,
          @Status,
          GETDATE()
        )
      `);

    res.status(201).json({ message: "Product added successfully" });

  } catch (err) {
    console.error("POST PRODUCT MASTER ERROR:", err);
    res.status(500).json({ message: "Error adding product master" });
  }
});



/* ======================================================
   UPDATE PRODUCT MASTER (USING ProductCode)
====================================================== */
app.put("/api/product-master/:code", async (req, res) => {
  try {
    const pool = await poolPromise;
    const productCode = req.params.code;

    const {
      productCategory,
      productType,
      productName,
      maxTenure,
      minTenure,
      maxLimit,
      minLimit,
      validFrom,
      validTo
    } = req.body;

    await pool.request()
      .input("ProductCode", productCode) // old code
.input("NewProductCode", req.body.productCode)
      .input("ProductCategory", productCategory)
      .input("ProductType", productType || "")
      .input("ProductName", productName)
      .input("MaxTenure", maxTenure || 0)
      .input("MinTenure", minTenure || 0)
      .input("MaxLimit", maxLimit || 0)
      .input("MinLimit", minLimit || 0)
      .input("ValidFrom", validFrom || null)
      .input("ValidTo", validTo || null)
      .query(`
        UPDATE smart_call.dbo.ProductMaster
SET
  ProductCategory = @ProductCategory,
  ProductType = @ProductType,
  ProductCode = @NewProductCode,
  ProductName = @ProductName,
  MaxTenure = @MaxTenure,
  MinTenure = @MinTenure,
  MaxLimit = @MaxLimit,
  MinLimit = @MinLimit,
  ValidFrom = @ValidFrom,
  ValidTo = @ValidTo,
  Timestamp = GETDATE()
WHERE ProductCode = @ProductCode
      `);

    res.json({ message: "Product updated successfully" });

  } catch (err) {
    console.error("UPDATE PRODUCT MASTER ERROR:", err);
    res.status(500).json({ message: "Error updating product master" });
  }
});



/* ======================================================
   DELETE PRODUCT MASTER (USING ProductCode)
====================================================== */
app.delete("/api/product-master/:code", async (req, res) => {
  try {
    const pool = await poolPromise;
    const productCode = req.params.code;

    await pool.request()
      .input("ProductCode", productCode)
      .query(`
        DELETE FROM smart_call.dbo.ProductMaster
        WHERE ProductCode = @ProductCode
      `);

    res.json({ message: "Product deleted successfully" });

  } catch (err) {
    console.error("DELETE PRODUCT MASTER ERROR:", err);
    res.status(500).json({ message: "Error deleting product master" });
  }
});

//=============== FRONTEND LOGGING ========================
app.post("/api/frontend-log", (req, res) => {
  try {
    const writeDailyLog = require("./logger");

    const { source, message, data } = req.body;

    if (!source || !message) {
      return res.status(400).json({ success: false });
    }

    const logMessage =
      message + (data ? " " + JSON.stringify(data) : "");

    writeDailyLog(`frontend/${source}`, logMessage);

    res.json({ success: true });

  } catch (err) {
    console.error("❌ FRONTEND LOG ERROR:", err);
    res.status(500).json({ success: false });
  }
});

//=============== Failure LOGGING ========================
app.post("/api/log/client-failure", (req, res) => {

  const { type, message, userId, userName, extra } = req.body;

  writeDailyLog(
    "client_failures",
    `${type} | userId=${userId} | userName=${userName} | message=${message} | extra=${JSON.stringify(extra || {})}`
  );

  res.json({ success: true });
});
// ======================
// START SERVER
// ======================
//app.listen(PORT, "0.0.0.0", () => {
  //console.log(`🚀 Backend running on port ${PORT}`);
//});
https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`🚀 HTTPS Server running on port ${PORT}`);
});
