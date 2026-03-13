process.on("uncaughtException", err => {
  console.error("UNCAUGHT EXCEPTION:", err);
});

process.on("unhandledRejection", err => {
  console.error("UNHANDLED REJECTION:", err);
});

const express = require("express");
const sql = require("mssql");
const cors = require("cors");

const app = express();
const PORT = 5001;
const axios = require("axios");

const GOOGLE_API_KEY = "AIzaSyBU8cG2UuNw7i-6m7azb1cUIiNgX0DJ4KA";

async function getRoadDistanceKm(startLat, startLng, stopLat, stopLng) {
  try {
    const response = await axios.get(
      "https://maps.googleapis.com/maps/api/directions/json",
      {
        params: {
          origin: `${startLat},${startLng}`,
          destination: `${stopLat},${stopLng}`,
key: GOOGLE_API_KEY,        
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
  },
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
  const { userId, password, mpin, securityQ, securityA, deviceId } = req.body;

  try {
    if (!userId || !password || !mpin || !securityQ || !securityA || !deviceId) {
      return res.status(400).json({ message: "All fields are mandatory" });
    }

    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,8}$/;

    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        message:
          "Password must be 6–8 characters with uppercase, lowercase, number and special character",
      });
    }

    if (!/^\d{4}$/.test(String(mpin))) {
      return res.status(400).json({
        message: "MPIN must be exactly 4 numeric digits",
      });
    }

    const pool = await poolPromise;

    // ✅ check authorized user in UsersInfo
    const userCheck = await pool
      .request()
      .input("UserId", sql.VarChar(50), String(userId).trim())
      .query(`
        SELECT UserId
        FROM UsersInfo
        WHERE UserId = @UserId
      `);

    if (userCheck.recordset.length === 0) {
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

    if (authCheck.recordset.length > 0) {
      return res.status(409).json({
        message: "User already registered. Please login.",
      });
    }

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

    return res.status(200).json({ message: "Registration successful" });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});
// =======================================================
// ✅ LOGIN (UserId + MPIN + DEVICE) ✅ FINAL BEST VERSION
// =======================================================
app.post("/login", async (req, res) => {
  const { mpin, deviceId } = req.body;

  try {
    if (!mpin || !deviceId) {
      return res.status(400).json({ message: "MPIN and Device ID are required" });
    }

    const cleanMPIN = String(mpin).trim();
    const cleanDeviceId = String(deviceId).trim();

    if (!/^\d{4}$/.test(cleanMPIN)) {
      return res.status(400).json({ message: "MPIN must be exactly 4 digits" });
    }

    const pool = await poolPromise;

    console.log("📌 LOGIN INPUT:", { cleanMPIN, cleanDeviceId });

    // ✅ Find user by MPIN
    const mpinUser = await pool.request()
      .input("AppMPIN", sql.VarChar(10), cleanMPIN)
      .query(`
        SELECT TOP 1 UserId, DeviceId
        FROM UserAuth
        WHERE AppMPIN = @AppMPIN
      `);

    if (mpinUser.recordset.length === 0) {
      return res.status(401).json({ message: "Invalid MPIN" });
    }

    const dbUser = mpinUser.recordset[0];

    // ✅ If device mismatch → auto rebind to current deviceId
    if (String(dbUser.DeviceId).trim() !== cleanDeviceId) {
      console.log("⚠️ Device mismatch → rebinding device to this MPIN user");

      await pool.request()
        .input("UserId", sql.VarChar(50), dbUser.UserId)
        .input("DeviceId", sql.VarChar(200), cleanDeviceId)
        .query(`
          UPDATE UserAuth
          SET DeviceId = @DeviceId
          WHERE UserId = @UserId
        `);
    }

    // ✅ Now fetch full profile
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

    // ✅ Update last login time
    await pool.request()
      .input("UserId", sql.VarChar(50), dbUser.UserId)
      .query(`
        UPDATE UserAuth
        SET LastLoginAt = GETDATE()
        WHERE UserId = @UserId
      `);
console.log("📤 LOGIN RESPONSE:", result);

    return res.status(200).json({
      message: "Login successful",
      user: result.recordset[0],
    });

  } catch (err) {
    console.error("❌ LOGIN ERROR:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

//============================================================================================
//                                DPD LIST (DATABASE CONNECTED)
//============================================================================================
app.post("/api/dpd-list", async (req, res) => {
  const { dpdQueue, userId } = req.body;

  if (!dpdQueue || !userId) {
    return res.status(400).json({
      message: "dpdQueue and userId are required",
    });
  }

  const dpdList = dpdQueue.split(",").map((d) => d.trim());

  try {
    const pool = await poolPromise;
    const request = pool.request();

    // force string userId
    request.input("userId", sql.VarChar(50), String(userId));

    dpdList.forEach((dpd, index) => {
      request.input(`dpd${index}`, sql.VarChar(2), dpd);
    });

    const placeholders = dpdList
      .map((_, index) => `@dpd${index}`)
      .join(",");

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
        AND RIGHT('00' + R.dpdQueue, 2) IN (${placeholders})

      ORDER BY TRY_CAST(R.currentOutstandingBalance AS DECIMAL(18,2)) DESC
    `;

    const result = await request.query(query);

    return res.json({ records: result.recordset });

  } catch (error) {
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

      A.AlternateNumber

    FROM dbo.Recovery_Raw_Data R
    LEFT JOIN dbo.Recovery_Alternate_Number A
      ON R.loanAccountNumber = A.LoanAccountNumber

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
// SAVE ALTERNATE NUMBER
// =======================================================
app.post("/api/account/save-alternate", async (req, res) => {
  const { loanAccountNumber, alternateNumber } = req.body;

  if (!loanAccountNumber || !alternateNumber) {
    return res.status(400).json({ message: "Loan account and alternate number required" });
  }

  if (!/^\d{10}$/.test(String(alternateNumber))) {
    return res.status(400).json({ message: "Alternate number must be 10 digits" });
  }

  try {
    const pool = await poolPromise;

await pool.request()
  .input("LoanAccountNumber", sql.VarChar(50), loanAccountNumber)
  .input("AlternateNumber", sql.VarChar(15), alternateNumber)
  .query(`
    IF EXISTS (SELECT 1 FROM dbo.Recovery_Alternate_Number 
               WHERE LoanAccountNumber = @LoanAccountNumber)
    BEGIN
        UPDATE dbo.Recovery_Alternate_Number
        SET AlternateNumber = @AlternateNumber,
            UpdatedAt = GETDATE()
        WHERE LoanAccountNumber = @LoanAccountNumber
    END
    ELSE
    BEGIN
        INSERT INTO dbo.Recovery_Alternate_Number
        (LoanAccountNumber, AlternateNumber)
        VALUES (@LoanAccountNumber, @AlternateNumber)
    END
  `);

    res.json({ success: true, message: "Alternate number saved successfully" });

  } catch (err) {
    console.error("SAVE ALTERNATE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
}); 

// =====================================================================
// HOME → MEMBERS SUMMARY (ASSIGNMENT BASED)
// =====================================================================
app.post("/api/home/members-summary", async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "userId is required" });
  }

  try {
    const pool = await poolPromise;

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

    return res.json({
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
    });

  } catch (err) {
    console.error("❌ MEMBERS SUMMARY ERROR:", err);
    return res.status(500).json({ message: "Failed to load members summary" });
  }
});
// =====================================================================
// NPA → DPD SUMMARY (ASSIGNED USER BASED)
// =====================================================================
app.post("/api/npa/dpd-summary", async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "userId is required" });
  }

  try {
    const pool = await poolPromise;

    const result = await pool.request()
      .input("userId", sql.VarChar(50), userId)
      .query(`
        SELECT
          SUM(CASE WHEN R.dpdQueue = '01' THEN 1 ELSE 0 END) AS d0_30,
          SUM(CASE WHEN R.dpdQueue = '02' THEN 1 ELSE 0 END) AS d31_60,
          SUM(CASE WHEN R.dpdQueue = '03' THEN 1 ELSE 0 END) AS d61_90,
          SUM(CASE WHEN R.dpdQueue IN ('04','05','06','07') THEN 1 ELSE 0 END) AS d90_plus
        FROM Account_Assignments A
        INNER JOIN Recovery_Raw_Data R
          ON A.LoanAccountNumber = R.loanAccountNumber
        WHERE
          A.AssignedToUserId = @userId
          AND A.AssignmentStatus = 'Assigned'
      `);

    const row = result.recordset[0] || {};

    return res.json({
      "0_30": row.d0_30 || 0,
      "31_60": row.d31_60 || 0,
      "61_90": row.d61_90 || 0,
      "90_plus": row.d90_plus || 0,
    });

  } catch (err) {
    console.error("❌ DPD SUMMARY ERROR:", err);
    res.status(500).json({ message: "Failed to load DPD summary" });
  }
});
// =====================================================================
// NPA → DPD SUMMARY V2 (Pending / InProcess / Completed from CallRecovery_Status)
// =====================================================================
app.post("/api/npa/dpd-summary-v2", async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "userId is required" });
  }

  try {
    const pool = await poolPromise;

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
              THEN 1 ELSE 0 END) AS completed_90_plus

        FROM NPA_Assigned NA
        LEFT JOIN CallRecovery_Status CRS
          ON CRS.LoanAccountNumber = NA.LoanAccountNumber
         AND CRS.UserId = @UserId
      `);

    const row = result.recordset[0] || {};

    return res.json({
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
      },
    });

  } catch (err) {
    console.error("❌ NPA DPD SUMMARY V2 ERROR:", err);
    return res.status(500).json({ message: "Failed to load dpd summary v2" });
  }
});
// =====================================================================
// HOME → MEMBERS SUMMARY V4 (Correct Separation)
// NPA & Welcome → Recovery Tables
// Marketing → Leads_Data Table
// =====================================================================
app.post("/api/home/members-summary-v3", async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "userId required" });
  }

  try {
    const pool = await poolPromise;

    // =====================================================
    // 1️⃣ RECOVERY SUMMARY (NPA + WELCOME)
    // =====================================================
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
              THEN 1 ELSE 0 END) AS welcome_completed

        FROM Assigned A
        LEFT JOIN CallRecovery_Status CRS
          ON CRS.LoanAccountNumber = A.LoanAccountNumber
         AND CRS.UserId = @UserId
      `);

    const r = recoveryResult.recordset[0] || {};

    // =====================================================
    // 2️⃣ MARKETING SUMMARY (From Leads_Data)
    // =====================================================
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

    // =====================================================
    // FINAL RESPONSE
    // =====================================================
    return res.json({
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
    });

  } catch (err) {
    console.error("❌ members-summary error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});
// =====================================================================
// UPDATE ACCOUNT STATUS → IN PROCESS (WHEN USER SCHEDULES CALL / VISIT)
// =====================================================================
app.post("/api/account/progress/inprocess", async (req, res) => {
  const { loanAccountNumber, userId, activityType } = req.body;

  if (!loanAccountNumber || !userId || !activityType) {
    return res.status(400).json({
      message: "loanAccountNumber, userId, activityType are required",
    });
  }

  try {
    const pool = await poolPromise;

    // ✅ update assignment status to InProcess
    await pool.request()
      .input("loanAccountNumber", sql.VarChar(50), loanAccountNumber)
      .input("userId", sql.VarChar(50), userId)
      .query(`
        UPDATE Account_Assignments
        SET WorkStatus = 'InProcess',
            WorkUpdatedAt = GETDATE()
        WHERE LoanAccountNumber = @loanAccountNumber
          AND AssignedToUserId = @userId
          AND AssignmentStatus = 'Assigned'
      `);

    return res.json({
      success: true,
      message: "Moved to In-Process successfully",
    });

  } catch (err) {
    console.error("❌ INPROCESS UPDATE ERROR:", err);
    return res.status(500).json({ message: "Failed to update status" });
  }
});

// =====================================================================
// HOME → SCHEDULE FOR THE DAY (Call + Pending)
// =====================================================================
// =====================================================================
// HOME → SCHEDULE FOR THE DAY SUMMARY (CALL + VISIT)
// ✅ Pending = scheduled date <= today (carry forward)
// ✅ Completed = ONLY completed today (UpdatedAt = today)
// =====================================================================
app.post("/api/home/schedule-summary", async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "userId is required" });
  }

  try {
    const pool = await poolPromise;

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
    console.error("❌ Schedule summary error:", err);
    return res.status(500).json({ message: "Failed to load schedule summary" });
  }
});


// =====================================================================
// HOME → SCHEDULE FOR THE DAY → TODAY + PAST (CALL / VISIT)
// =====================================================================
app.post("/api/home/schedule-today-list", async (req, res) => {
  const { userId, type } = req.body; // type = "CALL" or "VISIT"

  if (!userId || !type) {
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

    const result = await pool
      .request()
      .input("UserId", sql.VarChar(50), String(userId))
      .query(query);

    return res.json({
      type,
      records: result.recordset || [],
    });

  } catch (err) {
    console.error("❌ schedule-today-list error:", err);
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
  const {
    userId,
    userName,
    accountNo,
    customerName,

    startLat,
    startLng,
    startAddress,

    customerLat,
    customerLng,
    customerAddress
  } = req.body;

  // ===============================
  // VALIDATION
  // ===============================
if (
  !userId ||
  !userName ||
  !accountNo ||
  !customerName ||
  startLat === undefined ||
  startLng === undefined ||
  !startAddress ||
  customerLat === undefined ||
  customerLng === undefined ||
  !customerAddress
)
{
    return res.status(400).json({ message: "Missing required fields" });
  }

  try {
    const pool = await poolPromise;

    // ============================================
    // STEP 1 — GET BRANCH LAT/LNG FROM USER
    // UsersInfo → BranchCode → Branch_GPS
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
    // STEP 2 — INSERT INTO FieldVisitReport
    // ============================================
    const insertResult = await pool.request()
      .input("UserID", sql.VarChar(50), userId)
      .input("UserName", sql.VarChar(100), userName)
      .input("AccountNo", sql.VarChar(50), accountNo)
      .input("CustomerName", sql.VarChar(150), customerName)

      .input("BranchLatitude", sql.Decimal(18, 10), branchLat)
      .input("BranchLongitude", sql.Decimal(18, 10), branchLng)

      .input("StartLatitude", sql.Decimal(18, 10), startLat)
      .input("StartLongitude", sql.Decimal(18, 10), startLng)
      .input("StartAddress", sql.NVarChar(500), startAddress)

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
      return res.status(400).json({
        success: false,
        message: "Mandatory fields missing"
      });
    }

    if (!["Deposits", "Loan"].includes(ProductCategory)) {
      return res.status(400).json({
        success: false,
        message: "Invalid Product Category"
      });
    }

    const pool = await poolPromise;

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
      return res.status(400).json({
        success: false,
        message: "Cluster not found for this BranchCode"
      });
    }

    const ClusterName = clusterResult.recordset[0].cluster_name;

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
    return res.json({
      success: true,
      message: "Lead saved successfully"
    });

  } catch (err) {

    console.log("SAVE LEAD ERROR:", err);

    return res.status(500).json({
      success: false,
      message: "Server error while saving lead"
    });

  }
});
// ================= GET LEADS FOR LOGGED USER =================
app.get("/api/getMyLeads/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    const pool = await poolPromise;

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

    res.json({
      success: true,
      leads: result.recordset
    });

  } catch (err) {
    console.log("GET LEADS ERROR", err);
    res.json({ success: false });
  }
});

// ================= GET FULL LEAD DETAILS BY SNo =================
app.get("/api/getLeadDetails/:sno", async (req, res) => {
  try {
    const { sno } = req.params;

    const pool = await poolPromise;

    const result = await pool.request()
      .input("SNo", sql.Int, sno)
      .query(`
        SELECT *
        FROM Leads_Data
        WHERE SNo = @SNo
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Lead not found"
      });
    }

    res.json({
      success: true,
      lead: result.recordset[0]
    });

  } catch (err) {
    console.log("GET LEAD DETAILS ERROR", err);
    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});
app.post("/api/activity/history", async (req, res) => {
  try {
    const { userId, fromDate, toDate, searchText, type } = req.body;

    if (!userId) {
      return res.status(400).json({ message: "userId required" });
    }

    const pool = await poolPromise;

    const result = await pool.request()
      .input("UserId", sql.VarChar(50), String(userId))
      .input("FromDate", sql.Date, fromDate || null)
      .input("ToDate", sql.Date, toDate || null)
      .input("SearchText", sql.VarChar(100), searchText || null)
      .input("Type", sql.VarChar(20), type || null)
      .query(`

        ;WITH LatestAction AS (
          SELECT
            s.SessionId,
            MAX(l.CreatedAt) AS LatestTime
          FROM smart_call.dbo.Activity_Sessions s
          INNER JOIN smart_call.dbo.Activity_Logs l
            ON s.SessionId = l.SessionId
          WHERE s.StartedByUserId = @UserId
            AND (
                (@FromDate IS NULL OR CAST(l.CreatedAt AS DATE) >= @FromDate)
                AND
                (@ToDate IS NULL OR CAST(l.CreatedAt AS DATE) <= @ToDate)
            )
            AND (
                @Type IS NULL
                OR @Type = 'BOTH'
                OR UPPER(ISNULL(s.SourceType,'NPA')) = UPPER(@Type)
            )
          GROUP BY s.SessionId
        )

        ----------------------
        -- NPA RECORDS
        ----------------------
        SELECT
          s.LoanAccountNumber,
          'NPA' AS SourceType,
          s.SessionType,
          r.firstname AS CustomerName,
          r.dpdQueue,
          l.ActionLabel,
          FORMAT(l.CreatedAt, 'dd/MM/yyyy hh:mm tt') AS FormattedTime,

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

        FROM LatestAction LA
        INNER JOIN smart_call.dbo.Activity_Sessions s
          ON s.SessionId = LA.SessionId
        INNER JOIN smart_call.dbo.Activity_Logs l
          ON l.SessionId = s.SessionId
         AND l.CreatedAt = LA.LatestTime
        INNER JOIN smart_call.dbo.Recovery_Raw_Data r
          ON r.loanAccountNumber = s.LoanAccountNumber
        LEFT JOIN smart_call.dbo.CallRecovery_Status cr
          ON cr.LoanAccountNumber = s.LoanAccountNumber
         AND cr.UserId = @UserId
        WHERE ISNULL(s.SourceType,'NPA') = 'NPA'
          AND (
              @SearchText IS NULL OR
              r.firstname LIKE '%' + @SearchText + '%' OR
              r.loanAccountNumber LIKE '%' + @SearchText + '%'
          )

        UNION ALL

        ----------------------
        -- LEAD RECORDS
        ----------------------
        SELECT
          s.LoanAccountNumber,
          'LEAD' AS SourceType,
          s.SessionType,
          ld.FullName AS CustomerName,
          NULL AS dpdQueue,
          l.ActionLabel,
          FORMAT(l.CreatedAt, 'dd/MM/yyyy hh:mm tt') AS FormattedTime,
          'PENDING' AS AccountStatus

        FROM LatestAction LA
        INNER JOIN smart_call.dbo.Activity_Sessions s
          ON s.SessionId = LA.SessionId
        INNER JOIN smart_call.dbo.Activity_Logs l
          ON l.SessionId = s.SessionId
         AND l.CreatedAt = LA.LatestTime
        INNER JOIN smart_call.dbo.Leads_Data ld
          ON ld.SNo = s.SourceId
        WHERE s.SourceType = 'LEAD'
          AND (
              @SearchText IS NULL OR
              ld.FullName LIKE '%' + @SearchText + '%' OR
              ld.MobileNumber LIKE '%' + @SearchText + '%'
          )

        ORDER BY FormattedTime DESC
      `);

    res.json({
      success: true,
      count: result.recordset.length,
      records: result.recordset
    });

  } catch (err) {
    console.error("History API Error:", err);
    res.status(500).json({ message: "History fetch failed" });
  }
});
// =========================================================
// ACTIVITY HISTORY DETAILS
// Returns ALL actions for one LoanAccountNumber
// Includes formatted schedule timestamps
// =========================================================

app.post("/api/activity/history-details", async (req, res) => {
  try {
    const { loanAccountNumber } = req.body;

    if (!loanAccountNumber) {
      return res.status(400).json({ message: "LoanAccountNumber required" });
    }

    const pool = await poolPromise;

    const result = await pool.request()
      .input("LoanAccountNumber", sql.VarChar(50), String(loanAccountNumber))
      .query(`
        SELECT
          s.SessionType,
          l.ActionLabel,

          -- 🔥 Main Action Time (Formatted)
          FORMAT(l.CreatedAt, 'dd/MM/yyyy hh:mm tt') AS FormattedTime,

          -- 🔥 Scheduled Call Time (Formatted)
          FORMAT(cr.ScheduleCallTimestamp, 'dd/MM/yyyy hh:mm tt') 
            AS FormattedCallSchedule,

          -- 🔥 Scheduled Visit Time (Formatted)
          FORMAT(cr.ScheduleVisitTimestamp, 'dd/MM/yyyy hh:mm tt') 
            AS FormattedVisitSchedule

        FROM smart_call.dbo.Activity_Sessions s
        INNER JOIN smart_call.dbo.Activity_Logs l
          ON s.SessionId = l.SessionId

        LEFT JOIN smart_call.dbo.CallRecovery_Status cr
          ON cr.LoanAccountNumber = s.LoanAccountNumber

        WHERE s.LoanAccountNumber = @LoanAccountNumber

        ORDER BY l.CreatedAt DESC
      `);

    res.json({ records: result.recordset });

  } catch (err) {
    console.error("History details error:", err);
    res.status(500).json({ message: "Details fetch failed" });
  }
});
//=============================RESET VISIT=====================================
app.post("/api/visit/reset", async (req, res) => {
  try {
    const { loanAccountNumber, userId } = req.body;

    const pool = await poolPromise;

    await pool.request()
      .input("LoanAccountNumber", sql.VarChar(50), loanAccountNumber)
      .input("UserId", sql.VarChar(50), userId)
      .query(`
        UPDATE CallRecovery_Status
        SET
          PendingFlag = 1,
          InProcessFlag = 0,
          CompleteFlag = 0,

          ScheduleVisitTimestamp = GETDATE(),   -- ⭐ IMPORTANT

          ScheduleVisitPendingFlag = 1,
          ScheduleVisitCompletedFlag = 0,

          UpdatedAt = GETDATE()

        WHERE LoanAccountNumber = @LoanAccountNumber
        AND UserId = @UserId
      `);

    res.json({ success: true });

  } catch (err) {
    console.error("Reset visit error:", err);
    res.status(500).json({ message: "Reset visit failed" });
  }
});

//============================================================================================
//                               APP SMA Report
//============================================================================================
app.get("/api/sma-report", async (req, res) => {
  try {

    const { cluster, branchCode, branchName, irac } = req.query;

    const pool = await poolPromise;

    // Cluster Name → Cluster Code mapping
    const clusterMap = {
      "Krishna": "KR",
      "Guntur": "GU",
      "West Godavari": "WG",
      "Visakhapatnam": "VS"
    };

    const clusterCode = clusterMap[cluster] || null;

    let query = `
      SELECT
        [SNo.],
        [Br Code],
        [Branch Name],
        [Cluster Code],
        [Account No.],
        [Account Name],
        [Account Type Description],
        [Limit],
        [Drawing Power],
        [Int Rate],
        [Theo Balance],
        [Cleared Balance],
        [Uncleared Balance],
        [Outstanding Balance],
        [Overdue],
        [Sanction Date],
        [Expiry Date],
        [EMIs Due],
        [EMIs Paid],
        [EMIs OD],
        [NEW IRAC],
        [OLD IRAC],
        [NPA Date],
        [Arrear Condition],
        [Arrear Description],
        [Loan Type],
        [Product Group]
      FROM smart_call.dbo.SMA_Report
      WHERE 1=1
    `;

    // Cluster filter
    if (clusterCode) {
      query += ` AND [Cluster Code] = '${clusterCode}'`;
    }

    // Branch Code filter (handles leading zeros like 00001)
    if (branchCode) {
      query += ` AND CAST([Br Code] AS INT) = ${parseInt(branchCode)}`;
    }

    // Branch Name filter
    if (branchName) {
      query += ` AND [Branch Name] LIKE '%${branchName}%'`;
    }

    // IRAC filter (handles values like 00,01,02 etc)
    if (irac) {
      query += ` AND CAST([NEW IRAC] AS INT) = ${parseInt(irac)}`;
    }

    const result = await pool.request().query(query);

    res.json(result.recordset);

  } catch (err) {

    console.error("SMA API Error:", err);
    res.status(500).send("Server Error");

  }
});
//============================================================================================
//                                BRANCH CALL
//============================================================================================
app.get("/api/branch-contacts", async (req,res)=>{

try{

const {branchCode} = req.query;

const pool = await poolPromise;

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

res.json(result.recordset);

}catch(err){

console.log("Branch contacts error:",err);

res.status(500).send("Server error");

}

});
//============================================================================================
//                                CUSTOMER CALL
//============================================================================================
app.get("/api/customer-contact", async (req,res)=>{

try{

const {accountNumber} = req.query;

const pool = await poolPromise;

const result = await pool.request()
.input("accountNumber",accountNumber)
.query(`
SELECT
firstname,
mobileNumber
FROM smart_call.dbo.Recovery_Raw_Data
WHERE loanAccountNumber = @accountNumber
`);

res.json(result.recordset);

}catch(err){

console.log("Customer contact error:",err);

res.status(500).send("Server error");

}

});

app.get("/api/customer-numbers", async (req,res)=>{

try{

const {accountNumber} = req.query;

const pool = await poolPromise;

const result = await pool.request()
.input("accountNumber",accountNumber)
.query(`

SELECT
MAX(R.mobileNumber) as mobileNumber,
MAX(A.AlternateNumber) as AlternateNumber

FROM smart_call.dbo.Recovery_Raw_Data R

FULL OUTER JOIN smart_call.dbo.Recovery_Alternate_Number A
ON R.loanAccountNumber = A.LoanAccountNumber

WHERE
R.loanAccountNumber = @accountNumber
OR
A.LoanAccountNumber = @accountNumber

`);

res.json(result.recordset);

}catch(err){

console.log("Customer numbers error:",err);
res.status(500).send("Server error");

}

});
//=========================SMA START========================================
app.post("/api/sma/session/start", async (req,res)=>{

try{

const {
loanAccountNumber,
userId,
userName,
sourceType,
sourceId
} = req.body;

const pool = await poolPromise;

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

res.json({sessionId: result.recordset[0].SessionId});

}catch(err){

console.log("SMA session start error:",err);
res.status(500).send("Server error");

}

});

//======================================SMA ACTIVITY===========================================
//======================================SMA ACTIVITY===========================================
app.post("/api/sma/log", async (req,res)=>{

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

const pool = await poolPromise;

const metadataJson = metadata ? JSON.stringify(metadata) : null;


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

}

//===========================================================

res.json({logId});

}catch(err){

console.log("SMA log error:",err);
res.status(500).send("Server error");

}

});

//======================================SMA END==================================
app.post("/api/sma/session/end", async (req,res)=>{

try{

const {sessionId} = req.body;

const pool = await poolPromise;

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

res.json({success:true});

}catch(err){

console.log("SMA end session error:",err);
res.status(500).send("Server error");

}

});
//=========================== LEAD STATUS =======================================================================
app.get("/api/leads/status/:userId", async (req,res)=>{

try{

const {userId} = req.params;

const pool = await poolPromise;

const result = await pool.request()
.input("UserId",sql.VarChar,userId)

.query(`

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

`);

res.json(result.recordset);

}catch(err){

console.log(err);
res.status(500).send("Server error");

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
  const { records } = req.body;

  if (!records || !Array.isArray(records)) {
    return res.status(400).json({ message: "Invalid JSON format" });
  }

  try {
    const pool = await poolPromise;
	
	const userId = req.headers["x-user-id"];

if (!userId) {
  return res.status(401).json({ message: "Unauthorized" });
}

// Fetch user role from DB
const roleResult = await pool.request()
  .input("userId", sql.VarChar(50), userId)
  .query(`
    SELECT Role 
    FROM UsersInfo
    WHERE UserId = @userId
  `);

if (!roleResult.recordset.length) {
  return res.status(403).json({ message: "User not found" });
}

const userRole = roleResult.recordset[0].Role;

if (
  userRole === "Branch Manager" ||
  userRole.startsWith("Regional Manager")
) {
  return res.status(403).json({
    message: "Access Denied. Please Contact Admin."
  });
}

    const todayCount = records.length;

    // ------------------------------------------------------------------
    // STEP 1 — Get yesterday upload count (from log table)
    // ------------------------------------------------------------------
    const yesterdayRes = await pool.request().query(`
      SELECT TOP 1 record_count
      FROM Recovery_Upload_Log
      WHERE upload_date < CAST(GETDATE() AS DATE)
      ORDER BY upload_date DESC
    `);

    const yesterdayCount = yesterdayRes.recordset.length
      ? yesterdayRes.recordset[0].record_count
      : 0;

    // ------------------------------------------------------------------
    // STEP 2 — Backup current active data (HISTORY = BACKUP ONLY)
    // ------------------------------------------------------------------
    const oldCountRes = await pool.request()
      .query(`SELECT COUNT(*) AS cnt FROM Recovery_Raw_Data`);

    if (oldCountRes.recordset[0].cnt > 0) {
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
        r.currentOutstandingBalance, r.principleDue, r.interestDue,
        r.interestRate, r.lastInterestAppliedDate, r.npaDate,
        r.EMIAMOUNT, r.OVERDUEAMT, r.extra
      );
    });

    await pool.request().bulk(table);
	
// ------------------------------------------------------------------
// STEP 4 — Also store NEW upload into History table
// ------------------------------------------------------------------
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
await pool.request()
  .input("cnt", sql.Int, todayCount)
  .query(`
    INSERT INTO Recovery_Upload_Log 
    (upload_date, record_count, uploaded_at)
    VALUES 
    (CAST(GETDATE() AS DATE), @cnt, GETDATE())
  `);

// ------------------------------------------------------------------
// STEP 6 — Get YESTERDAY latest upload
// ------------------------------------------------------------------
const yesterdayLatestRes = await pool.request().query(`
  SELECT TOP 1 record_count
  FROM Recovery_Upload_Log
  WHERE upload_date = CAST(DATEADD(DAY, -1, GETDATE()) AS DATE)
  ORDER BY uploaded_at DESC
`);

const yesterdayLatestCount = 
  yesterdayLatestRes.recordset.length
  ? yesterdayLatestRes.recordset[0].record_count
  : 0;

// ------------------------------------------------------------------
// STEP 7 — Calculate difference (Yesterday latest vs Today latest)
// ------------------------------------------------------------------
const archived =
  todayCount < yesterdayLatestCount
    ? yesterdayLatestCount - todayCount
    : 0;

const newRecords =
  todayCount > yesterdayLatestCount
    ? todayCount - yesterdayLatestCount
    : 0;

    // ------------------------------------------------------------------
    // FINAL RESPONSE (USED BY FRONTEND MODAL)
    // ------------------------------------------------------------------
    res.status(200).json({
      success: true,
      message: "Upload completed successfully",
      archived,
      uploaded: newRecords,
      history_total: todayCount
    });

  } catch (err) {
    console.error("❌ PSV Upload Error:", err);
    res.status(500).json({ message: "Internal Server Error", error: err.message });
  }
});


//============================================================================================
//                          FILE UPLOAD STATUS (DAILY COMPARISON)
//============================================================================================
app.get("/api/recovery-upload-status", async (req, res) => {
  try {
    const pool = await poolPromise;
	
	const userId = req.headers["x-user-id"];

if (!userId) {
  return res.status(401).json({ message: "Unauthorized" });
}

// Fetch user role from DB
const roleResult = await pool.request()
  .input("userId", sql.VarChar(50), userId)
  .query(`
    SELECT Role 
    FROM UsersInfo
    WHERE UserId = @userId
  `);

if (!roleResult.recordset.length) {
  return res.status(403).json({ message: "User not found" });
}

const userRole = roleResult.recordset[0].Role;

if (
  userRole === "Branch Manager" ||
  userRole.startsWith("Regional Manager")
) {
  return res.status(403).json({
    message: "Access Denied. Please Contact Admin."
  });
}

// 🔹 Yesterday Last Upload
const yesterdayRes = await pool.request().query(`
SELECT TOP 1 record_count
FROM Recovery_Upload_Log
WHERE CAST(uploaded_at AS DATE) = CAST(DATEADD(DAY,-1,GETDATE()) AS DATE)
ORDER BY uploaded_at DESC
`);

const yesterday = yesterdayRes.recordset.length
  ? yesterdayRes.recordset[0].record_count
  : 0;


// 🔹 Today Last Upload
const todayRes = await pool.request().query(`
SELECT TOP 1 record_count
FROM Recovery_Upload_Log
WHERE CAST(uploaded_at AS DATE) = CAST(GETDATE() AS DATE)
ORDER BY uploaded_at DESC
`);

const today = todayRes.recordset.length
  ? todayRes.recordset[0].record_count
  : 0;


// 🔹 Difference Calculation
res.json({
  archived: today < yesterday ? yesterday - today : 0,
  uploaded: today > yesterday ? today - yesterday : 0,
  history_total: today
});

  } catch (err) {
    console.error("❌ STATUS ERROR:", err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});


//============================================================================================
//                                TRANSACTION SEARCH API
//============================================================================================
app.post("/api/transaction/search", async (req, res) => {
	
	const userId = req.headers["x-user-id"];

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
  return res.status(403).json({ message: "User not found" });
}

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

    const result = await request.query(query);

    return res.status(200).json(result.recordset);

  } catch (error) {
    console.error("❌ SEARCH API ERROR:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/assignUsers", async (req, res) => {
  try {
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

    const result = await request.query(query);
    res.json(result.recordset);

  } catch (err) {
    console.error("assignUsers error:", err);
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
    return res.json({ message: "Accounts assigned successfully" });

  } catch (err) {
    if (transaction) await transaction.rollback();
    console.error("❌ ASSIGN API ERROR:", err);
    return res.status(500).json({ message: "Assignment failed" });
  }
});


//============================================================================================
//                         TRANSACTION VIEW DETAILS (READ ONLY)
//============================================================================================
app.get("/api/transaction/details/:loanAccountNumber", async (req, res) => {

  const userId = req.headers["x-user-id"];

  if (!userId) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const { loanAccountNumber } = req.params;

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

    return res.status(200).json(result.recordset[0]);

  } catch (err) {
    console.error("❌ VIEW DETAILS API ERROR:", err);
    return res.status(500).json({ message: "Failed to fetch transaction details" });
  }
});


// ============================================================
// TRANSACTION → EXPORT PDF (FINAL CLEAN STABLE VERSION)
// ============================================================

app.post("/api/transaction/export-pdf", async (req, res) => {
  const { selectedIds, columns, fileName, serialData } = req.body;

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

    doc.end();

  } catch (err) {
    console.error("❌ TRANSACTION PDF ERROR:", err);
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

    return res.json({ message: "Assigned Successfully", assignedCount: loanIds.length });

  } catch (err) {
    console.error("Assign Error:", err);
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
    validUntil
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
    .input("UserId", userId)
    .input("UserName", userName)
    .input("BranchName", branchName)
    .input("BranchCode", sql.Int, branch_code)
    .input("ClusterName", sql.VarChar, cluster_name)
    .input("MobileNumber", mobileNumber)
    .input("DateOfBirth", sql.Date, dateOfBirth === "" ? null : dateOfBirth)
    .input("ValidFrom", sql.Date, validFrom === "" ? null : validFrom)
    .input("ValidUntil", sql.Date, validUntil === "" ? null : validUntil)

    .query(`
      INSERT INTO UsersInfo (
        UserId, UserName,
        BranchName, BranchCode, ClusterName,
        MobileNumber, DateOfBirth, ValidFrom, ValidUntil, CreatedAt
      ) VALUES (
        @UserId, @UserName,
        @BranchName, @BranchCode, @ClusterName,
        @MobileNumber, @DateOfBirth, @ValidFrom, @ValidUntil, GETDATE()
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
    validUntil
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
    name = "",
    branch = "",
	cluster = "" 
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
        'Active'     AS status
      FROM UsersInfo
      WHERE
        (@name = '' OR UserName LIKE '%' + @name + '%')
        AND (@branch = '' OR BranchName = @branch)
		AND (@cluster = '' OR ClusterName = @cluster)
      ORDER BY UserName ASC
      OFFSET @offset ROWS
      FETCH NEXT @pageSize ROWS ONLY
    `;

    const countQuery = `
      SELECT COUNT(*) AS total
      FROM UsersInfo
      WHERE
        (@name = '' OR UserName LIKE '%' + @name + '%')
        AND (@branch = '' OR BranchName = @branch)
		AND (@cluster = '' OR ClusterName = @cluster)   
    `;

    const request = pool.request()
  .input("name", sql.VarChar, name)
  .input("branch", sql.VarChar, finalBranch || "")
  .input("cluster", sql.VarChar, finalCluster || "")
      .input("offset", sql.Int, offset)
      .input("pageSize", sql.Int, pageSize);

    const records = await request.query(dataQuery);
    const countRes = await request.query(countQuery);

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

  try {

    const pool = await poolPromise;   // ✅ MOVE THIS UP
    const request = pool.request();

    const userId = req.headers["x-user-id"];
if (!userId) return res.status(401).json([]);

    const roleResult = await pool.request()
      .input("userId", userId)
      .query(`
        SELECT Role, BranchName, ClusterName
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    const userInfo = roleResult.recordset[0];

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
        f.Variance,
        f.Flow
      FROM smart_call.dbo.FieldVisitReport f
      INNER JOIN smart_call.dbo.Account_Assignments aa
        ON f.AccountNo = aa.LoanAccountNumber
        AND f.UserID = aa.AssignedToUserId
      WHERE 1 = 1
        AND aa.AssignmentStatus = 'ASSIGNED'
        AND aa.UnassignedAt IS NULL
    `;

    if (userInfo?.Role === "Branch Manager") {
      query += " AND aa.BranchName = @userBranch";
      request.input("userBranch", userInfo.BranchName);
    }
	
	// ================= REGIONAL MANAGER RESTRICTION =================
if (userInfo?.Role?.startsWith("Regional Manager")) {

  const match = userInfo.Role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  query += " AND aa.ClusterName = @rmCluster";
  request.input("rmCluster", rmCluster);

}

    if (user) {
      query += " AND f.UserID = @user";
      request.input("user", user);
    }

    if (cluster && cluster !== "Corporate Office") {
      query += " AND aa.ClusterName = @cluster";
      request.input("cluster", cluster);
    }

    if (branch) {
      query += " AND aa.BranchName = @branch";
      request.input("branch", branch);
    }

    if (fromDate) {
      query += " AND CAST(f.MeetingDate AS DATE) >= @fromDate";
      request.input("fromDate", fromDate);
    }

    if (toDate) {
      query += " AND CAST(f.MeetingDate AS DATE) <= @toDate";
      request.input("toDate", toDate);
    }

    query += " ORDER BY f.MeetingDate DESC";

    const result = await request.query(query);
    res.json(result.recordset || []);

  } catch (err) {
    console.error("FIELD VISIT REPORT ERROR:", err);
    res.status(500).json([]);
  }
});


// ====================================
// FIELD VISIT REPORT EXPORT PDF
// ====================================

const PDFDocument = require("pdfkit");

app.post("/api/field-visit-report/export-pdf", (req, res) => {
  const { columns, data } = req.body;

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

  doc.end();
});

// ====================================
// FIELD VISIT REPORT EXPORT EXCEL
// ====================================

const ExcelJS = require("exceljs");

app.post("/api/field-visit-report/export-excel", async (req, res) => {

  const { columns, data } = req.body;

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

    await workbook.xlsx.write(res);

    res.end();

  } catch (err) {

    console.error("EXCEL EXPORT ERROR:", err);
    res.status(500).send("Excel export failed");

  }

});


// =============================
// Activity Summary
// =============================
app.post("/api/activity-summary", async (req, res) => {
  const { user, branch, cluster, fromDate, toDate } = req.body;

  try {

    // ================= USER VALIDATION =================
    const rawUserId = req.headers["x-user-id"];

    if (!rawUserId) {
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

    if (!roleResult.recordset.length) {
      return res.json([]);
    }

    const userInfo = roleResult.recordset[0];

    const request = pool.request();

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
      query += ` AND aa.BranchName = @userBranch`;
      request.input("userBranch", sql.NVarChar, userInfo.BranchName);
    }
	
	// ================= REGIONAL MANAGER RESTRICTION =================
if (userInfo.Role.startsWith("Regional Manager")) {

  const match = userInfo.Role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  query += ` AND aa.ClusterName = @rmCluster`;
  request.input("rmCluster", sql.NVarChar, rmCluster);

}

    // ================= USER FILTER =================
    if (user) {
      query += ` AND aa.AssignedToUserId = @user`;
      request.input("user", sql.VarChar(50), user);
    }

    // ================= BRANCH FILTER =================
    if (branch) {
      query += ` AND aa.BranchName = @branch`;
      request.input("branch", sql.NVarChar, branch);
    }

    // ================= CLUSTER FILTER =================
    if (cluster && cluster !== "Corporate Office") {
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

    const result = await request.query(query);

    res.json(result.recordset || []);

  } catch (err) {
    console.error("Activity Summary Error:", err);
    res.status(500).json([]);
  }
});



// =====================================================================
// ACTIVITY SUMMARY → EXPORT PDF
// =====================================================================
app.post("/api/activity-summary/export-pdf", async (req, res) => {
  const { selectedData, columns, fileName } = req.body;

  if (!selectedData || selectedData.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {

    const doc = new PDFDocument({
      size: "A4",
      layout: "landscape",
      margin: 30
    });

    const safeName = (fileName || "Activity_Summary_Report")
      .replace(/\s+/g, "_");

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

    doc.end();

  } catch (err) {
    console.error("PDF ERROR:", err);
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});



// =====================================================================
// ASSIGNMENT SUMMARY
// =====================================================================

app.post("/api/assignment-summary/search", async (req, res) => {

  const { userName, cluster, branch, fromDate, toDate } = req.body;

  const role = req.headers["x-user-role"];
  const loggedBranch = req.headers["x-user-branch"];
  const loggedCluster = req.headers["x-user-cluster"];

  if (!userName && !cluster && !branch && !fromDate && !toDate) {
    return res.json([]);
  }

  try {

    const pool = await poolPromise;
    const request = pool.request();

    request.input("UserName", sql.VarChar, userName || "");

    let finalCluster = cluster;
    let finalBranch = branch;

    // 🔒 Branch Manager restriction
    if (role === "Branch Manager") {
      finalCluster = loggedCluster;
      finalBranch = loggedBranch;
    }
	
	// 🔒 Regional Manager restriction
if (role && role.startsWith("Regional Manager")) {

  const match = role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  finalCluster = rmCluster;

}

    // Corporate Office → show all clusters
    if (finalCluster === "Corporate Office") {
      finalCluster = "";
    }

    request.input("Cluster", sql.VarChar, finalCluster || "");
    request.input("Branch", sql.VarChar, finalBranch || "");
    request.input("FromDate", sql.Date, fromDate || null);
    request.input("ToDate", sql.Date, toDate || null);

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

    // ================= GROUP DATA =================

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

    res.json(Object.values(grouped));

  } catch (err) {

    console.error("Assignment summary error:", err);
    res.status(500).send("Server error");

  }

});

// ============================================================
// ASSIGNMENT SUMMARY → EXPORT PDF
// ============================================================

app.post("/api/assignment-summary/export-pdf", async (req, res) => {

  const { records, columns, fileName } = req.body;

  if (!records || records.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {

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

    doc.end();

  } catch (err) {
    console.error("PDF ERROR:", err);

    if (!res.headersSent) {
      res.status(500).json({ message: "Failed to generate PDF" });
    }
  }
});

// ======================================================
// BORROWERS CONTACTED BY PHONE 
// ======================================================
app.post("/api/borrowers-contacted/search", async (req, res) => {

  const loggedInUserId = req.headers["x-user-id"];

  if (!loggedInUserId) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const { cluster, branch, userId, fromDate, toDate } = req.body;

  try {
    const pool = await poolPromise;

// 🔥 Get logged-in user role & branch
const userInfo = await pool.request()
  .input("userId", sql.VarChar, loggedInUserId)
  .query(`
    SELECT Role, BranchName
    FROM UsersInfo
    WHERE UserId = @userId
  `);

if (!userInfo.recordset.length) {
  return res.status(403).json({ message: "User not found" });
}

const { Role, BranchName: userBranch } = userInfo.recordset[0];

const request = pool.request();

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
  query += ` AND BranchName = @restrictedBranch`;
  request.input("restrictedBranch", sql.VarChar, userBranch);
}

// 🔒 FORCE CLUSTER RESTRICTION FOR REGIONAL MANAGER
if (Role.startsWith("Regional Manager")) {

  const match = Role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  query += ` AND ClusterName = @rmCluster`;
  request.input("rmCluster", sql.VarChar, rmCluster);

}

    // ================= USER FILTER =================
    if (userId) {
      query += ` AND AssignedToUserId = @userId`;
      request.input("userId", sql.VarChar, userId);
    }

    // ================= BRANCH FILTER =================
    if (branch) {
      query += ` AND BranchName = @branch`;
      request.input("branch", sql.VarChar, branch);
    }

    // ================= CLUSTER FILTER =================
    if (cluster && cluster !== "Corporate Office") {
      query += ` AND ClusterName = @cluster`;
      request.input("cluster", sql.VarChar, cluster);
    }

    // ================= DATE FILTER =================
    if (fromDate) {
      query += ` AND CAST(StartedAt AS DATE) >= @fromDate`;
      request.input("fromDate", sql.Date, fromDate);
    }

    if (toDate) {
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

    const result = await request.query(query);

    res.json(result.recordset);

  } catch (err) {
    console.error("Borrowers Contacted Report Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// BORROWERS CONTACTED → EXPORT PDF
// ============================================================

app.post("/api/borrowers-contacted/export-pdf", async (req, res) => {
  const { selectedIndexes, columns, fileName, fullData } = req.body;

  if (!selectedIndexes || selectedIndexes.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {
    // Preserve order from frontend
    const data = selectedIndexes.map(i => fullData[i]);

    if (!data || data.length === 0) {
      return res.status(400).json({ message: "No records found" });
    }

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

    doc.end();

  } catch (err) {
    console.error("PDF ERROR:", err);
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});




// =====================================================================
// CASH COLLECTION REPORT (ONLY CASH PAYMENTS)
// =====================================================================
app.post("/api/cash-collection-report/search", async (req, res) => {
  const { user, cluster, branch, fromDate, toDate } = req.body;

  const userIdFromHeader = req.headers["x-user-id"];

  if (!userIdFromHeader) {
    return res.status(401).json([]);
  }

  // ✅ Block empty search
  if (!user && !cluster && !branch && !fromDate && !toDate) {
    return res.json([]);
  }

  try {
    const pool = await poolPromise;

    // 🔍 Get logged-in user details
    const userCheck = await pool.request()
      .input("userId", sql.VarChar(50), userIdFromHeader)
      .query(`
        SELECT Role, BranchName, ClusterName
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    if (userCheck.recordset.length === 0) {
      return res.status(403).json([]);
    }

    const loggedUser = userCheck.recordset[0];

    const request = pool.request();

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
      query += ` AND A.BranchName = @restrictedBranch`;
      request.input("restrictedBranch", sql.VarChar(100), loggedUser.BranchName);
    }
	
	// 🔒 Regional Manager restriction
if (loggedUser.Role.startsWith("Regional Manager")) {

  const match = loggedUser.Role.match(/\((.*?)\)/);
  const rmCluster = match ? match[1] : "";

  query += ` AND A.ClusterName = @rmCluster`;
  request.input("rmCluster", sql.VarChar(100), rmCluster);

}

    // ================= USER FILTER =================
    if (user) {
      query += ` AND A.AssignedToUserId = @user`;
      request.input("user", sql.VarChar(50), user);
    }

    // ================= CLUSTER FILTER =================
    if (cluster && cluster !== "Corporate Office") {
      query += ` AND A.ClusterName = @cluster`;
      request.input("cluster", sql.VarChar(100), cluster);
    }

    // ================= BRANCH FILTER =================
    if (branch) {
      query += ` AND A.BranchName = @branch`;
      request.input("branch", sql.VarChar(100), branch);
    }

    // ================= DATE FILTER =================
    if (fromDate) {
      query += ` AND CAST(L.CreatedAt AS DATE) >= @fromDate`;
      request.input("fromDate", sql.Date, fromDate);
    }

    if (toDate) {
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

    const result = await request.query(query);

    return res.json(result.recordset);

  } catch (err) {
    console.error("CASH COLLECTION REPORT ERROR:", err);
    return res.status(500).json([]);
  }
});

// ============================================================
// CASH COLLECTION REPORT → EXPORT PDF
// ============================================================

app.post("/api/cash-collection-report/export-pdf", async (req, res) => {
  const { selectedIndexes, columns, fileName, fullData } = req.body;

  if (!selectedIndexes || selectedIndexes.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {

    const data = selectedIndexes.map(i => fullData[i]).filter(Boolean);

    if (data.length === 0) {
      return res.status(400).json({ message: "No records found" });
    }

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

    doc.end();

  } catch (err) {
    console.error("❌ CASH COLLECTION PDF ERROR:", err);
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});


// =====================================================================
// USER TRIPS REPORT
// =====================================================================
app.post("/api/user-trips", async (req, res) => {
  const { cluster, branch, fromDate, toDate } = req.body;

const role = req.headers["x-user-role"];
const loggedBranch = req.headers["x-user-branch"];
const loggedCluster = req.headers["x-user-cluster"];

  if (!cluster && !branch && !fromDate && !toDate) {
    return res.status(200).json([]);
  }

  try {
    const pool = await poolPromise;
	let finalCluster = cluster;
let finalBranch = branch;

// 🔒 If Branch Manager → force restriction
if (role === "Branch Manager") {
  finalCluster = loggedCluster;
  finalBranch = loggedBranch;
}

// 🔒 Regional Manager restriction
if (role?.startsWith("Regional Manager")) {
  finalCluster = loggedCluster;
}

    const request = pool.request();

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
  query += " AND AA.ClusterName = @cluster";
  request.input("cluster", sql.VarChar, finalCluster);
}
    

    // ================= BRANCH FILTER =================
    if (finalBranch) {
  query += " AND AA.BranchName = @branch";
  request.input("branch", sql.VarChar, finalBranch);
}

    // ================= FROM DATE =================
    if (fromDate) {
      query += " AND CAST(AA.AssignedAt AS DATE) >= @fromDate";
      request.input("fromDate", sql.Date, fromDate);
    }

    // ================= TO DATE =================
    if (toDate) {
      query += " AND CAST(AA.AssignedAt AS DATE) <= @toDate";
      request.input("toDate", sql.Date, toDate);
    }

    query += " ORDER BY AA.AssignedAt DESC";

    const result = await request.query(query);

    return res.status(200).json(result.recordset || []);

  } catch (err) {
    console.error("❌ USER TRIPS ERROR:", err);
    return res.status(500).json([]);
  }
});

// ============================================================
// USER TRIPS → EXPORT PDF
// ============================================================

app.post("/api/user-trips/export-pdf", async (req, res) => {
  const { selectedIndexes, columns, fileName, fullData } = req.body;

  if (!selectedIndexes || selectedIndexes.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {

    // Preserve exact order from frontend
    const data = selectedIndexes.map(i => fullData[i]).filter(Boolean);

    if (data.length === 0) {
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

    doc.end();

  } catch (err) {
    console.error("❌ USER TRIPS PDF ERROR:", err);
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});


// ============================================================
// USER TRIPS → EXPORT EXCEL
// ============================================================

app.post("/api/user-trips/export-excel", async (req, res) => {

  const { selectedIndexes, columns, fileName, fullData } = req.body;

  try {

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
    res.end();

  } catch (err) {

    console.error("❌ EXCEL EXPORT ERROR:", err);
    res.status(500).send("Excel export failed");

  }

});


// =====================================================================
// LEAD DATA REPORT
// =====================================================================
app.post("/api/lead-data-report", async (req, res) => {

  const loggedUserId = req.headers["x-user-id"];

  const { userId, cluster, branch, fromDate, toDate } = req.body;

  if (!loggedUserId) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  if (!userId && !cluster && !branch && !fromDate && !toDate) {
    return res.json([]);
  }

  try {

    const pool = await poolPromise;
    const request = pool.request();

    // ================= GET LOGGED USER ROLE =================
    const userInfo = await pool.request()
      .input("userId", sql.VarChar, loggedUserId)
      .query(`
        SELECT Role, BranchName
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    if (!userInfo.recordset.length) {
      return res.status(403).json({ message: "User not found" });
    }

    const { Role, BranchName: userBranch } = userInfo.recordset[0];

    const isBranchManager = Role === "Branch Manager";
	const isRegionalManager = Role?.startsWith("Regional Manager");

    // ================= MAIN QUERY =================
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
      AND AL.ActionCode = 'LEAD_NOT_INTERESTED'
      AND AL.ActionLabel = 'Lead Not Interested'
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
  query += ` AND L.BranchName = @restrictedBranch `;
  request.input("restrictedBranch", sql.VarChar, userBranch);
}

// 🔒 Regional Manager restriction
if (isRegionalManager) {

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
      query += ` AND LA.LeadAssignedToUserId = @userId `;
      request.input("userId", sql.VarChar, userId);
    }

    // ================= CLUSTER FILTER =================
    if (cluster && cluster !== "Corporate Office") {
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
      query += ` AND L.BranchName = @branch `;
      request.input("branch", sql.VarChar, branch);
    }

    // ================= DATE FILTER =================
    if (fromDate) {
      query += ` AND CAST(L.TimeStamp AS DATE) >= @fromDate `;
      request.input("fromDate", sql.Date, fromDate);
    }

    if (toDate) {
      query += ` AND CAST(L.TimeStamp AS DATE) <= @toDate `;
      request.input("toDate", sql.Date, toDate);
    }

    query += ` ORDER BY L.TimeStamp DESC`;

    const result = await request.query(query);

    res.json(result.recordset || []);

  } catch (err) {

    console.error("❌ LEAD DATA REPORT ERROR:", err);
    res.status(500).json([]);

  }

});

// ============================================================
// LEAD DATA REPORT → EXPORT PDF
// ============================================================

app.post("/api/lead-data-report/export-pdf", async (req, res) => {
  const { selectedIndexes, columns, fileName, fullData } = req.body;

  if (!selectedIndexes || selectedIndexes.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {

    // Preserve exact order from frontend
    const data = selectedIndexes.map(i => fullData[i]).filter(Boolean);

    if (data.length === 0) {
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

    doc.end();

  } catch (err) {
    console.error("❌ LEAD DATA PDF ERROR:", err);
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});


// ============================================================
// LEAD DATA REPORT → EXPORT EXCEL
// ============================================================

app.post("/api/lead-data-report/export-excel", async (req, res) => {

  const { selectedIndexes, columns, fileName, fullData } = req.body;

  if (!selectedIndexes || selectedIndexes.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {

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

    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {

    console.error("❌ LEAD DATA EXCEL ERROR:", err);
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
	
	const userId = req.headers["x-user-id"];

if (!userId) {
  return res.status(401).json({ message: "Unauthorized" });
}

  const leads = req.body;

  if (!Array.isArray(leads) || leads.length === 0) {
    return res.status(400).json({ message: "No data received" });
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
  return res.status(403).json({ message: "User not found" });
}

const { Role } = userInfo.recordset[0];

const isAdmin =
  Role === "Admin" || Role === "Super Admin";

if (!isAdmin) {
  return res.status(403).json({
    message: "Only Admin can upload leads"
  });
}
  
  const transaction = new sql.Transaction(pool);

  try {

    await transaction.begin();
	
    // =============================
    // STEP 2 — INSERT NEW DATA
    // =============================
    for (const lead of leads) {

      const leadCategory = normalizeText(lead.LeadCategory);
      const leadType = normalizeText(lead.SelectLeadType);
      const userId = normalizeText(lead.UserID || lead.UserId);
      const branchCode = normalizeText(lead.BranchCode);
	  const mobileNumber = normalizeText(lead.MobileNumber);

      if (!ALLOWED_LEAD_CATEGORIES.includes(leadCategory)) {
        throw new Error(`Invalid LeadCategory`);
      }

      if (!ALLOWED_LEAD_TYPES.includes(leadType)) {
        throw new Error(`Invalid SelectLeadType`);
      }

      if (!userId) {
        throw new Error(`UserID missing in upload file`);
      }

      if (!branchCode) {
        throw new Error(`BranchCode missing in upload file`);
      }
	  
	  if (!mobileNumber) {                     
  throw new Error(`MobileNumber missing in upload file`);
}

      // ==================================
      // FETCH CLUSTER FROM BRANCH MASTER
      // ==================================
      const clusterResult = await new sql.Request(transaction)
        .input("BranchCode", sql.VarChar, branchCode)
        .query(`
          SELECT TOP 1 cluster_name
          FROM smart_call.dbo.Branch_Cluster_Master
          WHERE branch_code = @BranchCode
        `);

      if (!clusterResult.recordset.length) {
        throw new Error(`Cluster not found for BranchCode: ${branchCode}`);
      }

      const clusterName = clusterResult.recordset[0].cluster_name;

      // =============================
      // CREATE SQL REQUEST
      // =============================
      const request = new sql.Request(transaction);

      request.input("BranchCode", sql.VarChar, branchCode);
      request.input("BranchName", sql.VarChar, normalizeText(lead.BranchName));
      request.input("UserID", sql.VarChar, userId);
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

      // =============================
      // INSERT INTO HISTORY TABLE
      // =============================
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

    }

    await transaction.commit();

    res.json({
      message: "Leads uploaded successfully",
      count: leads.length
    });

  } catch (err) {

    await transaction.rollback();

    console.error("LEADS UPLOAD ERROR:", err.message);

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
  return res.status(401).json([]);
}

    const pool = await poolPromise;
    const request = pool.request();
	
	// 🔐 Get role and branch of logged user
const userInfo = await pool.request()
  .input("userId", sql.VarChar, loggedUserId)
  .query(`
    SELECT Role, BranchName, ClusterName
    FROM smart_call.dbo.UsersInfo
    WHERE UserId = @userId
  `);

if (!userInfo.recordset.length) {
  return res.status(403).json([]);
}

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

-- Not Interested
LEFT JOIN (
    SELECT DISTINCT SourceId
    FROM smart_call.dbo.Activity_Logs
    WHERE ActionCode = 'LEAD_NOT_INTERESTED'
      AND ActionLabel = 'Lead Not Interested'
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
      return res.json([]);
    }
	
    sqlQuery += " ORDER BY L.TimeStamp DESC";

    const result = await request.query(sqlQuery);
    res.json(result.recordset);

  } catch (err) {
    console.error("Lead List Search Error:", err);
    res.status(500).json([]);
  }
});

// =============================
// LEAD DETAILS
// =============================
app.get("/api/lead/details/:sno", async (req, res) => {
  try {

    const { sno } = req.params;

    const pool = await poolPromise;

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
      return res.json({});
    }

    res.json(result.recordset[0]);

  } catch (err) {
    console.error("Lead Details Error:", err);
    res.status(500).json({});
  }
});


// =====================================
// ASSIGN LEADS (LEAD LIST)
// =====================================

app.post("/api/lead/assign", async (req, res) => {

  try {

    const { mobileNumbers, assignedUserId } = req.body;
    const adminUserId = req.headers["x-user-id"];

    if (!adminUserId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    if (!mobileNumbers || mobileNumbers.length === 0) {
      return res.json({ message: "No leads selected" });
    }

    // ✅ CONNECT FIRST
   const pool = await poolPromise;

    // 🔐 Get admin role and branch
    const adminInfoFull = await pool.request()
      .input("userId", sql.VarChar, adminUserId)
      .query(`
        SELECT Role, BranchName
        FROM smart_call.dbo.UsersInfo
        WHERE UserId = @userId
      `);

    if (!adminInfoFull.recordset.length) {
      return res.status(403).json({ message: "User not found" });
    }

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

    // Get Assigned User Info
    const userInfo = await pool.request()
      .input("userId", sql.VarChar, assignedUserId)
      .query(`
        SELECT UserId, UserName, BranchCode, BranchName, ClusterName
        FROM smart_call.dbo.UsersInfo
        WHERE UserId = @userId
      `);

    if (!userInfo.recordset.length) {
      return res.json({ message: "Assigned user not found" });
    }

    const assignedUser = userInfo.recordset[0];

    let assignedCount = 0;

    for (const mobile of mobileNumbers) {

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

      if (!leadData.recordset.length) continue;

      const lead = leadData.recordset[0];
	  
	  // 🚫 Do not allow assignment if lead is OPEN or NOT INTERESTED
const activityCheck = await pool.request()
  .input("sourceId", sql.VarChar, String(lead.SNo))
  .query(`
    SELECT TOP 1 ActionCode
    FROM smart_call.dbo.Activity_Logs
    WHERE SourceId = @sourceId
    AND ActionCode IN ('LEAD_LOS_CAPTURED','LEAD_NOT_INTERESTED')
  `);

if (activityCheck.recordset.length > 0) {
  continue; // skip this lead
}

      if (!lead || !lead.SNo) {
        console.log("Lead not found for mobile:", mobile);
        continue;
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

    }

    res.json({
      message: `${assignedCount} lead(s) assigned successfully`
    });

  } catch (err) {
    console.error("Lead Assign Error:", err);
    res.status(500).json({ message: "Assignment failed" });
  }

});

// ============================================================
// LEAD ACTIVITY STATUS PAGE
// ============================================================
app.post("/api/leads-data/search", async (req, res) => {

  const userId = req.headers["x-user-id"];

  if (!userId) {
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
      closedBy = ""
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
      return res.status(403).json({ message: "User not found" });
    }

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

LEFT JOIN smart_call.dbo.Leads_Data LD
ON LD.SNo = AL.SourceId

LEFT JOIN smart_call.dbo.Lead_Assignments LA
ON LA.LeadSNo = AL.SourceId

WHERE
AL.SourceType='LEAD'
`;

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

    const result = await request.query(query);

    res.json(result.recordset);

  }

  catch (err) {

    console.error("❌ LEAD ACTIVITY STATUS ERROR:", err);
    res.status(500).json([]);

  }

});

// ============================================================
// LEAD ACTIVITY DETAILS POPUP
// ============================================================

app.post("/api/lead-activity-details", async (req, res) => {

  const userId = req.headers["x-user-id"];

  if (!userId) {
    return res.status(401).json([]);
  }

  try {

    const leadSNo = req.body.leadSNo ? String(req.body.leadSNo) : "";

    if (!leadSNo) {
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
      return res.status(403).json([]);
    }

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
            WHEN MAX(AL.ActionCode) = 'LEAD_SPOKE'
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

    const result = await request.query(query);

    res.json(result.recordset);

  } catch (err) {

    console.error("❌ ACTIVITY DETAILS ERROR:", err);
    res.status(500).json([]);

  }

});


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

// ======================================================================
// SMA REPORT UPLOAD (STORE VALUES EXACTLY AS IN EXCEL)
// ======================================================================

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
	
	const userId = req.headers["x-user-id"];

  if (!userId) {
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
    return res.status(403).json({ message: "User not found" });
  }

  const { Role } = userInfo.recordset[0];

  const isAdmin =
    Role === "Admin" || Role === "Super Admin";

  if (!isAdmin) {
    return res.status(403).json({
      message: "Only Admin can upload SMA file"
    });
  }

  try {

    const fileBuffer = req.file.buffer;
    const extension = path.extname(req.file.originalname).toLowerCase();

    let rows = [];


// ================= READ EXCEL =================

    if (extension === ".xlsx" || extension === ".xls") {

      const workbook = XLSX.read(fileBuffer, { type: "buffer" });

      const sheetName = workbook.SheetNames[0];
      const sheet = workbook.Sheets[sheetName];

      rows = XLSX.utils.sheet_to_json(sheet, { defval: "" });

      rows = rows.filter(r => r["Account Name"] && r["Account No."]);
    }


// ================= READ CSV =================

    else if (extension === ".csv") {

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

      rows = rows.filter(r => r["Account Name"] && r["Account No."]);
    }

    else {
      return res.status(400).json({ message: "Invalid file format" });
    }


    const pool = await poolPromise;


// ================= CLEAR OLD DATA =================

    await pool.request().query(`DELETE FROM dbo.SMA_Report`);


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

    // ================= BULK INSERT =================

await pool.request().bulk(table);


// ============================================================
// STEP 1 — Today Upload Count
// ============================================================

const todayCount = rows.length;


// ============================================================
// STEP 2 — Insert Upload Log
// ============================================================

await pool.request()
  .input("cnt", sql.Int, todayCount)
  .query(`
    INSERT INTO SMA_Upload_Log
    (upload_date, record_count, uploaded_at)
    VALUES
    (CAST(GETDATE() AS DATE), @cnt, GETDATE())
  `);


// ============================================================
// STEP 3 — Get Yesterday Latest Upload
// ============================================================

const yesterdayRes = await pool.request().query(`
  SELECT TOP 1 record_count
  FROM SMA_Upload_Log
  WHERE upload_date = CAST(DATEADD(DAY,-1,GETDATE()) AS DATE)
  ORDER BY uploaded_at DESC
`);

const yesterdayCount =
  yesterdayRes.recordset.length
  ? yesterdayRes.recordset[0].record_count
  : 0;


// ============================================================
// STEP 4 — Calculate Difference
// ============================================================

const archived =
  todayCount < yesterdayCount
    ? yesterdayCount - todayCount
    : 0;

const newRecords =
  todayCount > yesterdayCount
    ? todayCount - yesterdayCount
    : 0;


// ============================================================
// FINAL RESPONSE
// ============================================================

res.json({
  message: `${rows.length} records uploaded successfully`,
  archived,
  uploaded: newRecords,
  history_total: todayCount
});

  }

  catch (error) {

    console.error("SMA Upload Error:", error);

    res.status(500).json({
      message: "Upload failed"
    });

  }

});

// ============================================================
// SMA FILE UPLOAD STATUS
// ============================================================

app.get("/api/sma/upload-status", async (req, res) => {
	
	const userId = req.headers["x-user-id"];

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
  return res.status(403).json({ message: "User not found" });
}

const { Role } = userInfo.recordset[0];

if (Role !== "Admin" && Role !== "Super Admin") {
  return res.status(403).json({
    message: "Only Admin can view upload status"
  });
}

  try {

    const pool = await poolPromise;

    // 🔹 Yesterday Last Upload
    const yesterdayRes = await pool.request().query(`
      SELECT TOP 1 record_count
      FROM SMA_Upload_Log
      WHERE CAST(uploaded_at AS DATE) = CAST(DATEADD(DAY,-1,GETDATE()) AS DATE)
      ORDER BY uploaded_at DESC
    `);

    const yesterday =
      yesterdayRes.recordset.length
      ? yesterdayRes.recordset[0].record_count
      : 0;


    // 🔹 Today Last Upload
    const todayRes = await pool.request().query(`
      SELECT TOP 1 record_count
      FROM SMA_Upload_Log
      WHERE CAST(uploaded_at AS DATE) = CAST(GETDATE() AS DATE)
      ORDER BY uploaded_at DESC
    `);

    const today =
      todayRes.recordset.length
      ? todayRes.recordset[0].record_count
      : 0;


    // 🔹 Difference Calculation
    res.json({
      archived: today < yesterday ? yesterday - today : 0,
      uploaded: today > yesterday ? today - yesterday : 0,
      history_total: today
    });

  }

  catch (err) {

    console.error("SMA STATUS ERROR:", err);

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

  try {

    const pool = await sql.connect(dbConfig);

    const clusters = await pool.request().query(`
      SELECT DISTINCT [Cluster Code] as cluster
      FROM SMA_Report
      WHERE [Cluster Code] IS NOT NULL
	  ORDER BY [Cluster Code]
    `);

    const branches = await pool.request().query(`
      SELECT DISTINCT [Branch Name] as branch
      FROM SMA_Report
      WHERE [Branch Name] IS NOT NULL
	  ORDER BY [Branch Name]
    `);

    const products = await pool.request().query(`
      SELECT DISTINCT [Account Type Description] as product
      FROM SMA_Report
      WHERE [Account Type Description] IS NOT NULL
	  ORDER BY [Account Type Description]
    `);

    const productGroup = await pool.request().query(`
      SELECT DISTINCT [Product Group] as productGroup
      FROM SMA_Report
      WHERE [Product Group] IS NOT NULL
	  ORDER BY [Product Group]
    `);

    const loanType = await pool.request().query(`
      SELECT DISTINCT [Loan Type] as loanType
      FROM SMA_Report
      WHERE [Loan Type] IS NOT NULL
	  ORDER BY [Loan Type]
    `);

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

    res.json({
      clusters: clusterData,
      branches: branches.recordset,
      products: products.recordset,
      productGroup: productGroup.recordset,
      loanType: loanType.recordset,
      newIrac: newIrac
    });

  } catch (err) {

    console.error("SMA filters error:", err);
    res.status(500).json({ message: "Server error" });

  }

});


// ============================================================
// SMA SEARCH
// ============================================================
app.post("/api/sma/search", async (req, res) => {
	
	const userId = req.headers["x-user-id"];

if (!userId) {
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
  return res.status(403).json({ message: "User not found" });
}

const { Role } = userInfo.recordset[0];

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
  query += " AND COALESCE(r.mobileNumber, a.AlternateNumber) LIKE @mobileNumber";
  request.input("mobileNumber", sql.VarChar, `%${mobileNumber}%`);
}

 if (isRegionalManager) {

  query += " AND s.[Cluster Code] = @restrictedCluster";
  request.input("restrictedCluster", sql.VarChar, userClusterCode);

} else if (cluster) {

  query += " AND s.[Cluster Code] = @cluster";
  request.input("cluster", sql.VarChar, cluster);

}

    if (branch) {
      query += " AND [Branch Name] = @branch";
      request.input("branch", sql.VarChar, branch);
    }

    if (accountNumber) {
      query += " AND [Account No.] = @accountNumber";
      request.input("accountNumber", sql.VarChar, accountNumber);
    }

    if (customerName) {
      query += " AND [Account Name] LIKE @customerName";
      request.input("customerName", sql.VarChar, `%${customerName}%`);
    }

    if (product) {
      query += " AND [Account Type Description] = @product";
      request.input("product", sql.VarChar, product);
    }

    if (productGroup) {
      query += " AND [Product Group] = @productGroup";
      request.input("productGroup", sql.VarChar, productGroup);
    }

    if (loanType) {
      query += " AND [Loan Type] = @loanType";
      request.input("loanType", sql.VarChar, loanType);
    }
	
// ============================================================
// DATA TYPE FILTER
// ============================================================

if (dataType === "SMA") {

  query += `
AND s.[NEW IRAC] IN (0,1,2,3,4)
`;

}

if (dataType === "NPA") {

  query += `
AND s.[NEW IRAC] IN (4,5,6,7)
`;

}

    if (newIrac) {

  const iracValue = parseInt(newIrac); // converts "00" → 0

  query += " AND [NEW IRAC] = @newIrac";
  request.input("newIrac", sql.Int, iracValue);

}

    const result = await request.query(query);

    res.json(result.recordset);

  } catch (err) {

    console.error("SMA search error:", err);
    res.status(500).json({ message: "Server error" });

  }

});


// ============================================================
// SMA VIEW DETAILS
// ============================================================
app.get("/api/sma/details/:accountNumber", async (req, res) => {
	
	const userId = req.headers["x-user-id"];

if (!userId) {
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
  return res.status(403).json({ message: "User not found" });
}

const { Role } = userInfo.recordset[0];

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

const isRegionalManager = Role?.startsWith("Regional Manager");

  const { accountNumber } = req.params;

  try {

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

    res.json(result.recordset[0]);

  } catch (err) {

    console.error("SMA details error:", err);
    res.status(500).json({ message: "Server error" });

  }

});

// =======================================
// SMA BRANCHES BY CLUSTER
// =======================================

app.get("/api/sma/branches/:cluster", async (req, res) => {

  const { cluster } = req.params;

  try {

    const pool = await sql.connect(dbConfig);

    const result = await pool.request()
      .input("cluster", sql.VarChar, cluster)
      .query(`
        SELECT DISTINCT [Branch Name] as branch
        FROM SMA_Report
        WHERE [Cluster Code] = @cluster
        ORDER BY [Branch Name]
      `);

    res.json(result.recordset);

  } catch (err) {

    console.error("Branch fetch error:", err);
    res.status(500).json({ message: "Server error" });

  }

});


// ============================================================
// SMA ACTIVITY STATUS SEARCH
// ============================================================

app.post("/api/sma/activity/search", async (req,res)=>{

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

try{

const pool = await sql.connect(dbConfig);
const request = pool.request();

const userId = req.headers["x-user-id"];

if (!userId) {
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
  return res.status(403).json({ message: "User not found" });
}

const userRole = roleResult.recordset[0].Role;

if (userRole === "Branch Manager") {
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

if (isRegionalManager) {

  query += " AND s.[Cluster Code] = @restrictedCluster";
  request.input("restrictedCluster", sql.VarChar, userClusterCode);

} else if (cluster) {

  query += " AND s.[Cluster Code] = @cluster";
  request.input("cluster", sql.VarChar, cluster);

}

if(branch){
query += " AND s.[Branch Name] = @branch";
request.input("branch",sql.VarChar,branch);
}

if(accountNumber){
query += " AND s.[Account No.] = @accountNumber";
request.input("accountNumber",sql.VarChar,accountNumber);
}

if(customerName){
query += " AND s.[Account Name] LIKE '%' + @customerName + '%'";
request.input("customerName",sql.VarChar,customerName);
}

if(product){
query += " AND s.[Account Type Description] = @product";
request.input("product",sql.VarChar,product);
}

if(productGroup){
query += " AND s.[Product Group] = @productGroup";
request.input("productGroup",sql.VarChar,productGroup);
}

if(loanType){
query += " AND s.[Loan Type] = @loanType";
request.input("loanType",sql.VarChar,loanType);
}

if(newIrac !== ""){
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

const result = await request.query(query);

res.json(result.recordset);

}
catch(err){

console.error("SMA activity search error:",err);
res.status(500).json({message:"Server error"});

}

});

// =====================================================================
// SMA ACTIVITY DETAILS
// =====================================================================

app.post("/api/sma-activity-details", async (req, res) => {

  const { accountNumber } = req.body;

  if (!accountNumber) {
    return res.status(400).json([]);
  }

  try {

    const userId = req.headers["x-user-id"];
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const pool = await poolPromise;

    // ================= FETCH SESSIONS =================

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

    if (sessions.length === 0) {
      return res.json([]);
    }

    // ================= FETCH LOGS =================

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

    res.json(response);

  } catch (err) {

    console.error("SMA ACTIVITY DETAILS ERROR:", err);
    res.status(500).json([]);

  }

});



// =============================
// FIELD VISIT SUMMARY
// =============================

app.post("/api/field-visit-summary", async (req, res) => {

  try {

    const { user, cluster, branch, fromDate, toDate } = req.body;
	{
  return res.status(403).json({
    message: "Access Denied. Please Contact Admin."
  });
}

    const pool = await sql.connect(dbConfig);
	
	const userId = req.headers["x-user-id"];

if (!userId) {
  return res.status(401).json({ message: "Unauthorized" });
}

// Fetch user role
const roleResult = await pool.request()
  .input("userId", sql.VarChar(50), userId)
  .query(`
    SELECT Role
    FROM UsersInfo
    WHERE UserId = @userId
  `);

if (!roleResult.recordset.length) {
  return res.status(403).json({ message: "User not found" });
}

const userRole = roleResult.recordset[0].Role;

// 🔒 Admin Only Page
if (
  userRole === "Branch Manager" ||
  userRole.startsWith("Regional Manager")
) {
  return res.status(403).json({
    message: "Access Denied. Please Contact Admin."
  });
}
	
    const request = pool.request();

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

    if (user) {
      query += " AND F.UserID = @UserID";
      request.input("UserID", sql.VarChar, user);
    }

    if (cluster && cluster !== "Corporate Office") {
  query += " AND U.ClusterName = @Cluster";
  request.input("Cluster", sql.VarChar, cluster);
}

    if (branch) {
      query += " AND U.BranchName = @Branch";
      request.input("Branch", sql.VarChar, branch);
    }

    if (fromDate) {
      query += " AND CAST(F.MeetingDate AS DATE) >= @FromDate";
      request.input("FromDate", sql.Date, fromDate);
    }

    if (toDate) {
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

    const result = await request.query(query);

    res.json(result.recordset);

  } catch (error) {

    console.error("Field Visit Summary Error:", error);
    res.status(500).json({ error: "Internal Server Error" });

  }

});


// =============================
// FIELD VISIT SUMMARY EXPORT EXCEL
// =============================

app.post("/api/field-visit-summary/export-excel", async (req, res) => {

  try {

    const { columns, data } = req.body;

    if (!data || data.length === 0) {
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

    await workbook.xlsx.write(res);

    res.end();

  } catch (error) {

    console.error("Export Excel Error:", error);

    res.status(500).json({ error: "Excel export failed" });

  }

});

// =============================
// LOGIN API
// =============================

app.post("/api/login", async (req, res) => {
  const { userId, password } = req.body;

  if (!userId || !password) {
    return res.status(400).json({ message: "User ID and Password are required" });
  }

  try {
    const pool = await poolPromise;

    // 1️⃣ Check credentials
    const authQuery = await pool.request()
      .input("userId", userId)
      .input("password", password)
      .query(`
        SELECT UserId 
        FROM UserAuth
        WHERE UserId = @userId AND AppPassword = @password
      `);

    if (authQuery.recordset.length === 0) {
      return res.status(401).json({ message: "Invalid User ID or Password" });
    }

    // 2️⃣ Get user info
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
      return res.status(401).json({ message: "User not registered for dashboard access" });
    }

    const user = infoQuery.recordset[0];
    const today = new Date();

    // 3️⃣ Validity Check
    if (new Date(user.ValidFrom) > today || new Date(user.ValidUntil) < today) {
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
  return res.status(403).json({ message: "Calling Agent cannot access dashboard" });
}

if (!finalRole) {
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

// 5️⃣ SUCCESS
return res.json({
  message: "Login successful",
  userId: userId,
  role: finalRole,
  branchName: user.BranchName,
  branchCode: user.BranchCode,
  clusterName: clusterName
});

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});


/* ====================================================
   FORGOT PASSWORD – VALIDATE USER ID
   ==================================================== */

app.post("/api/forgot-password/validate-user", async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "UserId is required" });
  }

  try {
    const pool = await poolPromise;
    const request = pool.request();

    request.input("UserId", sql.VarChar(50), String(userId).trim());

    const result = await request.query(`
      SELECT TOP 1 SecurityQuestion
      FROM UserAuth
      WHERE UserId = @UserId
    `);

    if (result.recordset.length === 0) {
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

    return res.status(200).json({
      securityQuestion: fullQuestion,   // ✅ now frontend gets full sentence
      securityKey: storedValue          // ✅ optional: keep original also
    });

  } catch (err) {
    console.error("Validate User Error:", err);
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

  if (!userId || !securityAnswer || !newPassword) {
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
      return res.status(401).json({
        message: "Invalid security answer"
      });
    }

    // 2️⃣ Update password
    await pool.request()
      .input("UserId", sql.VarChar(50), String(userId).trim())
      .input("NewPassword", sql.VarChar(255), String(newPassword))
      .query(`
        UPDATE UserAuth
        SET AppPassword = @NewPassword
        WHERE UserId = @UserId
      `);

    return res.status(200).json({
      message: "Password updated successfully"
    });

  } catch (err) {
    console.error("RESET PASSWORD ERROR:", err);
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

  if (!userId || !securityAnswer) {
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
      return res.status(401).json({
        message: "Invalid security answer"
      });
    }

    // ✅ Answer is correct
    return res.status(200).json({
      message: "Security answer verified"
    });

  } catch (err) {
    console.error("VERIFY ANSWER ERROR:", err);
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
          Role
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
app.post("/api/activity/session/start", async (req, res) => {
  const {
    loanAccountNumber,
    sessionType,
    userId,
    userName,
    sourceType,
    sourceId,
  } = req.body;

  if (!sessionType || !userId || !userName || !sourceType) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  if (sourceType === "NPA" && !loanAccountNumber) {
    return res.status(400).json({ message: "LoanAccountNumber required for NPA" });
  }

  try {
    const pool = await poolPromise;

    let assignmentId = null;

    if (sourceType === "NPA") {
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

    return res.status(200).json({
      sessionId: result.recordset[0].SessionId,
      assignmentId,
    });

  } catch (err) {
    console.error("❌ START SESSION ERROR:", err);
    return res.status(500).json({ message: "Failed to start session" });
  }
});
app.post("/api/activity/log", async (req, res) => {

  console.log("📥 ACTIVITY LOG REQUEST:", req.body);

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
      }
    }

    // validation
    if (!Number(sessionIdToUse)) {
      return res.status(400).json({ message: "Invalid sessionId" });
    }

    if (!sessionIdToUse || !actionCode || !actionLabel || !userId) {
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

    return res.status(200).json({
      success: true,
      logId,
      message: "Activity log saved + status updated",
    });
  } catch (err) {
    console.error("❌ INSERT LOG ERROR:", err);
    return res.status(500).json({ message: "Failed to insert activity log" });
  }
});



app.post("/api/activity/session/end", async (req, res) => {
  const { sessionId } = req.body;

  if (!sessionId) {
    return res.status(400).json({ message: "SessionId is required" });
  }

  try {
    const pool = await poolPromise;

    await pool.request()
      .input("SessionId", sql.BigInt, parseInt(sessionId))
      .query(`
        UPDATE Activity_Sessions
        SET SessionStatus = 'COMPLETED',
            EndedAt = SYSDATETIME()
        WHERE SessionId = @SessionId
      `);

    return res.status(200).json({ success: true });

  } catch (err) {
    console.error("❌ END SESSION ERROR:", err);
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

  try {
	  
	const userId = req.headers["x-user-id"];
if (!userId) return res.status(401).json({ message: "Unauthorized" });

const pool = await poolPromise;

const roleResult = await pool.request()
  .input("userId", sql.VarChar, userId)
  .query(`
    SELECT Role, BranchName, ClusterName
    FROM UsersInfo
    WHERE UserId = @userId
  `);

const userInfo = roleResult.recordset[0];
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

    const result = await request.query(query);
    return res.json(result.recordset);

  } catch (err) {
    console.error("ACTIVITY STATUS SEARCH ERROR:", err);
    return res.status(500).json({ message: "Search failed" });
  }
});

// =====================================================================
// ACTIVITY DETAILS
// =====================================================================

app.post("/api/npa-activity-details", async (req, res) => {

  const { loanAccountNumber } = req.body;

  if (!loanAccountNumber) {
    return res.status(400).json([]);
  }

  try {

    const userId = req.headers["x-user-id"];
    if (!userId) {
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

    if (sessions.length === 0) {
      return res.json([]);
    }

    // ================= FETCH LOGS =================

    const logsResult = await pool.request().query(`
      SELECT SessionId, ActionLabel
      FROM Activity_Logs
      ORDER BY CreatedAt
    `);

    const logs = logsResult.recordset;

    // ================= GROUP LOGS =================

    const response = sessions.map(session => {

      const sessionLogs = logs.filter(
        l => l.SessionId === session.SessionId
      );

      const actions = sessionLogs
        .map((l, index) => `${index + 1}. ${l.ActionLabel}`)
        .join("\n");

      return {
        activityDate: session.activityDate,
        activityTime: session.activityTime,
        userName: session.userName,
        activityType: session.SessionType,
        activityStatus: actions || "",
        notes: ""
      };

    });

    res.json(response);

  } catch (err) {

    console.error("ACTIVITY DETAILS ERROR:", err);
    res.status(500).json([]);

  }
});

// ============================================================
// ACTIVITY STATUS → EXPORT PDF (MATCHES TRANSACTION FORMAT)
// ============================================================

app.post("/api/activity-status/export-pdf", async (req, res) => {
  const { selectedIds, columns, fileName, serialData } = req.body;

  if (!selectedIds || selectedIds.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {
    
	const userId = req.headers["x-user-id"];
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

    doc.end();

  } catch (err) {
    console.error("❌ ACTIVITY PDF ERROR:", err);
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});

// ==========================================================
// ACTIVITY STATUS ACTION API (Past / Future / Completed / Reactivate)
// ==========================================================
app.post("/api/activity-status/action", async (req, res) => {

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
    return res.status(400).json({ message: "actionType is required" });
  }

  try {
	  
	const userId = req.headers["x-user-id"];

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

      const result = await request.query(query);
      return res.json(result.recordset);
    }

    // ======================================================
    // 2️⃣ FUTURE SCHEDULE
    // ======================================================
    if (actionType === "future") {

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
    // 3️⃣ COMPLETED ACTIVITIES
    // ======================================================
    if (actionType === "completed") {

      const query = `
        SELECT DISTINCT
          R.firstname AS memberName,
          R.loanAccountNumber,
          R.mobileNumber,
          R.branchName,
          A.AssignedToUserName AS assignedTo
        ${baseQuery}
        AND (
              ISNULL(CRS.CompleteFlag,0) = 1
              OR
              ISNULL(CRS.Submitted,0) = 1
            )
      `;

      const result = await request.query(query);
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

  return res.json({ message: "Accounts reactivated successfully" });
}
    return res.status(400).json({ message: "Invalid actionType" });

  } catch (err) {
    console.error("ACTIVITY STATUS ACTION ERROR:", err);
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
// GET ROLES - POST
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
      .input("ProductCode", productCode)
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

// ======================
// START SERVER
// ======================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});
