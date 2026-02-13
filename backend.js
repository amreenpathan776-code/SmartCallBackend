const express = require("express");
const sql = require("mssql");
const cors = require("cors");

const app = express();
const PORT = 5001;

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

  const dpdList = dpdQueue.split(",").map(d => d.trim());

  try {
    const pool = await poolPromise;
    const request = pool.request();

    // ✅ FORCE STRING USER ID
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
    R.currentOutstandingBalance,
    R.dpdQueue,

    -- ✅ EXTRA: STATUS FLAGS
    ISNULL(CRS.PendingFlag, 0) AS PendingFlag,
    ISNULL(CRS.InProcessFlag, 0) AS InProcessFlag,
    ISNULL(CRS.CompleteFlag, 0) AS CompleteFlag,

    ISNULL(CRS.ScheduleCallPendingFlag, 0) AS ScheduleCallPendingFlag,
    ISNULL(CRS.ScheduleVisitPendingFlag, 0) AS ScheduleVisitPendingFlag,

    -- ✅ FINAL STATUS LABEL (Your requirement)
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
      .input("loanAccountNumber", sql.VarChar, loanAccountNumber)
      .query(`
        SELECT
  firstname,
  fathersName,
  village,
  gp,
  pincode,
  mobileNumber,
  loanAccountNumber,
  product,
  dpdQueue,
  currentOutstandingBalance,
  principleDue,
  interestDue,
  interestRate,
  CAST(lastInterestAppliedDate AS VARCHAR(20)) AS lastInterestAppliedDate,
  EMIAMOUNT,
  OVERDUEAMT
FROM dbo.Recovery_Raw_Data
WHERE loanAccountNumber = @loanAccountNumber;
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
// HOME → MEMBERS SUMMARY V3 (Members + NPA + Marketing + Welcome)
// =====================================================================
app.post("/api/home/members-summary-v3", async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ message: "userId required" });

  try {
    const pool = await poolPromise;

    const result = await pool.request()
      .input("UserId", sql.VarChar(50), String(userId))
      .query(`
        ;WITH Assigned AS (
          SELECT 
            A.LoanAccountNumber,
            RIGHT('00' + ISNULL(R.dpdQueue,''), 2) AS dpdQueue
          FROM Account_Assignments A
          INNER JOIN Recovery_Raw_Data R
            ON R.loanAccountNumber = A.LoanAccountNumber
          WHERE A.AssignedToUserId = @UserId
            AND A.AssignmentStatus = 'Assigned'
        )

        SELECT
          -- ===========================
          -- MEMBERS (ALL ASSIGNED)
          -- ===========================
          SUM(CASE 
                WHEN ISNULL(CRS.InProcessFlag,0)=0 
                 AND ISNULL(CRS.CompleteFlag,0)=0 
              THEN 1 ELSE 0 END) AS members_pending,

          SUM(CASE 
                WHEN ISNULL(CRS.InProcessFlag,0)=1 
                 AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS members_inprocess,

          SUM(CASE 
                WHEN ISNULL(CRS.CompleteFlag,0)=1 
              THEN 1 ELSE 0 END) AS members_completed,

          -- ===========================
          -- NPA (01 to 07)
          -- ===========================
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

          -- ===========================
          -- MARKETING (00)
          -- ===========================
          SUM(CASE 
                WHEN A.dpdQueue='00'
                 AND ISNULL(CRS.InProcessFlag,0)=0
                 AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS marketing_pending,

          SUM(CASE 
                WHEN A.dpdQueue='00'
                 AND ISNULL(CRS.InProcessFlag,0)=1
                 AND ISNULL(CRS.CompleteFlag,0)=0
              THEN 1 ELSE 0 END) AS marketing_inprocess,

          SUM(CASE 
                WHEN A.dpdQueue='00'
                 AND ISNULL(CRS.CompleteFlag,0)=1
              THEN 1 ELSE 0 END) AS marketing_completed,

          -- ===========================
          -- WELCOME (NULL / Empty dpdQueue)
          -- ===========================
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

    const row = result.recordset[0] || {};

    return res.json({
      members: {
        pending: row.members_pending || 0,
        inProcess: row.members_inprocess || 0,
        completed: row.members_completed || 0,
      },
      npa: {
        pending: row.npa_pending || 0,
        inProcess: row.npa_inprocess || 0,
        completed: row.npa_completed || 0,
      },
      marketing: {
        pending: row.marketing_pending || 0,
        inProcess: row.marketing_inprocess || 0,
        completed: row.marketing_completed || 0,
      },
      welcome: {
        pending: row.welcome_pending || 0,
        inProcess: row.welcome_inprocess || 0,
        completed: row.welcome_completed || 0,
      },
    });

  } catch (err) {
    console.error("❌ members-summary-v3 error:", err);
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
// HOME → SCHEDULE FOR THE DAY → TODAY LIST (CALL/VISIT)
// =====================================================================
app.post("/api/home/schedule-today-list", async (req, res) => {
  const { userId, type } = req.body;
  // type = "CALL" or "VISIT"

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
            R.currentOutstandingBalance,
            R.dpdQueue,

            -- ✅ MAIN STATUS FLAGS
            ISNULL(CRS.PendingFlag,0)   AS PendingFlag,
            ISNULL(CRS.InProcessFlag,0) AS InProcessFlag,
            ISNULL(CRS.CompleteFlag,0)  AS CompleteFlag,

            -- ✅ SCHEDULE FLAGS
            ISNULL(CRS.ScheduleCallPendingFlag,0)   AS ScheduleCallPendingFlag,
            ISNULL(CRS.ScheduleCallCompletedFlag,0) AS ScheduleCallCompletedFlag,

            CRS.ScheduleCallTimestamp,
            CRS.UpdatedAt,

            -- ✅ FINAL ACCOUNT STATUS
            CASE
              WHEN ISNULL(CRS.CompleteFlag,0) = 1 THEN 'COMPLETED'

              WHEN ISNULL(CRS.InProcessFlag,0) = 1
                OR ISNULL(CRS.ScheduleCallPendingFlag,0) = 1
                OR ISNULL(CRS.ScheduleVisitPendingFlag,0) = 1
              THEN 'IN PROCESS'

              ELSE 'PENDING'
            END AS AccountStatus

          FROM dbo.CallRecovery_Status CRS
          INNER JOIN dbo.Recovery_Raw_Data R
            ON R.loanAccountNumber = CRS.LoanAccountNumber

          WHERE CRS.UserId = @UserId
            AND (
              -- ✅ 1) PENDING CALLS WHICH ARE SCHEDULED TODAY
              (
                ISNULL(CRS.ScheduleCallPendingFlag,0) = 1
                AND CRS.ScheduleCallTimestamp IS NOT NULL
                AND CAST(CRS.ScheduleCallTimestamp AS DATE) = CAST(GETDATE() AS DATE)
              )

              OR

              -- ✅ 2) COMPLETED CALLS WHICH WERE COMPLETED TODAY
              (
                ISNULL(CRS.ScheduleCallCompletedFlag,0) = 1
                AND CAST(CRS.UpdatedAt AS DATE) = CAST(GETDATE() AS DATE)
              )
            )

          ORDER BY
            CASE
              WHEN ISNULL(CRS.ScheduleCallPendingFlag,0) = 1 THEN 1
              ELSE 2
            END,
            CRS.UpdatedAt DESC
        `
        : `
          SELECT
            CRS.LoanAccountNumber,
            R.firstname,
            R.mobileNumber,
            R.currentOutstandingBalance,
            R.dpdQueue,

            -- ✅ MAIN STATUS FLAGS
            ISNULL(CRS.PendingFlag,0)   AS PendingFlag,
            ISNULL(CRS.InProcessFlag,0) AS InProcessFlag,
            ISNULL(CRS.CompleteFlag,0)  AS CompleteFlag,

            -- ✅ SCHEDULE FLAGS
            ISNULL(CRS.ScheduleVisitPendingFlag,0)   AS ScheduleVisitPendingFlag,
            ISNULL(CRS.ScheduleVisitCompletedFlag,0) AS ScheduleVisitCompletedFlag,

            CRS.ScheduleVisitTimestamp,
            CRS.UpdatedAt,

            -- ✅ FINAL ACCOUNT STATUS
            CASE
              WHEN ISNULL(CRS.CompleteFlag,0) = 1 THEN 'COMPLETED'

              WHEN ISNULL(CRS.InProcessFlag,0) = 1
                OR ISNULL(CRS.ScheduleCallPendingFlag,0) = 1
                OR ISNULL(CRS.ScheduleVisitPendingFlag,0) = 1
              THEN 'IN PROCESS'

              ELSE 'PENDING'
            END AS AccountStatus

          FROM dbo.CallRecovery_Status CRS
          INNER JOIN dbo.Recovery_Raw_Data R
            ON R.loanAccountNumber = CRS.LoanAccountNumber

          WHERE CRS.UserId = @UserId
            AND (
              -- ✅ 1) PENDING VISITS WHICH ARE SCHEDULED TODAY
              (
                ISNULL(CRS.ScheduleVisitPendingFlag,0) = 1
                AND CRS.ScheduleVisitTimestamp IS NOT NULL
                AND CAST(CRS.ScheduleVisitTimestamp AS DATE) = CAST(GETDATE() AS DATE)
              )

              OR

              -- ✅ 2) COMPLETED VISITS WHICH WERE COMPLETED TODAY
              (
                ISNULL(CRS.ScheduleVisitCompletedFlag,0) = 1
                AND CAST(CRS.UpdatedAt AS DATE) = CAST(GETDATE() AS DATE)
              )
            )

          ORDER BY
            CASE
              WHEN ISNULL(CRS.ScheduleVisitPendingFlag,0) = 1 THEN 1
              ELSE 2
            END,
            CRS.UpdatedAt DESC
        `;

    const result = await pool.request()
      .input("UserId", sql.VarChar(50), String(userId))
      .query(query);

    return res.json({
      type,
      records: result.recordset || [],
    });

  } catch (err) {
    console.error("❌ schedule-today-list error:", err);
    return res.status(500).json({ message: "Failed to load today schedules" });
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
    !startLat ||
    !startLng ||
    !startAddress ||
    !customerLat ||
    !customerLng ||
    !customerAddress
  ) {
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
  const { sno, meetLat, meetLng, meetAddress, distanceTravelled } = req.body;

  if (!sno || !meetLat || !meetLng) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  try {
    const pool = await poolPromise;

    await pool.request()
      .input("SNo", sql.Int, sno)
      .input("MeetingLatitude", sql.Decimal(18, 10), meetLat)
      .input("MeetingLongitude", sql.Decimal(18, 10), meetLng)
      .input("MeetingAddress", sql.VarChar(sql.MAX), meetAddress || null)
      .input("DistanceTravelled", sql.Decimal(18, 3), distanceTravelled || 0)
      .input("MeetingDate", sql.DateTime, new Date())
      .query(`
        UPDATE FieldVisitReport
        SET
          MeetingDate = @MeetingDate,
          MeetingLatitude = @MeetingLatitude,
          MeetingLongitude = @MeetingLongitude,
          MeetingAddress = @MeetingAddress,
          DistanceTravelled = @DistanceTravelled
        WHERE SNo = @SNo
      `);

    return res.json({ message: "✅ Stop saved and distance updated" });
  } catch (err) {
    console.log("FieldVisitReport stop update error:", err);
    return res.status(500).json({ message: "Server error", error: err.message });
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
//                                PSV FILE DATA UPLOAD + DAILY COMPARISON
//============================================================================================
app.post("/api/recovery-upload", async (req, res) => {
  const { records } = req.body;

  if (!records || !Array.isArray(records)) {
    return res.status(400).json({ message: "Invalid JSON format" });
  }

  try {
    const pool = await poolPromise;

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
    // STEP 4 — Store TODAY count in log table
    // ------------------------------------------------------------------
    await pool.request()
      .input("cnt", sql.Int, todayCount)
      .query(`
        IF NOT EXISTS (
          SELECT 1 FROM Recovery_Upload_Log
          WHERE upload_date = CAST(GETDATE() AS DATE)
        )
        INSERT INTO Recovery_Upload_Log (upload_date, record_count)
        VALUES (CAST(GETDATE() AS DATE), @cnt)
      `);

    // ------------------------------------------------------------------
    // STEP 5 — Calculate DAILY differences
    // ------------------------------------------------------------------
    const archived =
      todayCount < yesterdayCount ? yesterdayCount - todayCount : 0;

    const newRecords =
      todayCount > yesterdayCount ? todayCount - yesterdayCount : 0;

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

    const todayRes = await pool.request().query(`
      SELECT record_count
      FROM Recovery_Upload_Log
      WHERE upload_date = CAST(GETDATE() AS DATE)
    `);

    const yesterdayRes = await pool.request().query(`
      SELECT TOP 1 record_count
      FROM Recovery_Upload_Log
      WHERE upload_date < CAST(GETDATE() AS DATE)
      ORDER BY upload_date DESC
    `);

    const today = todayRes.recordset.length ? todayRes.recordset[0].record_count : 0;
    const yesterday = yesterdayRes.recordset.length ? yesterdayRes.recordset[0].record_count : 0;

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

    if (mobileNumber) {
      query += ` AND mobileNumber = @mobileNumber`;
      request.input("mobileNumber", sql.VarChar, mobileNumber);
    }

    if (pincode) {
      query += ` AND pincode = @pincode`;
      request.input("pincode", sql.VarChar, pincode);
    }

    if (branchName) {
       query += ` AND branchName LIKE @branchName`;
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
      query += ` AND branchCode IN (
        SELECT branch_code
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
  const { loanAccountNumber } = req.params;

  if (!loanAccountNumber) {
    return res.status(400).json({ message: "Loan Account Number required" });
  }

  try {
    const pool = await poolPromise;

    const result = await pool.request()
      .input("loanAccountNumber", sql.VarChar, loanAccountNumber)
      .query(`
        SELECT TOP 1
          firstname                           AS customerName,

          CONVERT(VARCHAR, dob, 105)          AS dob,               -- dd-mm-yyyy

          CASE 
            WHEN gender = 'M' THEN 'Male'
            WHEN gender = 'F' THEN 'Female'
            ELSE gender
          END                                 AS gender,

          pancard                             AS panNumber,
          gp                                  AS address,
          pincode                             AS pincode,
          mobileNumber                        AS mobileNumber,
          loanAccountNumber                   AS loanAccountNumber,
          OVERDUEAMT                          AS outstandingAmount,
          interestDue                         AS interestDue,
          principleDue                        AS principalDue,
          interestRate                        AS interestRate

        FROM smart_call.dbo.Recovery_Raw_Data
        WHERE loanAccountNumber = @loanAccountNumber
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: "Record not found" });
    }

    return res.status(200).json(result.recordset[0]);

  } catch (err) {
    console.error("❌ VIEW DETAILS API ERROR:", err);
    return res.status(500).json({ message: "Failed to fetch transaction details" });
  }
});


// ============================================================
// TRANSACTION → EXPORT PDF (SELECTED ROWS ONLY)
// ============================================================

app.post("/api/transaction/export-pdf", async (req, res) => {
  const { selectedIds, columns, fileName } = req.body;

  if (!selectedIds || selectedIds.length === 0) {
    return res.status(400).json({ message: "No records selected" });
  }

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {
    const pool = await poolPromise;

    const request = pool.request();

    selectedIds.forEach((id, index) => {
      request.input(`id${index}`, sql.VarChar, id);
    });

    const result = await request.query(`
      SELECT
        firstname AS firstName,
        loanAccountNumber AS accountNumber,
        product,
        mobileNumber,
        branchName AS branch
      FROM Recovery_Raw_Data
      WHERE loanAccountNumber IN (${selectedIds.map((_, i) => `@id${i}`).join(",")})
    `);

    const data = result.recordset || [];

    const PDFDocument = require("pdfkit");

    const doc = new PDFDocument({
      size: "A4",
      layout: "landscape",
      margin: 30
    });

    const safeName = (fileName || "Transaction_Report").replace(/\s+/g, "_");

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.pdf"`
    );

    doc.pipe(res);

    // ================= TITLE =================
    doc.font("Helvetica-Bold").fontSize(14).text("Transaction Report", {
      align: "center"
    });

    doc.moveDown(1);

    const COLUMN_LABELS = {
      firstName: "First Name",
      accountNumber: "Account Number",
      product: "Product",
      mobileNumber: "Mobile Number",
      branch: "Branch"
    };

    const pageWidth =
      doc.page.width - doc.page.margins.left - doc.page.margins.right;

    const colWidth = pageWidth / columns.length;
    const rowHeight = 25;

    let x = doc.page.margins.left;
    let y = doc.y;

    // ================= HEADER =================
    doc.font("Helvetica-Bold").fontSize(10);

    columns.forEach(col => {
      doc.rect(x, y, colWidth, rowHeight).fillAndStroke("#e5e7eb", "#000");
      doc.fillColor("#000").text(COLUMN_LABELS[col], x + 5, y + 7, {
        width: colWidth - 10,
        align: "center"
      });
      x += colWidth;
    });

    y += rowHeight;
    doc.font("Helvetica").fontSize(9);

    // ================= ROWS =================
    data.forEach(row => {
      x = doc.page.margins.left;

      columns.forEach(col => {
        doc.rect(x, y, colWidth, rowHeight).stroke();
        doc.text(String(row[col] ?? ""), x + 5, y + 7, {
          width: colWidth - 10,
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
  allowedHeaders: ["Content-Type", "Authorization"]
}));


// ======================
// Assign Users (dropdown)
// ======================
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
      WHERE Role IN ('ADMIN','BM','CRO')  -- Shows Admins also
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
    role,
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
    .input("Role", role)
    .input("BranchName", branchName)
    .input("BranchCode", sql.Int, branch_code)
    .input("ClusterName", sql.VarChar, cluster_name)
    .input("MobileNumber", mobileNumber)
    .input("DateOfBirth", sql.Date, dateOfBirth === "" ? null : dateOfBirth)
    .input("ValidFrom", sql.Date, validFrom === "" ? null : validFrom)
    .input("ValidUntil", sql.Date, validUntil === "" ? null : validUntil)

    .query(`
      INSERT INTO UsersInfo (
        UserId, UserName, Role,
        BranchName, BranchCode, ClusterName,
        MobileNumber, DateOfBirth, ValidFrom, ValidUntil, CreatedAt
      ) VALUES (
        @UserId, @UserName, @Role,
        @BranchName, @BranchCode, @ClusterName,
        @MobileNumber, @DateOfBirth, @ValidFrom, @ValidUntil, GETDATE()
      )
    `);

  res.json({ message: "User created successfully" });
});

//=============USER ID ============================================
app.put("/api/users/:userId", async (req, res) => {
  const { userId } = req.params;

  const {
    userName,
    branchName,
    role,
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
      .input("Role", sql.VarChar, role)
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
          Role = @Role,
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
    branch = ""
  } = req.body;

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
        Role         AS role,
        MobileNumber AS mobileNumber,
        DateOfBirth  AS dateOfBirth,
        ValidFrom    AS validFrom,
        ValidUntil   AS validUntil,
        'Active'     AS status
      FROM UsersInfo
      WHERE
        (@name = '' OR UserName LIKE '%' + @name + '%')
        AND (@branch = '' OR BranchName = @branch)
      ORDER BY CreatedAt DESC
      OFFSET @offset ROWS
      FETCH NEXT @pageSize ROWS ONLY
    `;

    const countQuery = `
      SELECT COUNT(*) AS total
      FROM UsersInfo
      WHERE
        (@name = '' OR UserName LIKE '%' + @name + '%')
        AND (@branch = '' OR BranchName = @branch)
    `;

    const request = pool.request()
      .input("name", sql.VarChar, name)
      .input("branch", sql.VarChar, branch)
      .input("offset", sql.Int, offset)
      .input("pageSize", sql.Int, pageSize);

    const records = await request.query(dataQuery);
    const countRes = await request.query(countQuery);

    const total = countRes.recordset[0].total;
    const pages = Math.ceil(total / pageSize);

    res.json({
      records: records.recordset,
      page,
      pages
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
// FIELD VISIT REPORT - SEARCH (FIXED)
// ====================================================================================
app.post("/api/field-visit-report", async (req, res) => {
  const { user, fromDate, toDate } = req.body;

  try {
    const pool = await poolPromise;

    let query = `
      SELECT
        UserID,
        UserName,
        AccountNo,
        CustomerName,
        BranchLatitude,
        BranchLongitude,
        MeetingDate,
        StartLatitude,
        StartLongitude,
        MeetingLatitude,
        MeetingLongitude,
        MeetingAddress,
        DistanceTravelled,
        CustomerLatitude,
        CustomerLongitude,
        Variance,
        Flow
      FROM smart_call.dbo.FieldVisitReport
      WHERE 1 = 1
    `;

    const request = pool.request();

    if (user) {
      query += " AND UserID = @user";
      request.input("user", user);
    }

    if (fromDate) {
      query += " AND CAST(MeetingDate AS DATE) >= @fromDate";
      request.input("fromDate", fromDate);
    }

    if (toDate) {
      query += " AND CAST(MeetingDate AS DATE) <= @toDate";
      request.input("toDate", toDate);
    }

    query += " ORDER BY MeetingDate DESC";

    const result = await request.query(query);

    res.json(result.recordset); // ALWAYS ARRAY
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


// =============================
// Activity Summary
// =============================
app.post("/api/activity-summary", async (req, res) => {
  const { user, branch, fromDate, toDate } = req.body;

  try {
    const pool = await sql.connect(dbConfig);
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

    if (user) {
      query += ` AND aa.AssignedToUserName = @user`;
      request.input("user", sql.NVarChar, user);
    }

    if (branch) {
      query += ` AND aa.BranchName = @branch`;
      request.input("branch", sql.NVarChar, branch);
    }

    query += `
        GROUP BY
          aa.AssignedToUserName,
          aa.BranchName,
          aa.LoanAccountNumber
      )

      SELECT
  UserName,
  BranchName,
  COUNT(*) AS Assigned,

  -- cumulative call logic
  SUM(CASE WHEN CallCount >= 1 THEN 1 ELSE 0 END) AS CalledOnce,
  SUM(CASE WHEN CallCount >= 2 THEN 1 ELSE 0 END) AS CalledTwice,
  SUM(CASE WHEN CallCount >= 3 THEN 1 ELSE 0 END) AS CalledThrice,

  -- ✅ TOTAL calls (ALL CALL_SPOKE logs)
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
  const { filters, columns, fileName } = req.body;

  if (!columns || columns.length === 0) {
    return res.status(400).json({ message: "No columns selected" });
  }

  try {
    const pool = await poolPromise;
    const request = pool.request();

    request.input("fromDate", sql.Date, filters?.fromDate || null);
    request.input("toDate", sql.Date, filters?.toDate || null);

    if (filters?.user) {
      request.input("user", sql.NVarChar, filters.user);
    }

    if (filters?.branch) {
      request.input("branch", sql.NVarChar, filters.branch);
    }

    // 🔁 SAME QUERY AS /api/activity-summary
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
          AND l.ActionCode IN ('CALL_SPOKE','VISIT_COMPLETED')
          AND (@fromDate IS NULL OR CAST(l.CreatedAt AS DATE) >= @fromDate)
          AND (@toDate IS NULL OR CAST(l.CreatedAt AS DATE) <= @toDate)

        WHERE aa.AssignmentStatus = 'ASSIGNED'
          AND aa.UnassignedAt IS NULL
    `;

    if (filters?.user) query += ` AND aa.AssignedToUserName = @user`;
    if (filters?.branch) query += ` AND aa.BranchName = @branch`;

    query += `
        GROUP BY
          aa.AssignedToUserName,
          aa.BranchName,
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
      ORDER BY UserName, BranchName
    `;

    const result = await request.query(query);
    const data = result.recordset || [];

    // ================= PDF SETUP =================
    const doc = new PDFDocument({
      size: "A4",
      layout: "landscape",
      margin: 30
    });

    const safeName = (fileName || "Activity_Summary_Report").replace(/\s+/g, "_");

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeName}.pdf"`
    );

    doc.pipe(res);

    // ================= TITLE =================
    doc.font("Helvetica-Bold").fontSize(14).text("Activity Summary Report", {
      align: "center"
    });

    doc.moveDown(1);

    // ================= COLUMN LABELS =================
    const COLUMN_LABELS = {
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

    const pageWidth =
      doc.page.width - doc.page.margins.left - doc.page.margins.right;

    const colWidth = pageWidth / columns.length;
    const rowHeight = 22;

    let x = doc.page.margins.left;
    let y = doc.y;

    // ================= HEADER =================
    doc.fontSize(9).font("Helvetica-Bold");

    columns.forEach(col => {
      doc.rect(x, y, colWidth, rowHeight).fillAndStroke("#e5e7eb", "#000");
      doc
        .fillColor("#000")
        .text(COLUMN_LABELS[col], x + 4, y + 6, {
          width: colWidth - 8,
          align: "center"
        });
      x += colWidth;
    });

    y += rowHeight;
    doc.font("Helvetica").fontSize(9);

    // ================= ROWS =================
    data.forEach(row => {
      x = doc.page.margins.left;

      columns.forEach(col => {
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
    console.error("❌ ACTIVITY SUMMARY PDF ERROR:", err);
    res.status(500).json({ message: "Failed to generate PDF" });
  }
});


// =====================================================================
// ASSIGNMENT SUMMARY 
// =====================================================================

app.post("/api/assignment-summary/search", async (req, res) => {
  const { userName, cluster, branch, fromDate, toDate } = req.body;

  try {
    const pool = await poolPromise;
    const request = pool.request();

    request.input("UserName", sql.VarChar, userName || "");
    request.input("Cluster", sql.VarChar, cluster || "");
    request.input("Branch", sql.VarChar, branch || "");
    request.input("FromDate", sql.Date, fromDate || null);
    request.input("ToDate", sql.Date, toDate || null);

    const result = await request.query(`
      SELECT 
          U.UserId,
          U.UserName,
          U.BranchCode,
          U.BranchName,
          A.LoanAccountNumber AS AccountNumber,
          R.firstname AS CustomerName,
          R.dpdQueue AS DpdQueue,
          COUNT(A.LoanAccountNumber) 
              OVER (PARTITION BY U.UserId) AS NoOfAccounts,
          A.AssignedAt
      FROM Account_Assignments A
      INNER JOIN UsersInfo U
          ON A.AssignedByAdminName = U.UserName
      INNER JOIN Recovery_Raw_Data R
          ON A.LoanAccountNumber = R.loanAccountNumber
      WHERE 
          (@UserName = '' OR U.UserName = @UserName)
          AND (@Cluster = '' OR U.ClusterName = @Cluster)
          AND (@Branch = '' OR U.BranchName = @Branch)
          AND (
              @FromDate IS NULL 
              OR @ToDate IS NULL 
              OR CAST(A.AssignedAt AS DATE) 
                  BETWEEN @FromDate AND @ToDate
          )
      ORDER BY A.AssignedAt DESC
    `);

    res.json(result.recordset);

  } catch (err) {
    console.error("Assignment summary error:", err);
    res.status(500).send("Server error");
  }
});



// =====================================================================
// USER TRIPS REPORT (SEARCH)
// =====================================================================
app.post("/api/user-trips", async (req, res) => {
  const { cluster, branch, fromDate, toDate } = req.body;

  try {
    const pool = await poolPromise;
    const request = pool.request();

    let query = `
      SELECT
        UserName,
        UserId,
        MemberName,
        AccountNumber,
        BranchName,
        MonthYear,
        VisitDate,
        TotalDistance,
        DistanceTravelled,
        StartLocation,
        EndLocation
      FROM smart_call.dbo.User_Trips
      WHERE 1 = 1
    `;

    // ================= CLUSTER FILTER =================
    if (cluster && cluster !== "Corporate Office") {
      query += `
        AND BranchName IN (
          SELECT branch_name
          FROM Branch_Cluster_Master
          WHERE cluster_name = @cluster
        )
      `;
      request.input("cluster", sql.VarChar, cluster);
    }

    // ================= BRANCH FILTER =================
    if (branch) {
      query += " AND BranchName = @branch";
      request.input("branch", sql.VarChar, branch);
    }

    // ================= FROM DATE =================
    if (fromDate) {
      query += " AND CAST(VisitDate AS DATE) >= @fromDate";
      request.input("fromDate", sql.Date, fromDate);
    }

    // ================= TO DATE =================
    if (toDate) {
      query += " AND CAST(VisitDate AS DATE) <= @toDate";
      request.input("toDate", sql.Date, toDate);
    }

    query += " ORDER BY VisitDate DESC";

    const result = await request.query(query);

    return res.status(200).json(result.recordset || []);

  } catch (err) {
    console.error("❌ USER TRIPS ERROR:", err);
    return res.status(500).json([]);
  }
});


// =====================================================================
// LEAD DATA REPORT (SEARCH)
// =====================================================================
app.post("/api/lead-data-report", async (req, res) => {
  const { userId, cluster, branch, fromDate, toDate } = req.body;

  try {
    const pool = await poolPromise;
    const request = pool.request();

    let query = `
      SELECT
        Name,
        BranchName,
        UserName,
        MemberName,
        MemberAddress,
        MemberMobileNumber,
        ProductCategory,
        InitialProduct,
        InterestedProduct,
        CONVERT(VARCHAR, DateOfEntry, 105) AS DateOfEntry,
        CONVERT(VARCHAR, DateOfVisit, 105) AS DateOfVisit,
        ActivityStatus
      FROM smart_call.dbo.Lead_Data_Report
      WHERE 1 = 1
    `;

    // ================= USER FILTER =================
    if (userId) {
      query += " AND UserName = @userId";
      request.input("userId", sql.VarChar, userId);
    }

    // ================= CLUSTER FILTER =================
    if (cluster && cluster !== "Corporate Office") {
      query += `
        AND BranchName IN (
          SELECT branch_name
          FROM Branch_Cluster_Master
          WHERE cluster_name = @cluster
        )
      `;
      request.input("cluster", sql.VarChar, cluster);
    }

    // ================= BRANCH FILTER =================
    if (branch) {
      query += " AND BranchName = @branch";
      request.input("branch", sql.VarChar, branch);
    }

    // ================= FROM DATE =================
    if (fromDate) {
      query += " AND CAST(DateOfEntry AS DATE) >= @fromDate";
      request.input("fromDate", sql.Date, fromDate);
    }

    // ================= TO DATE =================
    if (toDate) {
      query += " AND CAST(DateOfEntry AS DATE) <= @toDate";
      request.input("toDate", sql.Date, toDate);
    }

    query += " ORDER BY DateOfEntry DESC";

    const result = await request.query(query);

    res.json(result.recordset || []);
  } catch (err) {
    console.error("❌ LEAD DATA REPORT ERROR:", err);
    res.status(500).json([]);
  }
});


// =============================
// LEAD DATA UPLOAD (FINAL)
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

// DB constraint values
const ALLOWED_LEAD_CATEGORIES = [
  "Known Lead",
  "Unknown Lead"
];

// Business Lead Types
const ALLOWED_LEAD_TYPES = [
  "Hot Lead",
  "Warm Lead",
  "Cold Lead"
];

app.post("/api/leads/upload", async (req, res) => {
  const leads = req.body;

  if (!Array.isArray(leads) || leads.length === 0) {
    return res.status(400).json({ message: "No data received" });
  }

  const pool = await poolPromise;
  const transaction = new sql.Transaction(pool);

  try {
    await transaction.begin();

    // =====================================
    // STEP 1 — DELETE OLD LEADS
    // =====================================
    await new sql.Request(transaction).query(`
      DELETE FROM dbo.Leads_Data
    `);

    // =====================================
    // STEP 2 — INSERT NEW LEADS
    // =====================================
    for (const lead of leads) {
      const request = new sql.Request(transaction);

      const leadCategory = normalizeText(lead.LeadCategory);
      const leadType = normalizeText(lead.SelectLeadType);

      // ---------------- VALIDATIONS ----------------
      if (!ALLOWED_LEAD_CATEGORIES.includes(leadCategory)) {
        throw new Error(
          `Invalid LeadCategory: "${lead.LeadCategory}". Allowed: Known Lead, Unknown Lead`
        );
      }

      if (!ALLOWED_LEAD_TYPES.includes(leadType)) {
        throw new Error(
          `Invalid SelectLeadType: "${lead.SelectLeadType}". Allowed: Hot Lead, Warm Lead, Cold Lead`
        );
      }

      // ---------------- PARAMETERS ----------------
      request.input("BranchCode", sql.VarChar, normalizeText(lead.BranchCode));
      request.input("BranchName", sql.VarChar, normalizeText(lead.BranchName));
      request.input("UserID", sql.VarChar, normalizeText(lead.UserID));
      request.input("UserName", sql.VarChar, normalizeText(lead.UserName));
      request.input("AssignedTo", sql.VarChar, normalizeText(lead.AssignedTo));
      request.input("LeadCategory", sql.VarChar, leadCategory);
      request.input("FullName", sql.VarChar, normalizeText(lead.FullName || lead.FirstName));
      request.input("MobileNumber", sql.VarChar, normalizeText(lead.MobileNumber));
      request.input("Address", sql.VarChar, normalizeText(lead.Address));
      request.input("PinCode", sql.VarChar, normalizeText(lead.PinCode));
      request.input("DOB", sql.Date, parseDate(lead.DOB));
      request.input("ProductCategory", sql.VarChar, normalizeText(lead.ProductCategory));
      request.input("SelectProduct", sql.VarChar, normalizeText(lead.SelectProduct));
      request.input("SelectLeadType", sql.VarChar, leadType);
      request.input("LeadStatus", sql.VarChar, normalizeText(lead.LeadStatus));
      request.input("ScheduledTime", sql.DateTime, parseDate(lead.ScheduledTime));
      request.input("ScheduledVisit", sql.DateTime, parseDate(lead.ScheduledVisit));
      request.input("CalledAt", sql.DateTime, parseDate(lead.CalledAt));
      request.input("VisitedAt", sql.DateTime, parseDate(lead.VisitedAt));

      // ---------- INSERT INTO MAIN TABLE ----------
      await request.query(`
        INSERT INTO dbo.Leads_Data (
          BranchCode,
          BranchName,
          UserID,
          UserName,
          AssignedTo,
          LeadCategory,
          FullName,
          MobileNumber,
          Address,
          PinCode,
          DOB,
          ProductCategory,
          SelectProduct,
          SelectLeadType,
          LeadStatus,
          ScheduledTime,
          ScheduledVisit,
          CalledAt,
          VisitedAt,
          TimeStamp
        ) VALUES (
          @BranchCode,
          @BranchName,
          @UserID,
          @UserName,
          @AssignedTo,
          @LeadCategory,
          @FullName,
          @MobileNumber,
          @Address,
          @PinCode,
          @DOB,
          @ProductCategory,
          @SelectProduct,
          @SelectLeadType,
          @LeadStatus,
          @ScheduledTime,
          @ScheduledVisit,
          @CalledAt,
          @VisitedAt,
          GETDATE()
        )
      `);

      // ---------- INSERT INTO HISTORY TABLE ----------
      await request.query(`
        INSERT INTO dbo.Leads_Data_History (
          BranchCode,
          BranchName,
          UserID,
          UserName,
          AssignedTo,
          LeadCategory,
          FullName,
          MobileNumber,
          Address,
          PinCode,
          DOB,
          ProductCategory,
          SelectProduct,
          SelectLeadType,
          LeadStatus,
          ScheduledTime,
          ScheduledVisit,
          CalledAt,
          VisitedAt,
          TimeStamp,
          UploadedAt
        ) VALUES (
          @BranchCode,
          @BranchName,
          @UserID,
          @UserName,
          @AssignedTo,
          @LeadCategory,
          @FullName,
          @MobileNumber,
          @Address,
          @PinCode,
          @DOB,
          @ProductCategory,
          @SelectProduct,
          @SelectLeadType,
          @LeadStatus,
          @ScheduledTime,
          @ScheduledVisit,
          @CalledAt,
          @VisitedAt,
          GETDATE(),
          GETDATE()
        )
      `);
    }

    await transaction.commit();

    res.json({
      message: "Leads uploaded successfully",
      uploaded: leads.length
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
    console.log("SEARCH FILTERS:", req.body);

    const {
      memberName,
      mobileNumber,
      pincode,
      cluster,
      branch,
      product,
      assignedTo,
      leadType
    } = req.body;

    let sqlQuery = `
      SELECT
        L.SNo,
        L.FullName        AS firstName,
        L.MobileNumber    AS mobileNumber,
        L.BranchName      AS branch,
        L.SelectLeadType  AS leadType,
        L.LeadStatus      AS status
      FROM smart_call.dbo.Leads_Data L
      INNER JOIN smart_call.dbo.Branch_Cluster_Master B
        ON L.BranchName = B.branch_name
      WHERE 1 = 1
    `;

    const pool = await sql.connect(dbConfig);
    const request = pool.request();

    // 🔎 Member Name
    if (memberName) {
      sqlQuery += " AND L.FullName LIKE @memberName";
      request.input("memberName", `%${memberName}%`);
    }

    // 🔎 Mobile Number
    if (mobileNumber) {
      sqlQuery += " AND L.MobileNumber LIKE @mobileNumber";
      request.input("mobileNumber", `%${mobileNumber}%`);
    }

    // 🔎 Pincode
    if (pincode) {
      sqlQuery += " AND L.PinCode = @pincode";
      request.input("pincode", pincode);
    }

    // 🔎 Cluster (NOW WORKS)
    if (cluster) {
      sqlQuery += " AND B.cluster_name = @cluster";
      request.input("cluster", cluster);
    }

    // 🔎 Branch
    if (branch) {
      sqlQuery += " AND L.BranchName = @branch";
      request.input("branch", branch);
    }

    // 🔎 Product
    if (product) {
      sqlQuery += " AND L.SelectProduct LIKE @product";
      request.input("product", `%${product}%`);
    }

    // 🔎 Assigned To
    if (assignedTo) {
      sqlQuery += " AND L.AssignedTo LIKE @assignedTo";
      request.input("assignedTo", `%${assignedTo}%`);
    }

    // 🔎 Lead Type
    if (leadType) {
      sqlQuery += " AND L.SelectLeadType LIKE @leadType";
      request.input("leadType", `%${leadType}%`);
    }

    console.log("FINAL SQL:", sqlQuery);

    const result = await request.query(sqlQuery);
    res.json(result.recordset);
  } catch (err) {
    console.error("Lead List Search Error:", err);
    res.status(500).json([]);
  }
});


// =============================
// LEAD LIST SEARCH (Leads_Data)
// =============================
app.post("/api/leads-data/search", async (req, res) => {
  try {
    const {
      memberName = "",
      mobileNumber = "",
      pincode = "",
      cluster = "",
      branch = "",
      product = "",
      assignedTo = "",
      leadType = "",
      leadStatus = ""
    } = req.body;

    const pool = await poolPromise;
    const request = pool.request();

    let query = `
      SELECT
        L.SNo,
        L.FullName        AS memberName,
        L.MobileNumber    AS mobileNumber,
        L.BranchName      AS branchName,
        L.SelectProduct   AS product,
        L.SelectLeadType  AS leadType,
        L.LeadStatus      AS leadStatus,
        L.AssignedTo      AS assignedTo
      FROM smart_call.dbo.Leads_Data L
      LEFT JOIN smart_call.dbo.Branch_Cluster_Master B
        ON L.BranchName = B.branch_name
      WHERE 1 = 1
    `;

    // 🔎 Member Name
    if (memberName) {
      query += " AND L.FullName LIKE @memberName";
      request.input("memberName", sql.VarChar, `%${memberName}%`);
    }

    // 🔎 Mobile Number
    if (mobileNumber) {
      query += " AND L.MobileNumber LIKE @mobileNumber";
      request.input("mobileNumber", sql.VarChar, `%${mobileNumber}%`);
    }

    // 🔎 Pincode
    if (pincode) {
      query += " AND L.PinCode = @pincode";
      request.input("pincode", sql.VarChar, pincode);
    }

    // 🔎 Cluster (via Branch master)
    if (cluster && cluster !== "Corporate Office") {
      query += " AND B.cluster_name = @cluster";
      request.input("cluster", sql.VarChar, cluster);
    }

    // 🔎 Branch
    if (branch) {
      query += " AND L.BranchName = @branch";
      request.input("branch", sql.VarChar, branch);
    }

    // 🔎 Product
    if (product) {
      query += " AND L.SelectProduct = @product";
      request.input("product", sql.VarChar, product);
    }

    // 🔎 Assigned To
    if (assignedTo) {
      query += " AND L.AssignedTo = @assignedTo";
      request.input("assignedTo", sql.VarChar, assignedTo);
    }

    // 🔎 Lead Type
    if (leadType) {
      query += " AND L.SelectLeadType = @leadType";
      request.input("leadType", sql.VarChar, leadType);
    }

    // 🔎 Lead Status
    if (leadStatus) {
      query += " AND L.LeadStatus = @leadStatus";
      request.input("leadStatus", sql.VarChar, leadStatus);
    }

    query += " ORDER BY L.TimeStamp DESC";

    const result = await request.query(query);
    return res.json(result.recordset || []);

  } catch (err) {
    console.error("❌ LEADS SEARCH ERROR:", err);
    return res.status(500).json([]);
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

    // 1. Check credentials in UserAuth
    const authQuery = await pool.request()
      .input("userId", userId)
      .input("password", password)
      .query(`
        SELECT UserId FROM UserAuth
        WHERE UserId = @userId AND AppPassword = @password
      `);

    if (authQuery.recordset.length === 0) {
      return res.status(401).json({ message: "Invalid User ID or Password" });
    }

    // 2. Check user authorization & role in UsersInfo
    const infoQuery = await pool.request()
      .input("userId", userId)
      .query(`
        SELECT Role, ValidFrom, ValidUntil
        FROM UsersInfo
        WHERE UserId = @userId
      `);

    if (infoQuery.recordset.length === 0) {
      return res.status(401).json({ message: "User not registered for dashboard access" });
    }

    const user = infoQuery.recordset[0];
    const today = new Date();

    // 3. Check validity dates
    if (new Date(user.ValidFrom) > today || new Date(user.ValidUntil) < today) {
      return res.status(403).json({ message: "User access expired or not yet active" });
    }

    // 4. Check role access (optional rules)
    if (!["ADMIN"].includes(user.Role)) {
      return res.status(403).json({ message: "User role not authorized for dashboard" });
    }


    // 5. Successful login
    return res.json({
      message: "Login successful",
      role: user.Role,
      userId: userId
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




// ===============================================================================================================================================================================================
//                           ACTIVITY LOGGING APIs
// ==================================================================================================================================================================================================
app.post("/api/activity/session/start", async (req, res) => {
  const {
    loanAccountNumber,
    sessionType,
    userId,
    userName,
  } = req.body;

  if (!loanAccountNumber || !sessionType || !userId || !userName) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  try {
    const pool = await poolPromise;

    // ✅ Get AssignmentId from Account_Assignments
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

    const assignmentId = assignRes.recordset[0].AssignmentId;

    // ✅ Start Session
    const result = await pool.request()
      .input("AssignmentId", sql.BigInt, assignmentId)
      .input("LoanAccountNumber", sql.VarChar(50), loanAccountNumber)
      .input("SessionType", sql.VarChar(20), sessionType)
      .input("StartedByUserId", sql.VarChar(50), String(userId))
      .input("StartedByUserName", sql.VarChar(100), userName)
      .query(`
        INSERT INTO Activity_Sessions (
          AssignmentId,
          LoanAccountNumber,
          SessionType,
          SessionStatus,
          StartedByUserId,
          StartedByUserName
        )
        OUTPUT INSERTED.SessionId
        VALUES (
          @AssignmentId,
          @LoanAccountNumber,
          @SessionType,
          'ACTIVE',
          @StartedByUserId,
          @StartedByUserName
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
  const {
    sessionId,
    actionCode,
    actionLabel,
    reasonCode = null,
    metadata = null,
    noteText = null,
    userId,
    userName,
  } = req.body;

  if (!sessionId || !actionCode || !actionLabel || !userId) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  try {
    const pool = await poolPromise;

    // 1️⃣ Get last log for hierarchy
    const parentResult = await pool
      .request()
      .input("SessionId", sql.BigInt, sessionId)
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
      .input("SessionId", sql.BigInt, sessionId)
      .input("ParentLogId", sql.BigInt, parentLogId)
      .input("ActionCode", sql.VarChar(100), actionCode)
      .input("ActionLabel", sql.VarChar(200), actionLabel)
      .input("ReasonCode", sql.VarChar(50), reasonCode)
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
          CreatedByUserName
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
          @CreatedByUserName
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
        .input("SessionId", sql.BigInt, sessionId)
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
      .input("SessionId", sql.BigInt, sessionId)
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
    const pool = await poolPromise;
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
	
	if (queue) {
  query += ` AND R.QueueType = @queue`;
  request.input("queue", queue);
}

if (dpdQueue === "30") {
  query += ` AND R.DPD BETWEEN 1 AND 30`;
}

if (dpdQueue === "60") {
  query += ` AND R.DPD BETWEEN 31 AND 60`;
}

if (dpdQueue === "60+") {
  query += ` AND R.DPD > 60`;
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
        AND R.branchCode IN (
          SELECT branch_code
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

app.post("/api/activity-details", async (req, res) => {
  const { loanAccountNumber } = req.body;

  if (!loanAccountNumber) {
    return res.status(400).json([]);
  }

  try {
    const pool = await poolPromise;

    // 1️⃣ Fetch sessions
    const sessionsResult = await pool.request()
      .input("loanAccountNumber", sql.VarChar, loanAccountNumber)
      .query(`
        SELECT
          s.SessionId,
          CONVERT(varchar, s.StartedAt, 105) AS activityDate,
          FORMAT(s.StartedAt, 'hh:mm tt') AS activityTime,
          s.StartedByUserName AS userName,
          s.SessionType,
          s.SessionStatus
        FROM Activity_Sessions s
        WHERE s.LoanAccountNumber = @loanAccountNumber
        ORDER BY s.StartedAt DESC
      `);

    const sessions = sessionsResult.recordset;

    if (sessions.length === 0) {
      return res.json([]);
    }

    // 2️⃣ Fetch logs
    const logsResult = await pool.request().query(`
      SELECT SessionId, ActionLabel
      FROM Activity_Logs
      ORDER BY CreatedAt
    `);

    const logs = logsResult.recordset;

    // 3️⃣ Group logs under sessions
    const response = sessions.map(session => {
      const actions = logs
        .filter(l => l.SessionId === session.SessionId)
        .map(l => `• ${l.ActionLabel}`)
        .join("\n");

      return {
        activityDate: session.activityDate,
        activityTime: session.activityTime,
        userName: session.userName,
        activityType: session.SessionType,
        activityStatus: session.SessionStatus,
        notes: actions
      };
    });

    res.json(response);

  } catch (err) {
    console.error("ACTIVITY DETAILS ERROR:", err);
    res.status(500).json([]);
  }
});


// ======================
// START SERVER
// ======================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});
