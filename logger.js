const fs = require("fs");
const path = require("path");

function writeDailyLog(type, message) {
  const now = new Date();

  const today = now.toLocaleDateString("en-CA", {
    timeZone: "Asia/Kolkata"
  });

  const time = now.toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata"
  });

  const logDir = path.join(__dirname, "logs", type);

  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  const safeType = type.includes("/") 
    ? type.split("/").pop() 
    : type;

  const logFile = path.join(logDir, `${today}.${safeType}.log`);

  const line = `${time} | ${message}\n`;

  fs.appendFileSync(logFile, line);
}

module.exports = writeDailyLog;