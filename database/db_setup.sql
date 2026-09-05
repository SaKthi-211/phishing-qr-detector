-- db_setup.sql
-- ---------------------------------------------------------
-- Run this script to create the phishing_qr_db database and the
-- scan_history table (via MySQL Workbench or the command line):
--
--   mysql -u root -p < database/db_setup.sql
--
-- ---------------------------------------------------------

CREATE DATABASE IF NOT EXISTS phishing_qr_db;
USE phishing_qr_db;

CREATE TABLE IF NOT EXISTS scan_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_type VARCHAR(20) NOT NULL,       -- 'url' or 'qr'
    input_value TEXT NOT NULL,            -- scanned URL / decoded QR payload
    verdict VARCHAR(20) NOT NULL,         -- 'Safe', 'Suspicious', 'Phishing'
    risk_score FLOAT NOT NULL,            -- 0 to 100
    scanned_at DATETIME NOT NULL
);

-- Quick check
SELECT 'phishing_qr_db ready!' AS status;
