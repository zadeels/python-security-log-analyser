# Python Security Log Analyser

## Overview
A Python-based cybersecurity project that analyses authentication logs to identify potentially suspicious login activity.

## Current Features
- Reads authentication records from a sample CSV file
- Counts failed login attempts
- Counts successful login attempts
- Track failed login attempts by IP address
- Reads CSV files using csv.DictReader
- Detects IP addresses that reach or exceed a configurable failed-login threshold
- Displays warning and informational messages for authentication activity.
- Allows users to specify their own CSV authentication log files.
- Handles missing authentication log files using Python exception handling.
- Displays clear error messages when a file cannot be found.
- Validates CSV files for required column headers.
- Displays descriptive error messages when required columns are missing.
- Validates authentication timestamps using Python's datetime module.
- Reports invalid timestamp values and their corresponding CSV row numbers.
- Validates authentication timestamps and identifies invalid date/time values.
- Records failed login timestamps separately for each IP address.
- Performs an initial five-minute detection check using the first five failed attempts per IP.

## Planned Features
- Generate CSV security reports

## Technologies
- Python 3
- CSV authentication logs

## Development Status
In development.

## Learning Objectives
- Improve Python programming skills
- Understand authentication log analysis
- Practise basic security monitoring and detection

## Input File Format

The Security Log Analyser currently supports CSV files containing authentication records.

Each file must contain the following columns:

| Column | Description |
|---|---|
| `timestamp` | Date and time of the login attempt |
| `ip_address` | IP address associated with the login attempt |
| `username` | Username involved in the login attempt |
| `status` | Login result (`SUCCESS` or `FAILED`) |

### Example CSV

```csv
timestamp,ip_address,username,status
2026-10-30 09:00:01,192.168.1.10,admin,FAILED
2026-10-30 09:01:00,192.168.1.20,john,SUCCESS
2026-10-30 09:02:00,192.168.1.10,admin,FAILED
```

**Note:** The current version expects these column names and uses `SUCCESS` and `FAILED` to identify authentication outcomes. Support for additional log formats and improved input validation is planned.
