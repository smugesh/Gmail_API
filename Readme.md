# Gmail API Email Processor

A standalone Python application that integrates with Gmail API to fetch, store, and process emails based on configurable rules. This system can automatically perform actions like marking emails as read/unread and moving messages to different folders based on customizable conditions.

## Features

- **Gmail API Integration**: Secure OAuth authentication with Gmail API
- **Email Storage**: SQLite database for local email storage and processing
- **Rule-Based Processing**: Flexible JSON-configured rules for email automation
- **Multiple Conditions**: Support for string and date-based conditions with AND/OR logic
- **Automated Actions**: Mark as read/unread and move messages to folders
- **Comprehensive Testing**: Full test suite with unit and integration tests

## Project Structure

```
gmail-email-processor/
├── main.py                     # Main application script
├── rules.json                  # Email processing rules configuration
├── test_email_processor.py     # Comprehensive test suite
├── requirements.txt            # Python dependencies
├── README.md                   # This documentation
├── credentials.json            # Gmail API credentials (you need to create this)
├── token.json                  # OAuth token (auto-generated)
├── emails.db                   # SQLite database (auto-generated)
└── setup.py                    # Installation script
```

## Prerequisites

1. **Python 3.8+** installed on your system
2. **Gmail Account** with API access enabled
3. **Google Cloud Project** with Gmail API enabled

## Installation & Setup

### Step 1: Clone or Download the Project

```bash
# If using git
git clone <repository-url>
cd gmail-email-processor

# Or download and extract the files to a directory
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Set Up Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Gmail API:
   - Go to "APIs & Services" > "Library"
   - Search for "Gmail API" and enable it
4. Create credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Choose "Desktop application"
   - Download the JSON file and save it as `credentials.json` in your project directory

### Step 4: Configure Rules

Edit the `rules.json` file to customize email processing rules according to your needs. The file contains example rules that you can modify.

### Step 5: Run the Application

```bash
python main.py
```

On first run, the application will:
1. Open a browser window for Gmail OAuth authentication
2. Create the SQLite database (`emails.db`)
3. Fetch emails from your inbox
4. Store them in the database
5. Process them according to your rules

## Configuration

### Rules Configuration

The `rules.json` file defines the email processing rules. Each rule has:

#### Rule Structure
```json
{
  "rules": [
    {
      "name": "Rule Name",
      "description": "Optional description",
      "predicate": "All|Any",
      "conditions": [
        {
          "field": "from|to|subject|message|received",
          "predicate": "contains|does not contain|equals|does not equal|less than|greater than",
          "value": "condition value"
        }
      ],
      "actions": [
        {
          "type": "mark as read|mark as unread|move message",
          "folder": "folder name (for move action)"
        }
      ]
    }
  ]
}
```

#### Supported Fields
- `from`: Sender email address
- `to`: Recipient email address  
- `subject`: Email subject line
- `message`: Email body content
- `received`: Email received date/time

#### String Predicates
- `contains`: Field contains the specified value
- `does not contain`: Field does not contain the specified value
- `equals`: Field exactly matches the specified value
- `does not equal`: Field does not match the specified value

#### Date Predicates
- `less than`: Email received within the specified time (e.g., "2 days", "1 month")
- `greater than`: Email received before the specified time

#### Rule Predicates
- `All`: All conditions must be true
- `Any`: At least one condition must be true

#### Actions
- `mark as read`: Mark the email as read
- `mark as unread`: Mark the email as unread
- `move message`: Move email to specified folder

### Example Rules

```json
{
  "rules": [
    {
      "name": "Auto-read newsletters",
      "predicate": "Any",
      "conditions": [
        {"field": "from", "predicate": "contains", "value": "newsletter"},
        {"field": "subject", "predicate": "contains", "value": "unsubscribe"}
      ],
      "actions": [
        {"type": "mark as read"}
      ]
    },
    {
      "name": "Important work emails",
      "predicate": "All",
      "conditions": [
        {"field": "from", "predicate": "contains", "value": "@company.com"},
        {"field": "subject", "predicate": "contains", "value": "URGENT"}
      ],
      "actions": [
        {"type": "mark as unread"},
        {"type": "move message", "folder": "Important"}
      ]
    }
  ]
}
```

## Database Schema

The SQLite database contains an `emails` table with the following structure:

```sql
CREATE TABLE emails (
    id TEXT PRIMARY KEY,              -- Gmail message ID
    thread_id TEXT,                   -- Gmail thread ID
    from_email TEXT,                  -- Sender email
    to_email TEXT,                    -- Recipient email
    subject TEXT,                     -- Email subject
    date_received TEXT,               -- Date received (RFC 2822 format)
    message_body TEXT,                -- Email body content
    labels TEXT,                      -- Gmail labels (JSON array)
    is_read BOOLEAN,                  -- Read status
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Testing

Run the test suite:

```bash
python test_email_processor.py
```

The test suite includes:
- **Unit tests** for individual components
- **Integration tests** for workflow testing

### Test Coverage

- Database operations (create, store, retrieve)
- Rule evaluation (all condition types)
- Action execution (mark read/unread, move messages)
- Date condition parsing and evaluation
- Error handling for invalid inputs
- End-to-end workflow testing

## Architecture

### Main Components

1. **GmailAPIClient**: Handles Gmail API authentication and operations
   - OAuth authentication flow
   - Email fetching and parsing
   - Email actions (mark read/unread, move)

2. **EmailDatabase**: Manages local SQLite database
   - Database initialization
   - Email storage and retrieval
   - Duplicate handling

3. **EmailRuleProcessor**: Processes emails against defined rules
   - Rule loading and parsing
   - Condition evaluation
   - Action execution
