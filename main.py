#!/usr/bin/env python3
"""
Gmail API Integration with Rule-Based Email Processing

This script authenticates with Gmail API, fetches emails, stores them in a database,
and processes them based on configurable rules.
"""

import os
import json
import sqlite3
import logging
from asyncio import timeout
from datetime import datetime, timedelta
import base64

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class GmailAPIClient:
    """Gmail API client for authentication and email operations."""

    # Required scopes for reading and modifying email labels/status
    SCOPES = [
        'https://www.googleapis.com/auth/gmail.readonly',  # Read emails and metadata
        'https://www.googleapis.com/auth/gmail.modify'  # Modify messages (mark read/unread, move)
    ]

    def __init__(self, credentials_file='credentials.json', token_file='token.json'):
        self.credentials_file = credentials_file
        self.token_file = token_file
        self.service = None
        self.authenticate()

    def authenticate(self):
        """Authenticate with Gmail API using OAuth."""
        creds = None

        # Load existing token
        if os.path.exists(self.token_file):
            creds = Credentials.from_authorized_user_file(self.token_file, self.SCOPES)

        # If there are no valid credentials, request authorization
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(self.credentials_file):
                    raise FileNotFoundError(f"Credentials file {self.credentials_file} not found. "
                                            "Download it from Google Cloud Console.")

                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_file, self.SCOPES)
                creds = flow.run_local_server(port=0)

            # Save credentials for next run
            with open(self.token_file, 'w') as token:
                token.write(creds.to_json())

        self.service = build('gmail', 'v1', credentials=creds)
        logger.info("Successfully authenticated with Gmail API")

    def fetch_emails(self, max_results=100, query='in:inbox'):
        """Fetch emails from Gmail."""
        try:
            # Get list of message IDs
            results = self.service.users().messages().list(
                userId='me', maxResults=2, q=query).execute()
            messages = results.get('messages', [])

            emails = []
            for message in messages:
                msg = self.service.users().messages().get(
                    userId='me', id=message['id'], format='full').execute()
                email_data = self._parse_email(msg)
                emails.append(email_data)

            logger.info(f"Fetched {len(emails)} emails")
            return emails

        except HttpError as error:
            logger.error(f"An error occurred: {error}")
            return []
        except Exception as err:
            logger.error(f"An error occurred: {err}")
            return []

    def _parse_email(self, message):
        """Parse Gmail message into structured data."""
        headers = message['payload'].get('headers', [])
        header_dict = {h['name'].lower(): h['value'] for h in headers}

        # Extract body
        body = self._extract_body(message['payload'])

        email_data = {
            'id': message['id'],
            'thread_id': message['threadId'],
            'from_email': header_dict.get('from', ''),
            'to_email': header_dict.get('to', ''),
            'subject': header_dict.get('subject', ''),
            'date_received': header_dict.get('date', ''),
            'message_body': body,
            'labels': message.get('labelIds', []),
            'is_read': 'UNREAD' not in message.get('labelIds', [])
        }

        return email_data

    def _extract_body(self, payload):
        """Extract email body from payload."""
        body = ""

        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
                    break
        elif payload['body'].get('data'):
            body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')

        return body

    def mark_as_read(self, message_id):
        """Mark email as read."""
        try:
            self.service.users().messages().modify(
                userId='me', id=message_id,
                body={'removeLabelIds': ['UNREAD']}
            ).execute()
            logger.info(f"Marked message {message_id} as read")
            return True
        except HttpError as error:
            if error.resp.status == 404:
                logger.warning(f"Message {message_id} not found (may have been deleted)")
            else:
                logger.error(f"Error marking message as read: {error}")
            return False

    def mark_as_unread(self, message_id):
        """Mark email as unread."""
        try:
            self.service.users().messages().modify(
                userId='me', id=message_id,
                body={'addLabelIds': ['UNREAD']}
            ).execute()
            logger.info(f"Marked message {message_id} as unread")
            return True
        except HttpError as error:
            if error.resp.status == 404:
                logger.warning(f"Message {message_id} not found (may have been deleted)")
            else:
                logger.error(f"Error marking message as unread: {error}")
            return False

    def move_message(self, message_id, label_name):
        """Move message to a label/folder."""
        try:
            # First, get all labels to find the target label ID
            labels_result = self.service.users().labels().list(userId='me').execute()
            labels = labels_result.get('labels', [])

            target_label_id = None
            for label in labels:
                if label['name'].lower() == label_name.lower():
                    target_label_id = label['id']
                    break

            if not target_label_id:
                # Try to create the label if it doesn't exist
                target_label_id = self.create_label(label_name)
                if not target_label_id:
                    logger.warning(f"Could not find or create label '{label_name}'")
                    return False

            # Move message
            self.service.users().messages().modify(
                userId='me', id=message_id,
                body={'addLabelIds': [target_label_id], 'removeLabelIds': ['INBOX']}
            ).execute()
            logger.info(f"Moved message {message_id} to {label_name}")
            return True

        except HttpError as error:
            if error.resp.status == 404:
                logger.warning(f"Message {message_id} not found (may have been deleted)")
            else:
                logger.error(f"Error moving message: {error}")
            return False

    def create_label(self, label_name):
        """Create a new label in Gmail."""
        try:
            label_object = {
                'name': label_name,
                'labelListVisibility': 'labelShow',
                'messageListVisibility': 'show'
            }

            result = self.service.users().labels().create(
                userId='me', body=label_object
            ).execute()

            logger.info(f"Created new label: {label_name}")
            return result['id']

        except HttpError as error:
            logger.error(f"Error creating label {label_name}: {error}")
            return None


class EmailDatabase:
    """Database operations for storing emails."""

    def __init__(self, db_file='emails.db'):
        self.db_file = db_file
        self.init_database()

    def init_database(self):
        """Initialize database and create tables."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id TEXT PRIMARY KEY,
                thread_id TEXT,
                from_email TEXT,
                to_email TEXT,
                subject TEXT,
                date_received TEXT,
                message_body TEXT,
                labels TEXT,
                is_read BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()
        logger.info("Database initialized")

    def store_emails(self, emails):
        """Store emails in database."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        for email in emails:
            cursor.execute('''
                INSERT OR REPLACE INTO emails 
                (id, thread_id, from_email, to_email, subject, date_received, 
                 message_body, labels, is_read)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                email['id'],
                email['thread_id'],
                email['from_email'],
                email['to_email'],
                email['subject'],
                email['date_received'],
                email['message_body'],
                json.dumps(email['labels']),
                email['is_read']
            ))

        conn.commit()
        conn.close()
        logger.info(f"Stored {len(emails)} emails in database")

    def get_emails(self):
        """Retrieve all emails from database."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM emails')
        rows = cursor.fetchall()

        emails = []
        for row in rows:
            email = {
                'id': row[0],
                'thread_id': row[1],
                'from_email': row[2],
                'to_email': row[3],
                'subject': row[4],
                'date_received': row[5],
                'message_body': row[6],
                'labels': json.loads(row[7]) if row[7] else [],
                'is_read': bool(row[8])
            }
            emails.append(email)

        conn.close()
        return emails


class EmailRuleProcessor:
    """Process emails based on rules defined in JSON."""

    def __init__(self, rules_file='rules.json', gmail_client=None):
        self.rules_file = rules_file
        self.gmail_client = gmail_client
        self.rules = self.load_rules()

    def load_rules(self):
        """Load rules from JSON file."""
        try:
            with open(self.rules_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Rules file {self.rules_file} not found")
            return {'rules': []}

    def process_emails(self, emails):
        """Process emails against all rules."""
        processed_count = 0

        for email in emails:
            for rule in self.rules.get('rules', []):
                if self.evaluate_rule(email, rule):
                    self.execute_actions(email, rule.get('actions', []))
                    processed_count += 1
                    logger.info(f"Applied rule '{rule.get('name', 'Unnamed')}' to email {email['id']}")

        logger.info(f"Processed {processed_count} rule applications")

    def evaluate_rule(self, email, rule):
        """Evaluate if an email matches a rule."""
        conditions = rule.get('conditions', [])
        predicate = rule.get('predicate', 'All')

        if not conditions:
            return False

        results = []
        for condition in conditions:
            result = self.evaluate_condition(email, condition)
            results.append(result)

        if predicate.lower() == 'all':
            return all(results)
        elif predicate.lower() == 'any':
            return any(results)
        else:
            return False

    def evaluate_condition(self, email, condition):
        """Evaluate a single condition against an email."""
        field = condition.get('field', '').lower()
        predicate = condition.get('predicate', '').lower()
        value = condition.get('value', '')

        # Get email field value
        email_value = self.get_email_field_value(email, field)

        # String predicates
        if predicate == 'contains':
            return value.lower() in email_value.lower()
        elif predicate == 'does not contain':
            return value.lower() not in email_value.lower()
        elif predicate == 'equals':
            return email_value.lower() == value.lower()
        elif predicate == 'does not equal':
            return email_value.lower() != value.lower()

        # Date predicates
        elif predicate in ['less than', 'greater than']:
            return self.evaluate_date_condition(email_value, predicate, value)

        return False

    def get_email_field_value(self, email, field):
        """Get the value of a specific field from email."""
        field_mapping = {
            'from': 'from_email',
            'to': 'to_email',
            'subject': 'subject',
            'message': 'message_body',
            'received': 'date_received'
        }

        return email.get(field_mapping.get(field, field), '')

    from datetime import datetime, timedelta
    import logging

    logger = logging.getLogger(__name__)

    def evaluate_date_condition(self, email_date_str, predicate, value):
        """Evaluate date conditions."""
        try:
            # Replace 'GMT' with '+0000' for proper parsing
            email_date_str = email_date_str.replace('GMT', '+0000')

            # Parse email date (RFC 2822 format)
            email_date = datetime.strptime(
                email_date_str.split(' (')[0].strip(),  # Remove timezone info
                '%a, %d %b %Y %H:%M:%S %z'
            ).replace(tzinfo=None)

            # Parse value (e.g., "2 days", "1 month")
            parts = value.split()
            if len(parts) != 2:
                return False

            amount = int(parts[0])
            unit = parts[1].lower()

            if unit.startswith('day'):
                delta = timedelta(days=amount)
            elif unit.startswith('month'):
                delta = timedelta(days=amount * 30)  # Approximate
            else:
                return False

            threshold_date = datetime.now() - delta

            if predicate == 'less than':
                return email_date > threshold_date
            elif predicate == 'greater than':
                return email_date < threshold_date

        except (ValueError, IndexError):
            logger.warning(f"Could not parse date: {email_date_str}")
            return False

        return False

    def execute_actions(self, email, actions):
        """Execute actions on an email."""
        for action in actions:
            action_type = action.get('type', '').lower()

            if action_type == 'mark as read':
                if self.gmail_client:
                    self.gmail_client.mark_as_read(email['id'])
                else:
                    # Fallback: only update local database
                    logger.info(f"LOCAL: Marked email {email['id']} as read")
            elif action_type == 'mark as unread':
                if self.gmail_client:
                    self.gmail_client.mark_as_unread(email['id'])
                else:
                    logger.info(f"LOCAL: Marked email {email['id']} as unread")
            elif action_type == 'move message':
                folder = action.get('folder', '')
                if folder and self.gmail_client:
                    self.gmail_client.move_message(email['id'], folder)
                else:
                    logger.info(f"LOCAL: Moved email {email['id']} to {folder}")


def main():
    """Main function to orchestrate the email processing."""
    try:
        # Initialize components
        gmail_client = GmailAPIClient()
        database = EmailDatabase()

        # Fetch emails from Gmail
        logger.info("Fetching emails from Gmail...")
        emails = gmail_client.fetch_emails(max_results=50)

        if not emails:
            logger.info("No emails found")
            return

        # Store emails in database
        logger.info("Storing emails in database...")
        database.store_emails(emails)

        # Process emails with rules
        logger.info("Processing emails with rules...")
        rule_processor = EmailRuleProcessor(gmail_client=gmail_client)

        # Get emails from database for processing
        stored_emails = database.get_emails()
        rule_processor.process_emails(stored_emails)

        logger.info("Email processing completed successfully")

    except Exception as e:
        logger.error(f"Error in main execution: {e}")
        raise


if __name__ == "__main__":
    main()