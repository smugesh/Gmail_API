#!/usr/bin/env python3
"""
Test suite for Gmail API Email Processor

This module contains unit and integration tests for the email processing system.
"""

import unittest
import json
import os
import tempfile
import sqlite3
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

# Import our main modules
from main import GmailAPIClient, EmailDatabase, EmailRuleProcessor


class TestEmailDatabase(unittest.TestCase):
    """Test cases for EmailDatabase class."""

    def setUp(self):
        """Set up test database."""
        self.test_db = tempfile.NamedTemporaryFile(delete=False)
        self.test_db.close()
        self.db = EmailDatabase(self.test_db.name)

        # Sample email data
        self.sample_emails = [
            {
                'id': 'test_id_1',
                'thread_id': 'thread_1',
                'from_email': 'sender@example.com',
                'to_email': 'receiver@example.com',
                'subject': 'Test Subject',
                'date_received': 'Mon, 1 Jan 2024 10:00:00 +0000',
                'message_body': 'Test message body',
                'labels': ['INBOX', 'UNREAD'],
                'is_read': False
            },
            {
                'id': 'test_id_2',
                'thread_id': 'thread_2',
                'from_email': 'newsletter@company.com',
                'to_email': 'receiver@example.com',
                'subject': 'Weekly Newsletter',
                'date_received': 'Tue, 2 Jan 2024 10:00:00 +0000',
                'message_body': 'Newsletter content',
                'labels': ['INBOX'],
                'is_read': True
            }
        ]

    def tearDown(self):
        """Clean up test database."""
        os.unlink(self.test_db.name)

    def test_database_initialization(self):
        """Test database table creation."""
        conn = sqlite3.connect(self.test_db.name)
        cursor = conn.cursor()

        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='emails'")
        result = cursor.fetchone()
        self.assertIsNotNone(result)

        conn.close()

    def test_store_emails(self):
        """Test storing emails in database."""
        self.db.store_emails(self.sample_emails)

        conn = sqlite3.connect(self.test_db.name)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM emails')
        count = cursor.fetchone()[0]

        self.assertEqual(count, 2)
        conn.close()

    def test_get_emails(self):
        """Test retrieving emails from database."""
        self.db.store_emails(self.sample_emails)
        retrieved_emails = self.db.get_emails()

        self.assertEqual(len(retrieved_emails), 2)
        self.assertEqual(retrieved_emails[0]['id'], 'test_id_1')
        self.assertEqual(retrieved_emails[1]['subject'], 'Weekly Newsletter')

    def test_duplicate_email_handling(self):
        """Test that duplicate emails are handled correctly."""
        # Store same emails twice
        self.db.store_emails(self.sample_emails)
        self.db.store_emails(self.sample_emails)

        retrieved_emails = self.db.get_emails()
        self.assertEqual(len(retrieved_emails), 2)  # Should still be 2, not 4


class TestEmailRuleProcessor(unittest.TestCase):
    """Test cases for EmailRuleProcessor class."""

    def setUp(self):
        """Set up test rules and processor."""
        self.test_rules_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')

        self.test_rules = {
            "rules": [
                {
                    "name": "Newsletter Rule",
                    "predicate": "Any",
                    "conditions": [
                        {
                            "field": "from",
                            "predicate": "contains",
                            "value": "newsletter"
                        }
                    ],
                    "actions": [
                        {
                            "type": "mark as read"
                        }
                    ]
                },
                {
                    "name": "Important Rule",
                    "predicate": "All",
                    "conditions": [
                        {
                            "field": "subject",
                            "predicate": "contains",
                            "value": "URGENT"
                        },
                        {
                            "field": "from",
                            "predicate": "contains",
                            "value": "boss"
                        }
                    ],
                    "actions": [
                        {
                            "type": "mark as unread"
                        },
                        {
                            "type": "move message",
                            "folder": "Important"
                        }
                    ]
                }
            ]
        }

        json.dump(self.test_rules, self.test_rules_file)
        self.test_rules_file.close()

        # Mock Gmail client
        self.mock_gmail_client = Mock()

        self.processor = EmailRuleProcessor(
            rules_file=self.test_rules_file.name,
            gmail_client=self.mock_gmail_client
        )

        # Sample emails for testing
        self.test_emails = [
            {
                'id': 'email_1',
                'from_email': 'newsletter@company.com',
                'to_email': 'user@example.com',
                'subject': 'Weekly Update',
                'message_body': 'Newsletter content',
                'date_received': 'Mon, 1 Jan 2024 10:00:00 +0000',
                'is_read': False
            },
            {
                'id': 'email_2',
                'from_email': 'boss@company.com',
                'to_email': 'user@example.com',
                'subject': 'URGENT: Project Deadline',
                'message_body': 'This is urgent',
                'date_received': 'Tue, 2 Jan 2024 10:00:00 +0000',
                'is_read': False
            },
            {
                'id': 'email_3',
                'from_email': 'friend@example.com',
                'to_email': 'user@example.com',
                'subject': 'Casual message',
                'message_body': 'Just saying hi',
                'date_received': 'Wed, 3 Jan 2024 10:00:00 +0000',
                'is_read': False
            }
        ]

    def tearDown(self):
        """Clean up test files."""
        os.unlink(self.test_rules_file.name)

    def test_load_rules(self):
        """Test loading rules from JSON file."""
        rules = self.processor.rules
        self.assertEqual(len(rules['rules']), 2)
        self.assertEqual(rules['rules'][0]['name'], 'Newsletter Rule')

    def test_evaluate_condition_contains(self):
        """Test 'contains' condition evaluation."""
        email = self.test_emails[0]  # Newsletter email
        condition = {
            'field': 'from',
            'predicate': 'contains',
            'value': 'newsletter'
        }

        result = self.processor.evaluate_condition(email, condition)
        self.assertTrue(result)

    def test_evaluate_condition_does_not_contain(self):
        """Test 'does not contain' condition evaluation."""
        email = self.test_emails[2]  # Friend email
        condition = {
            'field': 'from',
            'predicate': 'does not contain',
            'value': 'newsletter'
        }

        result = self.processor.evaluate_condition(email, condition)
        self.assertTrue(result)

    def test_evaluate_condition_equals(self):
        """Test 'equals' condition evaluation."""
        email = self.test_emails[1]  # Boss email
        condition = {
            'field': 'subject',
            'predicate': 'equals',
            'value': 'URGENT: Project Deadline'
        }

        result = self.processor.evaluate_condition(email, condition)
        self.assertTrue(result)

    def test_evaluate_rule_any_predicate(self):
        """Test rule evaluation with 'Any' predicate."""
        email = self.test_emails[0]  # Newsletter email
        rule = self.test_rules['rules'][0]  # Newsletter rule

        result = self.processor.evaluate_rule(email, rule)
        self.assertTrue(result)

    def test_evaluate_rule_all_predicate(self):
        """Test rule evaluation with 'All' predicate."""
        email = self.test_emails[1]  # Boss email with URGENT subject
        rule = self.test_rules['rules'][1]  # Important rule

        result = self.processor.evaluate_rule(email, rule)
        self.assertTrue(result)

    def test_evaluate_rule_all_predicate_fails(self):
        """Test rule evaluation with 'All' predicate that should fail."""
        email = self.test_emails[2]  # Friend email (doesn't match conditions)
        rule = self.test_rules['rules'][1]  # Important rule

        result = self.processor.evaluate_rule(email, rule)
        self.assertFalse(result)

    def test_execute_actions_mark_as_read(self):
        """Test executing 'mark as read' action."""
        email = self.test_emails[0]
        actions = [{'type': 'mark as read'}]

        self.processor.execute_actions(email, actions)
        self.mock_gmail_client.mark_as_read.assert_called_once_with('email_1')

    def test_execute_actions_move_message(self):
        """Test executing 'move message' action."""
        email = self.test_emails[1]
        actions = [{'type': 'move message', 'folder': 'Important'}]

        self.processor.execute_actions(email, actions)
        self.mock_gmail_client.move_message.assert_called_once_with('email_2', 'Important')

    def test_process_emails_integration(self):
        """Test end-to-end email processing."""
        self.processor.process_emails(self.test_emails)

        # Should have called mark_as_read for newsletter email
        self.mock_gmail_client.mark_as_read.assert_called_with('email_1')

        # Should have called both mark_as_unread and move_message for boss email
        self.mock_gmail_client.mark_as_unread.assert_called_with('email_2')
        self.mock_gmail_client.move_message.assert_called_with('email_2', 'Important')

    def test_get_email_field_value(self):
        """Test field value extraction from email."""
        email = self.test_emails[0]

        from_value = self.processor.get_email_field_value(email, 'from')
        subject_value = self.processor.get_email_field_value(email, 'subject')

        self.assertEqual(from_value, 'newsletter@company.com')
        self.assertEqual(subject_value, 'Weekly Update')


class TestDateConditions(unittest.TestCase):
    """Test cases for date-based conditions."""

    def setUp(self):
        """Set up processor for date testing."""
        self.processor = EmailRuleProcessor()

    def test_evaluate_date_condition_less_than(self):
        """Test 'less than' date condition (recent emails)."""
        # Email from yesterday (should be less than 2 days)
        yesterday = datetime.now() - timedelta(days=1)
        email_date_str = yesterday.strftime('%a, %d %b %Y %H:%M:%S +0000')

        result = self.processor.evaluate_date_condition(
            email_date_str, 'less than', '2 days'
        )
        self.assertTrue(result)

    def test_evaluate_date_condition_greater_than(self):
        """Test 'greater than' date condition (old emails)."""
        # Email from 10 days ago (should be greater than 7 days)
        old_date = datetime.now() - timedelta(days=10)
        email_date_str = old_date.strftime('%a, %d %b %Y %H:%M:%S +0000')

        result = self.processor.evaluate_date_condition(
            email_date_str, 'greater than', '7 days'
        )
        self.assertTrue(result)

    def test_evaluate_date_condition_months(self):
        """Test date condition with months."""
        # Email from 2 months ago
        old_date = datetime.now() - timedelta(days=70)
        email_date_str = old_date.strftime('%a, %d %b %Y %H:%M:%S +0000')

        result = self.processor.evaluate_date_condition(
            email_date_str, 'greater than', '1 month'
        )
        self.assertTrue(result)


class TestGmailAPIClientMocked(unittest.TestCase):
    """Test cases for GmailAPIClient with mocked API calls."""

    @patch('main.build')
    @patch('main.Credentials')
    def setUp(self, mock_credentials, mock_build):
        """Set up mocked Gmail client."""
        # Mock the credentials and service
        mock_creds = Mock()
        mock_creds.valid = True
        mock_credentials.from_authorized_user_file.return_value = mock_creds

        self.mock_service = Mock()
        mock_build.return_value = self.mock_service

        # Create client with mocked authentication
        with patch('os.path.exists', return_value=True):
            self.client = GmailAPIClient()

    def test_parse_email_basic(self):
        """Test basic email parsing."""
        mock_message = {
            'id': 'test_id',
            'threadId': 'test_thread',
            'labelIds': ['INBOX', 'UNREAD'],
            'payload': {
                'headers': [
                    {'name': 'From', 'value': 'sender@example.com'},
                    {'name': 'To', 'value': 'receiver@example.com'},
                    {'name': 'Subject', 'value': 'Test Subject'},
                    {'name': 'Date', 'value': 'Mon, 1 Jan 2024 10:00:00 +0000'}
                ],
                'body': {
                    'data': 'VGVzdCBib2R5'  # Base64 for "Test body"
                }
            }
        }

        parsed_email = self.client._parse_email(mock_message)

        self.assertEqual(parsed_email['id'], 'test_id')
        self.assertEqual(parsed_email['from_email'], 'sender@example.com')
        self.assertEqual(parsed_email['subject'], 'Test Subject')
        self.assertFalse(parsed_email['is_read'])  # UNREAD label present

    def test_parse_email_multipart(self):
        """Test parsing multipart email."""
        mock_message = {
            'id': 'test_id',
            'threadId': 'test_thread',
            'labelIds': ['INBOX'],
            'payload': {
                'headers': [
                    {'name': 'From', 'value': 'sender@example.com'},
                    {'name': 'Subject', 'value': 'Multipart Test'}
                ],
                'parts': [
                    {
                        'mimeType': 'text/plain',
                        'body': {
                            'data': 'VGVzdCBib2R5'  # Base64 for "Test body"
                        }
                    },
                    {
                        'mimeType': 'text/html',
                        'body': {
                            'data': 'PGh0bWw+VGVzdDwvaHRtbD4='
                        }
                    }
                ]
            }
        }

        parsed_email = self.client._parse_email(mock_message)

        self.assertEqual(parsed_email['message_body'], 'Test body')
        self.assertTrue(parsed_email['is_read'])  # No UNREAD label

    def test_mark_as_read(self):
        """Test mark as read functionality."""
        self.client.mark_as_read('test_message_id')

        self.mock_service.users().messages().modify.assert_called_once()
        call_args = self.mock_service.users().messages().modify.call_args

        self.assertEqual(call_args[1]['userId'], 'me')
        self.assertEqual(call_args[1]['id'], 'test_message_id')
        self.assertEqual(call_args[1]['body']['removeLabelIds'], ['UNREAD'])

    def test_mark_as_unread(self):
        """Test mark as unread functionality."""
        self.client.mark_as_unread('test_message_id')

        self.mock_service.users().messages().modify.assert_called_once()
        call_args = self.mock_service.users().messages().modify.call_args

        self.assertEqual(call_args[1]['userId'], 'me')
        self.assertEqual(call_args[1]['id'], 'test_message_id')
        self.assertEqual(call_args[1]['body']['addLabelIds'], ['UNREAD'])


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system."""

    def setUp(self):
        """Set up integration test environment."""
        # Create temporary files
        self.test_db = tempfile.NamedTemporaryFile(delete=False)
        self.test_db.close()

        self.test_rules_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump({
            "rules": [{
                "name": "Test Rule",
                "predicate": "Any",
                "conditions": [{
                    "field": "from",
                    "predicate": "contains",
                    "value": "test"
                }],
                "actions": [{
                    "type": "mark as read"
                }]
            }]
        }, self.test_rules_file)
        self.test_rules_file.close()

        # Mock Gmail client
        self.mock_gmail_client = Mock()

    def tearDown(self):
        """Clean up test files."""
        os.unlink(self.test_db.name)
        os.unlink(self.test_rules_file.name)

    def test_full_workflow(self):
        """Test the complete workflow from database to rule processing."""
        # Initialize components
        database = EmailDatabase(self.test_db.name)
        processor = EmailRuleProcessor(
            rules_file=self.test_rules_file.name,
            gmail_client=self.mock_gmail_client
        )

        # Sample email data
        test_emails = [{
            'id': 'test_email',
            'thread_id': 'test_thread',
            'from_email': 'test@example.com',
            'to_email': 'user@example.com',
            'subject': 'Test Email',
            'date_received': 'Mon, 1 Jan 2024 10:00:00 +0000',
            'message_body': 'Test content',
            'labels': ['INBOX'],
            'is_read': False
        }]

        # Store emails in database
        database.store_emails(test_emails)

        # Retrieve emails from database
        stored_emails = database.get_emails()
        self.assertEqual(len(stored_emails), 1)

        # Process emails with rules
        processor.process_emails(stored_emails)

        # Verify action was called
        self.mock_gmail_client.mark_as_read.assert_called_once_with('test_email')


class TestErrorHandling(unittest.TestCase):
    """Test error handling scenarios."""

    def test_missing_rules_file(self):
        """Test handling of missing rules file."""
        processor = EmailRuleProcessor(rules_file='nonexistent_file.json')
        self.assertEqual(processor.rules, {'rules': []})

    def test_invalid_date_format(self):
        """Test handling of invalid date formats."""
        processor = EmailRuleProcessor()

        result = processor.evaluate_date_condition(
            'invalid_date_format', 'less than', '2 days'
        )
        self.assertFalse(result)

    def test_invalid_rule_structure(self):
        """Test handling of malformed rules."""
        processor = EmailRuleProcessor()

        # Rule with missing conditions
        malformed_rule = {
            'name': 'Broken Rule',
            'actions': [{'type': 'mark as read'}]
        }

        test_email = {
            'id': 'test',
            'from_email': 'test@example.com',
            'subject': 'Test'
        }

        result = processor.evaluate_rule(test_email, malformed_rule)
        self.assertFalse(result)


def run_tests():
    """Run all tests with detailed output."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    test_classes = [
        TestEmailDatabase,
        TestEmailRuleProcessor,
        TestDateConditions,
        TestGmailAPIClientMocked,
        TestIntegration,
        TestErrorHandling
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print(f"\nTest Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")

    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)