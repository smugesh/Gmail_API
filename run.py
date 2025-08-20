#!/usr/bin/env python3
"""
Gmail API Email Processor Runner

This script provides a command-line interface for running the email processor
with various options and configurations.
"""

import argparse
import sys
import os
import logging
from main import main as run_main_app


def setup_logging(level):
    """Configure logging based on user preference."""
    log_levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR
    }

    logging.basicConfig(
        level=log_levels.get(level.upper(), logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('email_processor.log')
        ]
    )


def validate_files():
    """Validate that required files exist."""
    required_files = ['credentials.json', 'rules.json']
    missing_files = []

    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)

    if missing_files:
        print(f"❌ Missing required files: {', '.join(missing_files)}")
        print("Run 'python setup.py' to initialize the project")
        return False

    return True


def main():
    """Main function with command-line interface."""
    parser = argparse.ArgumentParser(
        description='Gmail API Email Processor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                          # Run with default settings
  python run.py --log-level DEBUG        # Run with debug logging
  python run.py --max-emails 200         # Fetch more emails
  python run.py --dry-run                # Test mode without actions
        """
    )

    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )

    parser.add_argument(
        '--max-emails',
        type=int,
        default=100,
        help='Maximum number of emails to fetch (default: 100)'
    )

    parser.add_argument(
        '--rules-file',
        default='rules.json',
        help='Path to rules configuration file (default: rules.json)'
    )

    parser.add_argument(
        '--database',
        default='emails.db',
        help='Path to SQLite database file (default: emails.db)'
    )

    parser.add_argument(
        '--query',
        default='in:inbox',
        help='Gmail search query (default: in:inbox)'
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    # Validate required files
    if not validate_files():
        sys.exit(1)

    # Display configuration
    print("🚀 Gmail API Email Processor")
    print("=" * 40)
    print(f"Log Level:     {args.log_level}")
    print(f"Max Emails:    {args.max_emails}")
    print(f"Rules File:    {args.rules_file}")
    print(f"Database:      {args.database}")
    print(f"Query:         {args.query}")
    print("=" * 40)

    try:

        # Set environment variables for configuration
        os.environ['EMAIL_PROCESSOR_MAX_EMAILS'] = str(args.max_emails)
        os.environ['EMAIL_PROCESSOR_RULES_FILE'] = args.rules_file
        os.environ['EMAIL_PROCESSOR_DATABASE'] = args.database
        os.environ['EMAIL_PROCESSOR_QUERY'] = args.query

        # Run the main application
        logger.info("Starting Gmail API Email Processor...")
        run_main_app()
        logger.info("Email processing completed successfully")

    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
        print("\n👋 Process interrupted. Goodbye!")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Application error: {e}")
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()