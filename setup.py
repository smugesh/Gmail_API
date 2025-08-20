#!/usr/bin/env python3
"""
Setup script for Gmail API Email Processor

This script helps set up the development environment and install dependencies.
"""

import os
import sys
import subprocess
import json
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required.")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version}")
    return True


def install_requirements():
    """Install required packages from requirements.txt."""
    try:
        print("📦 Installing Python dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False


def check_credentials():
    """Check if credentials.json exists and is valid."""
    credentials_file = "credentials.json"

    if not os.path.exists(credentials_file):
        print(f"⚠️  Warning: {credentials_file} not found")
        print("   You need to:")
        print("   1. Go to Google Cloud Console (https://console.cloud.google.com/)")
        print("   2. Create a project and enable Gmail API")
        print("   3. Create OAuth 2.0 credentials")
        print("   4. Download the credentials file as 'credentials.json'")
        return False

    try:
        with open(credentials_file, 'r') as f:
            creds = json.load(f)

        if 'installed' in creds and 'client_id' in creds['installed']:
            print("✅ credentials.json found and appears valid")
            return True
        else:
            print("❌ credentials.json exists but format appears incorrect")
            return False
    except json.JSONDecodeError:
        print("❌ credentials.json exists but is not valid JSON")
        return False


def create_default_rules():
    """Create default rules.json if it doesn't exist."""
    rules_file = "rules.json"

    if os.path.exists(rules_file):
        print("✅ rules.json already exists")
        return True

    default_rules = {
        "rules": [
            {
                "name": "Newsletter Auto-Read",
                "description": "Mark newsletters as read automatically",
                "predicate": "Any",
                "conditions": [
                    {
                        "field": "from",
                        "predicate": "contains",
                        "value": "newsletter"
                    },
                    {
                        "field": "subject",
                        "predicate": "contains",
                        "value": "unsubscribe"
                    }
                ],
                "actions": [
                    {
                        "type": "mark as read"
                    }
                ]
            },
            {
                "name": "Important Emails",
                "description": "Handle important emails from specific senders",
                "predicate": "Any",
                "conditions": [
                    {
                        "field": "subject",
                        "predicate": "contains",
                        "value": "URGENT"
                    },
                    {
                        "field": "subject",
                        "predicate": "contains",
                        "value": "IMPORTANT"
                    }
                ],
                "actions": [
                    {
                        "type": "mark as unread"
                    }
                ]
            }
        ]
    }

    try:
        with open(rules_file, 'w') as f:
            json.dump(default_rules, f, indent=2)
        print(f"✅ Created default {rules_file}")
        return True
    except Exception as e:
        print(f"❌ Error creating {rules_file}: {e}")
        return False


def run_tests():
    """Run the test suite to verify installation."""
    try:
        print("🧪 Running tests to verify installation...")
        result = subprocess.run([sys.executable, "test_email_processor.py"],
                                capture_output=True, text=True)

        if result.returncode == 0:
            print("✅ All tests passed!")
            return True
        else:
            print("❌ Some tests failed:")
            print(result.stdout)
            print(result.stderr)
            return False
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return False


def display_next_steps():
    """Display next steps for the user."""
    print("\n" + "=" * 50)
    print("🎉 Setup Complete!")
    print("=" * 50)
    print("\n📋 Next Steps:")
    print("1. Ensure you have credentials.json in the project directory")
    print("2. Review and customize rules.json for your needs")
    print("3. Run the application: python main.py")
    print("\n📖 For detailed instructions, see README.md")
    print("\n🔧 Useful Commands:")
    print("   • Run application:     python main.py")
    print("   • Run tests:          python test_email_processor.py")
    print("   • Update dependencies: pip install -r requirements.txt --upgrade")


def main():
    """Main setup function."""
    print("🚀 Gmail API Email Processor Setup")
    print("=" * 40)

    steps = [
        ("Checking Python version", check_python_version),
        ("Installing dependencies", install_requirements),
        ("Checking credentials", check_credentials),
        ("Creating default rules", create_default_rules),
        ("Running tests", run_tests)
    ]

    failed_steps = []

    for step_name, step_func in steps:
        print(f"\n📋 {step_name}...")
        try:
            if not step_func():
                failed_steps.append(step_name)
        except Exception as e:
            print(f"❌ Error in {step_name}: {e}")
            failed_steps.append(step_name)

    print("\n" + "=" * 50)
    print("📊 Setup Summary")
    print("=" * 50)

    if failed_steps:
        print(f"❌ Failed steps: {', '.join(failed_steps)}")
        print("⚠️  Please resolve the above issues before running the application")
        return False
    else:
        print("✅ All setup steps completed successfully!")
        display_next_steps()
        return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)