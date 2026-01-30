#!/usr/bin/env python3
"""
Database setup script for rbac-core package.

This script creates the test database and all required tables/indexes
for both PostgreSQL and MongoDB adapters.

Usage:
    python setup_db.py --db-type postgresql --db-name test_rbac_pg --host 192.168.1.8
    python setup_db.py --db-type mongodb --db-name test_rbac_mongo --host 192.168.1.8
"""

import argparse
import sys
from pathlib import Path


def setup_postgresql(host: str, port: int, db_name: str, username: str, password: str):
    """Create PostgreSQL database and tables for rbac-core"""
    try:
        from sqlalchemy import create_engine, text
    except ImportError:
        print("Error: sqlalchemy not installed. Run: pip install sqlalchemy")
        sys.exit(1)

    # Step 1: Create database
    admin_url = f"postgresql://{username}:{password}@{host}:{port}/postgres"

    try:
        engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")

        with engine.connect() as conn:
            # Drop database if exists
            conn.execute(text(f"DROP DATABASE IF EXISTS {db_name}"))
            print(f"  Dropped existing database '{db_name}' (if existed)")

            # Create database
            conn.execute(text(f"CREATE DATABASE {db_name}"))
            print(f"  Created database '{db_name}'")

        engine.dispose()

    except Exception as e:
        print(f"Error creating database: {e}")
        sys.exit(1)

    # Step 2: Create tables
    db_url = f"postgresql://{username}:{password}@{host}:{port}/{db_name}"

    try:
        # Import SQLAlchemy models
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from rbac_core.adapters.repositories.sqlalchemy import Base

        engine = create_engine(db_url)
        Base.metadata.create_all(engine)
        print(f"  Created all tables (roles, policies, role_assignments)")

        engine.dispose()

    except ImportError as e:
        print(f"Error importing models: {e}")
        print("Make sure rbac-core is installed: pip install -e .")
        sys.exit(1)
    except Exception as e:
        print(f"Error creating tables: {e}")
        sys.exit(1)

    print(f"PostgreSQL setup completed successfully for '{db_name}'")


def setup_mongodb(host: str, port: int, db_name: str, username: str, password: str):
    """Create MongoDB database and indexes for rbac-core"""
    try:
        from pymongo import MongoClient
    except ImportError:
        print("Error: pymongo not installed. Run: pip install pymongo")
        sys.exit(1)

    try:
        # Connect to MongoDB
        client = MongoClient(f"mongodb://{username}:{password}@{host}:{port}/")

        # Drop database if exists
        client.drop_database(db_name)
        print(f"  Dropped existing database '{db_name}' (if existed)")

        # Get database reference
        db = client[db_name]

        # Roles collection
        roles_collection = db.roles
        roles_collection.create_index("name", unique=True)
        print(f"  Created unique index on roles.name")

        roles_collection.create_index("created_at")
        print(f"  Created index on roles.created_at")

        # Policies collection
        policies_collection = db.policies
        policies_collection.create_index("name")
        print(f"  Created index on policies.name")

        policies_collection.create_index("subjects")
        print(f"  Created index on policies.subjects")

        policies_collection.create_index("created_at")
        print(f"  Created index on policies.created_at")

        # Role assignments collection
        role_assignments_collection = db.role_assignments
        role_assignments_collection.create_index("subject_id")
        print(f"  Created index on role_assignments.subject_id")

        role_assignments_collection.create_index("role_id")
        print(f"  Created index on role_assignments.role_id")

        role_assignments_collection.create_index([("subject_id", 1), ("role_id", 1)])
        print(f"  Created compound index on role_assignments.subject_id and role_id")

        role_assignments_collection.create_index("assigned_at")
        print(f"  Created index on role_assignments.assigned_at")

        role_assignments_collection.create_index("expires_at")
        print(f"  Created index on role_assignments.expires_at")

        client.close()

    except Exception as e:
        print(f"Error setting up MongoDB: {e}")
        sys.exit(1)

    print(f"MongoDB setup completed successfully for '{db_name}'")


def main():
    parser = argparse.ArgumentParser(
        description='Setup test database for rbac-core',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        '--db-type',
        required=True,
        choices=['postgresql', 'mongodb'],
        help='Database type'
    )

    parser.add_argument(
        '--db-name',
        required=True,
        help='Database name (should start with test_)'
    )

    parser.add_argument(
        '--host',
        required=True,
        help='Database host'
    )

    parser.add_argument(
        '--port',
        type=int,
        help='Database port (default: 5432 for PostgreSQL, 27017 for MongoDB)'
    )

    parser.add_argument(
        '--username',
        default='postgres',
        help='Database username (default: postgres)'
    )

    parser.add_argument(
        '--password',
        default='postgres',
        help='Database password (default: postgres)'
    )

    args = parser.parse_args()

    # Validate database name starts with test_
    if not args.db_name.startswith('test_'):
        print("Error: Database name must start with 'test_' to avoid accidental data loss")
        sys.exit(1)

    # Set default port based on database type
    if args.port is None:
        args.port = 5432 if args.db_type == 'postgresql' else 27017

    print(f"Setting up {args.db_type} database '{args.db_name}' on {args.host}:{args.port}")

    if args.db_type == 'postgresql':
        setup_postgresql(args.host, args.port, args.db_name, args.username, args.password)
    elif args.db_type == 'mongodb':
        setup_mongodb(args.host, args.port, args.db_name, args.username, args.password)


if __name__ == '__main__':
    main()
