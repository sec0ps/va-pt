"""Administrative CLI for user and workspace management."""

import os
import sys

_venv_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv")
_venv_python = os.path.join(_venv_dir, "bin", "python")
if os.path.exists(_venv_python) and os.path.abspath(sys.prefix) != os.path.abspath(_venv_dir):
    os.execv(_venv_python, [_venv_python] + sys.argv)

import argparse
import getpass

import db
from config import Config
from console.auth import hash_password


def _ensure():
    Config().ensure_dirs()
    db.init_db()


def cmd_create_admin(args):
    _ensure()
    if db.get_user_by_username(args.username):
        print("user already exists")
        return 1
    password = args.password or getpass.getpass("password: ")
    if not password:
        print("password required")
        return 1
    db.create_user(args.username, hash_password(password), "admin")
    print("created admin %s" % args.username)
    return 0


def cmd_create_user(args):
    _ensure()
    if args.role not in ("admin", "operator"):
        print("role must be admin or operator")
        return 1
    if db.get_user_by_username(args.username):
        print("user already exists")
        return 1
    password = args.password or getpass.getpass("password: ")
    if not password:
        print("password required")
        return 1
    db.create_user(args.username, hash_password(password), args.role)
    print("created %s %s" % (args.role, args.username))
    return 0


def cmd_list_users(args):
    _ensure()
    for user in db.list_users():
        state = "active" if user["active"] else "disabled"
        print("%d\t%s\t%s\t%s" % (user["id"], user["username"], user["role"], state))
    return 0


def cmd_create_workspace(args):
    _ensure()
    if db.get_workspace_by_name(args.name):
        print("workspace already exists")
        return 1
    wid = db.create_workspace(args.name, args.client, None)
    print("created workspace %s id %d" % (args.name, wid))
    return 0


def cmd_assign(args):
    _ensure()
    user = db.get_user_by_username(args.username)
    if user is None:
        print("no such user")
        return 1
    workspace = db.get_workspace_by_name(args.workspace)
    if workspace is None:
        print("no such workspace")
        return 1
    db.add_membership(user["id"], workspace["id"])
    print("assigned %s to %s" % (args.username, args.workspace))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description="darkweb recon management")
    sub = parser.add_subparsers(dest="command", required=True)

    admin = sub.add_parser("create-admin", help="create an admin user")
    admin.add_argument("--username", required=True)
    admin.add_argument("--password")
    admin.set_defaults(func=cmd_create_admin)

    user = sub.add_parser("create-user", help="create an operator or admin user")
    user.add_argument("--username", required=True)
    user.add_argument("--password")
    user.add_argument("--role", default="operator")
    user.set_defaults(func=cmd_create_user)

    listing = sub.add_parser("list-users", help="list all users")
    listing.set_defaults(func=cmd_list_users)

    workspace = sub.add_parser("create-workspace", help="create a workspace")
    workspace.add_argument("--name", required=True)
    workspace.add_argument("--client", default=None)
    workspace.set_defaults(func=cmd_create_workspace)

    assign = sub.add_parser("assign", help="assign a user to a workspace")
    assign.add_argument("--username", required=True)
    assign.add_argument("--workspace", required=True)
    assign.set_defaults(func=cmd_assign)

    return parser


def main():
    args = build_parser().parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
