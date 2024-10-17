#!/usr/bin/env python3.9

import os
import pwd
import subprocess
import sys
import argparse
from loguru import logger


# Helper function to parse arguments provided by the user
def Argparse_Helper():
    parser = argparse.ArgumentParser(
        description="This script reads a username and remote IP, then sets up password-less SSH authentication by generating and copying the SSH key."
    )
    parser.add_argument("user", help="Username for whom the SSH key will be generated")
    parser.add_argument(
        "remote_ip", help="Remote IP of the server where the SSH public key will be copied"
    )
    parser.add_argument("--logfile", help="Optional log file name (default: passwordless_ssh_setup.log)")
    parser.add_argument("--version", action="version", version="%(prog)s 1.1")
    args = parser.parse_args()
    return args


# Function to ensure an SSH key exists, or generate a new one
def ensure_ssh_key(key_path, user):
    """Ensure an SSH key pair exists for the user, generating one if necessary."""
    ssh_dir = os.path.dirname(key_path)

    # Get the user's UID and GID for permission setting
    try:
        user_info = pwd.getpwnam(user)
        uid = user_info.pw_uid
        gid = user_info.pw_gid
    except KeyError:
        logger.error(f"User {user} does not exist.")
        sys.exit(1)

    # Ensure the .ssh directory exists, with proper permissions
    if not os.path.exists(ssh_dir):
        try:
            os.makedirs(ssh_dir, mode=0o700)
            logger.info(f"Created .ssh directory: {ssh_dir}")
            os.chown(ssh_dir, uid, gid)
        except OSError as e:
            logger.error(f"Error creating directory {ssh_dir}: {e}")
            sys.exit(1)

    # Check if SSH key already exists, otherwise generate a new one
    if os.path.exists(key_path):
        logger.info("Using existing SSH key.")
    else:
        try:
            hostname = subprocess.check_output(['hostname']).decode().strip()
            subprocess.run(
                ['ssh-keygen', '-t', 'rsa', '-b', '2048', '-f', key_path, '-N', '', '-C', f'{user}@{hostname}'],
                check=True
            )
            logger.info("SSH key pair generated successfully.")
            # Correct file ownership for generated keys
            for root, dirs, files in os.walk(ssh_dir):
                for file_name in files:
                    os.chown(os.path.join(root, file_name), uid, gid)

        except subprocess.CalledProcessError as e:
            logger.error(f"Error generating SSH key: {e}")
            sys.exit(1)


# Function to copy the public SSH key to the remote server
def copy_public_key(remote_user, remote_host, key_path):
    """Copy the public SSH key to the remote server to enable password-less login."""
    public_key_path = f"{key_path}.pub"

    # Create the .ssh directory on the remote server, if necessary
    try:
        logger.info(f"Ensuring .ssh directory exists on remote server: {remote_host}")
        subprocess.run(
            ['ssh', f"{remote_user}@{remote_host}", '/bin/mkdir -p ~/.ssh && chmod 700 ~/.ssh'],
            check=True, capture_output=True
        )
        logger.info(f".ssh directory created or already exists on {remote_host}.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error creating .ssh directory on remote server: {e}")
        sys.exit(1)

    # Copy the public key to the remote server
    try:
        logger.info(f"Copying public key to remote server: {remote_host}")
        subprocess.run(['ssh-copy-id', '-i', public_key_path, f"{remote_user}@{remote_host}"], check=True)
        logger.info("Public key successfully copied to remote server.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error copying public key to remote server: {e}")
        sys.exit(1)


def main():
    """Main function to set up SSH key-based authentication for a user on a remote server."""
    args = Argparse_Helper()

    # Set up logging
    log_file = args.logfile if args.logfile else "script.log"
    logger.add(log_file, rotation="1 MB", retention="10 days", level="INFO")

    user = args.user
    remote_host = args.remote_ip
    key_path = os.path.expanduser(f'~{user}/.ssh/id_rsa')

    ensure_ssh_key(key_path, user)
    copy_public_key(user, remote_host, key_path)


if __name__ == "__main__":
    main()
