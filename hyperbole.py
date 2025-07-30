#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
import sys
import subprocess
import datetime
import shutil
import logging
import hashlib
import zipfile
import tarfile

# Hyperbole is the official build script for XLESS.
# Available environment variables for controlling the build:
#   - HY_APP_VERSION: App version
#   - HY_APP_COMMIT: App commit hash
#   - HY_APP_PLATFORMS: Platforms to build for (e.g. "windows/amd64,linux/arm")
#   - HY_API_POST_KEY: API key for publishing updates

# Configure logging
def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

setup_logging()

LOGO = """
 __   __  __       __
|  \ |  ||  |     |  |
|   \|  ||  |     |  |
| |\ \  ||  |     |  |
| | \ \ ||  |____ |  |____
|_|  \_|||_______||_______|
"""

DESC = "Hyperbole is the official build script for XLESS."

# --- Configuration ---
BUILD_CONFIG = {
    "BUILD_DIR": "build",
    "CORE_SRC_DIR": "./core",
    "EXTRAS_SRC_DIR": "./extras",
    "APP_SRC_DIR": "./app",
    "APP_SRC_CMD_PKG": "github.com/XLESSGo/XLESS/app/cmd",
    "MODULE_SRC_DIRS": ["./core", "./extras", "./app"],
    "ARCH_ALIASES": {
        "arm": {"GOARCH": "arm", "GOARM": "7"},
        "armv5": {"GOARCH": "arm", "GOARM": "5"},
        "armv6": {"GOARCH": "arm", "GOARM": "6"},
        "armv7": {"GOARCH": "arm", "GOARM": "7"},
        "mips": {"GOARCH": "mips", "GOMIPS": ""},
        "mipsle": {"GOARCH": "mipsle", "GOMIPS": ""},
        "mips-sf": {"GOARCH": "mips", "GOMIPS": "softfloat"},
        "mipsle-sf": {"GOARCH": "mipsle", "GOMIPS": "softfloat"},
        "amd64": {"GOARCH": "amd64", "GOAMD64": ""},
        "amd64-avx": {"GOARCH": "amd64", "GOAMD64": "v3"},
        "loong64": {"GOARCH": "loong64"},
    },
    "DEFAULT_PLATFORMS": [], # Will be populated by get_current_os_arch
    "PUBLISH_API_URL": "https://api.xl2.io/v1/update",
}

# Helper to run shell commands
def run_command(cmd, cwd=None, env=None, capture_output=False, check=True, **kwargs):
    """
    Runs a shell command.
    :param cmd: List of command arguments.
    :param cwd: Working directory.
    :param env: Environment variables.
    :param capture_output: If True, returns stdout and stderr.
    :param check: If True, raises CalledProcessError on non-zero exit code.
    :return: CompletedProcess object or None.
    """
    logging.debug(f"Running command: {' '.join(cmd)} in {cwd if cwd else os.getcwd()}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=capture_output,
            text=True, # Decode stdout/stderr as text
            check=check,
            **kwargs
        )
        if capture_output:
            return result
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with exit code {e.returncode}: {' '.join(cmd)}")
        if e.stdout:
            logging.error(f"STDOUT:\n{e.stdout}")
        if e.stderr:
            logging.error(f"STDERR:\n{e.stderr}")
        if check:
            sys.exit(e.returncode)
        return False
    except FileNotFoundError:
        logging.error(f"Command not found: '{cmd[0]}'. Please ensure it's installed and in your PATH.")
        if check:
            sys.exit(1)
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred while running command '{cmd[0]}': {e}")
        if check:
            sys.exit(1)
        return False


def check_command_exists(cmd_args):
    """Checks if a command exists and is executable."""
    try:
        run_command(cmd_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def get_go_env(var_name):
    """Fetches a Go environment variable."""
    try:
        result = run_command(["go", "env", var_name], capture_output=True)
        return result.stdout.strip()
    except Exception:
        logging.warning(f"Could not get Go environment variable: {var_name}")
        return "Unknown"

def check_build_env():
    """Checks for necessary build tools."""
    if not check_command_exists(["git", "--version"]):
        logging.error("Git is not installed. Please install Git and try again.")
        return False
    if not check_command_exists(["git", "rev-parse", "--is-inside-work-tree"]):
        logging.error("Not in a Git repository. Please go to the project root and try again.")
        return False
    if not check_command_exists(["go", "version"]):
        logging.error("Go is not installed. Please install Go and try again.")
        return False
    return True


def get_app_version():
    """Determines the application version."""
    app_version = os.environ.get("HY_APP_VERSION")
    if not app_version:
        try:
            # Prefer git tag for version
            output = run_command(
                ["git", "describe", "--tags", "--always", "--match", "app/v*"],
                capture_output=True
            ).stdout.strip()
            app_version = output.split("/")[-1]
        except Exception:
            logging.warning("Could not determine app version from Git. Using 'Unknown'.")
            app_version = "Unknown"
    return app_version


def get_app_version_code(version_str=None):
    """Generates a numeric version code from a version string (e.g., v1.2.3 -> 010203)."""
    if not version_str:
        version_str = get_app_version()

    match = re.search(r"v(\d+)\.(\d+)\.(\d+)", version_str)
    if match:
        major, minor, patch = match.groups()
        # Pad with zeros and take first 2 digits to ensure 6-digit code
        major = major.zfill(2)[:2]
        minor = minor.zfill(2)[:2]
        patch = patch.zfill(2)[:2]
        return int(f"{major}{minor}{patch}")
    else:
        logging.warning(f"Could not parse version string '{version_str}' for version code. Returning 0.")
        return 0


def get_app_commit():
    """Gets the current Git commit hash."""
    app_commit = os.environ.get("HY_APP_COMMIT")
    if not app_commit:
        try:
            app_commit = run_command(["git", "rev-parse", "HEAD"], capture_output=True).stdout.strip()
        except Exception:
            logging.warning("Could not determine app commit from Git. Using 'Unknown'.")
            app_commit = "Unknown"
    return app_commit


def get_toolchain():
    """Gets the Go toolchain version."""
    output = get_go_env("version")
    if output.startswith("go version "):
        output = output[11:]
    return output


def get_current_os_arch():
    """Gets the current OS and architecture from Go environment."""
    d_os = get_go_env("GOOS")
    d_arch = get_go_env("GOARCH")
    return (d_os, d_arch)


def get_lib_version():
    """Attempts to get the version of a specific library from go.mod."""
    try:
        with open(BUILD_CONFIG["CORE_SRC_DIR"] + "/go.mod") as f:
            for line in f:
                line = line.strip()
                # This dependency is not part of the project name change
                if line.startswith("github.com/apernet/quic-go"):
                    return line.split(" ")[1].strip()
    except Exception as e:
        logging.warning(f"Could not get library version from go.mod: {e}. Using 'Unknown'.")
    return "Unknown"


def get_app_platforms():
    """Determines target platforms from environment or defaults."""
    platforms_env = os.environ.get("HY_APP_PLATFORMS")
    if platforms_env:
        result = []
        for platform in platforms_env.split(","):
            platform = platform.strip()
            if not platform:
                continue
            parts = platform.split("/")
            if len(parts) != 2:
                logging.warning(f"Invalid platform format: '{platform}'. Skipping.")
                continue
            result.append((parts[0], parts[1]))
        return result
    else:
        # Default to current OS/Arch if no platforms are specified
        if not BUILD_CONFIG["DEFAULT_PLATFORMS"]:
            BUILD_CONFIG["DEFAULT_PLATFORMS"] = [get_current_os_arch()]
        return BUILD_CONFIG["DEFAULT_PLATFORMS"]


# --- Commands ---

def cmd_deps():
    """Downloads Go module dependencies."""
    if not check_build_env():
        return

    logging.info("Downloading Go module dependencies...")
    for dir in BUILD_CONFIG["MODULE_SRC_DIRS"]:
        logging.info(f"Downloading dependencies for {dir}...")
        try:
            run_command(["go", "mod", "download"], cwd=dir)
            logging.info(f"Dependencies for {dir} downloaded successfully.")
        except Exception:
            logging.error(f"Failed to download dependencies for {dir}.")
            sys.exit(1)


def cmd_lint():
    """Runs Go linting tools."""
    if not check_build_env():
        return

    logging.info("Running Go linting tools...")

    # Run go vet
    logging.info("Running go vet...")
    try:
        run_command(["go", "vet", "./..."], cwd=BUILD_CONFIG["APP_SRC_DIR"])
        logging.info("go vet completed.")
    except Exception:
        logging.error("go vet failed.")
        sys.exit(1)

    # Run golangci-lint if available
    if check_command_exists(["golangci-lint", "--version"]):
        logging.info("Running golangci-lint...")
        try:
            # Use a specific config file if it exists, otherwise default
            lint_cmd = ["golangci-lint", "run", "./..."]
            if os.path.exists(".golangci.yml"):
                lint_cmd.extend(["--config", ".golangci.yml"])
            run_command(lint_cmd, cwd=BUILD_CONFIG["APP_SRC_DIR"])
            logging.info("golangci-lint completed.")
        except Exception:
            logging.error("golangci-lint failed.")
            sys.exit(1)
    else:
        logging.warning("golangci-lint not found. Skipping linting with golangci-lint. Install with 'go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest'.")


def cmd_build(pprof=False, release=False, race=False):
    """Builds the XLESS application for specified platforms."""
    if not check_build_env():
        return

    os.makedirs(BUILD_CONFIG["BUILD_DIR"], exist_ok=True)

    app_version = get_app_version()
    app_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    app_toolchain = get_toolchain()
    app_commit = get_app_commit()
    lib_version = get_lib_version()

    base_ldflags = [
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appVersion={app_version}",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appDate={app_date}",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appType={'release' if release else 'dev'}{'-pprof' if pprof else ''}",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appToolchain={app_toolchain}",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appCommit={app_commit}",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.libVersion={lib_version}",
    ]
    if release:
        base_ldflags.extend(["-s", "-w"]) # Strip debug info and symbol table

    for os_name, arch in get_app_platforms():
        logging.info(f"Building for {os_name}/{arch}...")

        out_name = f"xless-{os_name}-{arch}"
        if os_name == "windows":
            out_name += ".exe"

        env = os.environ.copy()
        env["GOOS"] = os_name
        
        # Apply architecture aliases
        if arch in BUILD_CONFIG["ARCH_ALIASES"]:
            for k, v in BUILD_CONFIG["ARCH_ALIASES"][arch].items():
                env[k] = v
        else:
            env["GOARCH"] = arch

        # CGO_ENABLED handling
        if os_name == "android":
            env["CGO_ENABLED"] = "1"
            android_ndk_home = os.environ.get("ANDROID_NDK_HOME")
            if not android_ndk_home:
                logging.error("ANDROID_NDK_HOME environment variable is not set. Cannot build for Android.")
                sys.exit(1)
            
            ndk_toolchain_path = os.path.join(android_ndk_home, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin")
            
            if arch == "arm64":
                env["CC"] = os.path.join(ndk_toolchain_path, "aarch64-linux-android29-clang")
            elif arch == "armv7":
                env["CC"] = os.path.join(ndk_toolchain_path, "armv7a-linux-androideabi29-clang")
            elif arch == "386":
                env["CC"] = os.path.join(ndk_toolchain_path, "i686-linux-android29-clang")
            elif arch == "amd64":
                env["CC"] = os.path.join(ndk_toolchain_path, "x86_64-linux-android29-clang")
            else:
                logging.error(f"Unsupported arch for Android: {arch}")
                continue # Skip this platform
            
            if not os.path.exists(env["CC"]):
                logging.error(f"Android NDK compiler not found at {env['CC']}. Please check your ANDROID_NDK_HOME or NDK installation.")
                sys.exit(1)
        else:
            env["CGO_ENABLED"] = "1" if race else "0"  # Race detector requires cgo

        plat_ldflags = base_ldflags.copy()
        plat_ldflags.extend([
            "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appPlatform={os_name}",
            "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appArch={arch}",
        ])

        cmd = [
            "go", "build",
            "-o", os.path.join(BUILD_CONFIG["BUILD_DIR"], out_name),
            "-ldflags", " ".join(plat_ldflags),
        ]
        if pprof:
            cmd.extend(["-tags", "pprof"])
        if race:
            cmd.append("-race")
        if release:
            cmd.append("-trimpath") # Remove all file system paths from the compiled executable.
        cmd.append(BUILD_CONFIG["APP_SRC_DIR"])

        if run_command(cmd, env=env):
            logging.info(f"Successfully built {out_name}")
        else:
            logging.error(f"Failed to build for {os_name}/{arch}. See logs above for details.")
            sys.exit(1)


def cmd_run(args, pprof=False, race=False):
    """Runs the XLESS application directly from source."""
    if not check_build_env():
        return

    app_version = get_app_version()
    app_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    app_toolchain = get_toolchain()
    app_commit = get_app_commit()
    lib_version = get_lib_version()

    current_os, current_arch = get_current_os_arch()

    ldflags = [
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appVersion={app_version}",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appDate={app_date}",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appType=dev-run",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appToolchain={app_toolchain}",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appCommit={app_commit}",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appPlatform={current_os}",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.appArch={current_arch}",
        "-X", f"{BUILD_CONFIG['APP_SRC_CMD_PKG']}.libVersion={lib_version}",
    ]

    env = os.environ.copy()
    env["CGO_ENABLED"] = "1" if race else "0" # Race detector requires cgo

    cmd = ["go", "run", "-ldflags", " ".join(ldflags)]
    if pprof:
        cmd.extend(["-tags", "pprof"])
    if race:
        cmd.append("-race")
    cmd.append(BUILD_CONFIG["APP_SRC_DIR"])
    cmd.extend(args)

    logging.info(f"Running XLESS: {' '.join(cmd)}")
    try:
        run_command(cmd, env=env, check=False) # Allow run to exit with app's exit code
    except KeyboardInterrupt:
        logging.info("XLESS stopped by user (Ctrl+C).")
    except Exception as e:
        logging.error(f"Error running XLESS: {e}")


def cmd_format():
    """Formats Go code using gofumpt."""
    if not check_command_exists(["gofumpt", "-version"]):
        logging.error("gofumpt is not installed. Please install gofumpt and try again.")
        return

    logging.info("Formatting code with gofumpt...")
    try:
        run_command(["gofumpt", "-w", "-l", "-extra", "."])
        logging.info("Code formatted successfully.")
    except Exception:
        logging.error("Failed to format code.")
        sys.exit(1)


def cmd_mockgen():
    """Generates mock interfaces using mockery."""
    if not check_command_exists(["mockery", "--version"]):
        logging.error("mockery is not installed. Please install mockery and try again.")
        return

    logging.info("Generating mock interfaces...")
    for dirpath, dirnames, filenames in os.walk("."):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")] # Exclude hidden dirs
        if ".mockery.yaml" in filenames:
            logging.info(f"Generating mocks for {dirpath}...")
            try:
                run_command(["mockery"], cwd=dirpath)
                logging.info(f"Mocks for {dirpath} generated successfully.")
            except Exception:
                logging.error(f"Failed to generate mocks for {dirpath}.")
                sys.exit(1)


def cmd_protogen():
    """Generates protobuf code using protoc."""
    if not check_command_exists(["protoc", "--version"]):
        logging.error("protoc is not installed. Please install protoc and try again.")
        return

    logging.info("Generating protobuf interfaces...")
    for dirpath, dirnames, filenames in os.walk("."):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")] # Exclude hidden dirs
        proto_files = [f for f in filenames if f.endswith(".proto")]

        if len(proto_files) > 0:
            for proto_file in proto_files:
                logging.info(f"Generating protobuf for {os.path.join(dirpath, proto_file)}...")
                try:
                    run_command(
                        ["protoc", "--go_out=paths=source_relative:.", proto_file],
                        cwd=dirpath,
                    )
                    logging.info(f"Protobuf for {proto_file} generated successfully.")
                except Exception:
                    logging.error(f"Failed to generate protobuf for {proto_file}.")
                    sys.exit(1)


def cmd_tidy():
    """Tidies Go modules and syncs go.work."""
    if not check_build_env():
        return

    logging.info("Tidying Go modules...")
    for dir in BUILD_CONFIG["MODULE_SRC_DIRS"]:
        logging.info(f"Tidying {dir}...")
        try:
            run_command(["go", "mod", "tidy"], cwd=dir)
            logging.info(f"Successfully tidied {dir}.")
        except Exception:
            logging.error(f"Failed to tidy {dir}.")
            sys.exit(1)

    logging.info("Syncing go work...")
    try:
        run_command(["go", "work", "sync"])
        logging.info("go work synced successfully.")
    except Exception:
        logging.error("Failed to sync go work.")
        sys.exit(1)


def cmd_test(module=None):
    """Runs tests for specified Go modules or all modules."""
    if not check_build_env():
        return

    if module:
        if module not in BUILD_CONFIG["MODULE_SRC_DIRS"]:
            logging.error(f"Unknown module: {module}. Available modules: {', '.join(BUILD_CONFIG['MODULE_SRC_DIRS'])}")
            sys.exit(1)
        logging.info(f"Testing {module}...")
        try:
            run_command(["go", "test", "-v", "./..."], cwd=module)
            logging.info(f"Tests for {module} passed.")
        except Exception:
            logging.error(f"Tests for {module} failed.")
            sys.exit(1)
    else:
        logging.info("Testing all Go modules...")
        for dir in BUILD_CONFIG["MODULE_SRC_DIRS"]:
            logging.info(f"Testing {dir}...")
            try:
                run_command(["go", "test", "-v", "./..."], cwd=dir)
                logging.info(f"Tests for {dir} passed.")
            except Exception:
                logging.error(f"Tests for {dir} failed.")
                sys.exit(1)


def cmd_package():
    """Packages built binaries into archives and generates checksums."""
    if not os.path.exists(BUILD_CONFIG["BUILD_DIR"]) or not os.listdir(BUILD_CONFIG["BUILD_DIR"]):
        logging.warning(f"Build directory '{BUILD_CONFIG['BUILD_DIR']}' is empty or does not exist. Please run 'build' first.")
        return

    logging.info("Packaging built binaries...")
    app_version = get_app_version()
    package_name_base = f"xless-{app_version}"
    
    # Create archives for each built binary
    for filename in os.listdir(BUILD_CONFIG["BUILD_DIR"]):
        file_path = os.path.join(BUILD_CONFIG["BUILD_DIR"], filename)
        if os.path.isfile(file_path) and not filename.endswith((".zip", ".tar.gz", ".sha256")):
            base_filename, _ = os.path.splitext(filename)
            
            # Create .zip archive for Windows
            if "windows" in filename:
                zip_filename = os.path.join(BUILD_CONFIG["BUILD_DIR"], f"{base_filename}.zip")
                logging.info(f"Creating zip archive: {zip_filename}")
                with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zf:
                    zf.write(file_path, arcname=filename)
            # Create .tar.gz archive for Linux/macOS
            else:
                tar_filename = os.path.join(BUILD_CONFIG["BUILD_DIR"], f"{base_filename}.tar.gz")
                logging.info(f"Creating tar.gz archive: {tar_filename}")
                with tarfile.open(tar_filename, 'w:gz') as tf:
                    tf.add(file_path, arcname=filename)

    # Generate SHA256 checksums for all archives and binaries
    checksum_file_path = os.path.join(BUILD_CONFIG["BUILD_DIR"], f"{package_name_base}-checksums.sha256")
    logging.info(f"Generating SHA256 checksums to {checksum_file_path}...")
    with open(checksum_file_path, 'w') as f_checksum:
        for filename in os.listdir(BUILD_CONFIG["BUILD_DIR"]):
            file_path = os.path.join(BUILD_CONFIG["BUILD_DIR"], filename)
            if os.path.isfile(file_path) and not filename.endswith(".sha256"):
                sha256_hash = hashlib.sha256()
                with open(file_path, "rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                f_checksum.write(f"{sha256_hash.hexdigest()}  {filename}\n")
    logging.info("Packaging complete.")


def cmd_publish(urgent=False):
    """Publishes the current version to the update API."""
    try:
        import requests
    except ImportError:
        logging.error("The 'requests' library is required for publishing. Please install it with 'pip install requests'.")
        return

    if not check_build_env():
        return

    app_version = get_app_version()
    app_version_code = get_app_version_code(app_version)
    if app_version_code == 0:
        logging.error("Invalid app version. Cannot publish.")
        return

    api_key = os.environ.get("HY_API_POST_KEY") # Reverted to HY_API_POST_KEY
    if not api_key:
        logging.error("HY_API_POST_KEY environment variable is not set. Cannot publish.")
        return

    payload = {
        "code": app_version_code,
        "ver": app_version,
        "chan": "release",
        "url": "https://github.com/XLESSGo/XLESS/releases",
        "urgent": urgent,
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": api_key,
    }

    logging.info(f"Publishing version {app_version} (code: {app_version_code}, urgent: {urgent})...")
    try:
        resp = requests.post(BUILD_CONFIG["PUBLISH_API_URL"], json=payload, headers=headers, timeout=10)
        resp.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        logging.info(f"Successfully published version {app_version}.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to publish {app_version}. Error: {e}")
        if resp:
            logging.error(f"Status Code: {resp.status_code}")
            logging.error(f"Response: {resp.text}")
        sys.exit(1)


def cmd_clean():
    """Cleans the build directory."""
    logging.info(f"Cleaning build directory: {BUILD_CONFIG['BUILD_DIR']}...")
    try:
        shutil.rmtree(BUILD_CONFIG["BUILD_DIR"], ignore_errors=True)
        logging.info("Build directory cleaned.")
    except Exception as e:
        logging.error(f"Failed to clean build directory: {e}")


def cmd_about():
    """Prints about information."""
    print(LOGO)
    print(DESC)


def main():
    parser = argparse.ArgumentParser(description=DESC)

    p_cmd = parser.add_subparsers(dest="command")
    p_cmd.required = True

    # Run
    p_run = p_cmd.add_parser("run", help="Run the XLESS application directly from source for development.")
    p_run.add_argument(
        "-p", "--pprof", action="store_true", help="Run with pprof enabled for profiling."
    )
    p_run.add_argument(
        "-d", "--race", action="store_true", help="Run with Go data race detection enabled."
    )
    p_run.add_argument("args", nargs=argparse.REMAINDER, help="Arguments to pass to the XLESS application.")

    # Build
    p_build = p_cmd.add_parser("build", help="Build the XLESS application for various platforms.")
    p_build.add_argument(
        "-p", "--pprof", action="store_true", help="Build with pprof enabled for profiling."
    )
    p_build.add_argument(
        "-r", "--release", action="store_true", help="Build a release version (strips debug info, optimizes)."
    )
    p_build.add_argument(
        "-d", "--race", action="store_true", help="Build with Go data race detection enabled."
    )

    # Format
    p_cmd.add_parser("format", help="Format the Go source code using gofumpt.")

    # Mockgen
    p_cmd.add_parser("mockgen", help="Generate mock interfaces using mockery (requires .mockery.yaml files).")

    # Protogen
    p_cmd.add_parser("protogen", help="Generate protobuf code from .proto files using protoc.")

    # Tidy
    p_cmd.add_parser("tidy", help="Tidy Go modules (go mod tidy) and sync go.work file.")

    # Test
    p_test = p_cmd.add_parser("test", help="Run tests for specified Go modules or all modules.")
    p_test.add_argument("module", nargs="?", help="Optional: specific module to test (e.g., 'core', 'app'). If omitted, all modules are tested.")

    # Deps
    p_cmd.add_parser("deps", help="Download Go module dependencies.")

    # Lint
    p_cmd.add_parser("lint", help="Run Go static analysis tools (go vet, golangci-lint).")

    # Package
    p_cmd.add_parser("package", help="Package built binaries into archives (zip/tar.gz) and generate SHA256 checksums.")

    # Publish
    p_pub = p_cmd.add_parser("publish", help="Publish the current version to the update API.")
    p_pub.add_argument(
        "-u", "--urgent", action="store_true", help="Mark the update as urgent."
    )

    # Clean
    p_cmd.add_parser("clean", help="Clean the build directory.")

    # About
    p_cmd.add_parser("about", help="Print about information for Hyperbole.")

    args = parser.parse_args()

    if args.command == "run":
        cmd_run(args.args, args.pprof, args.race)
    elif args.command == "build":
        cmd_build(args.pprof, args.release, args.race)
    elif args.command == "format":
        cmd_format()
    elif args.command == "mockgen":
        cmd_mockgen()
    elif args.command == "protogen":
        cmd_protogen()
    elif args.command == "tidy":
        cmd_tidy()
    elif args.command == "test":
        cmd_test(args.module)
    elif args.command == "deps":
        cmd_deps()
    elif args.command == "lint":
        cmd_lint()
    elif args.command == "package":
        cmd_package()
    elif args.command == "publish":
        cmd_publish(args.urgent)
    elif args.command == "clean":
        cmd_clean()
    elif args.command == "about":
        cmd_about()


if __name__ == "__main__":
    main()
