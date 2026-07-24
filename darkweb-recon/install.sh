#!/usr/bin/env bash
# Installer for the darkweb recon research container.
# Installs Docker on the host if missing, then builds the application image.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/install.log"
IMAGE_NAME="darkweb-recon:latest"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

fail() {
    log "ERROR $*"
    exit 1
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        fail "run as root, use sudo ./install.sh"
    fi
}

install_docker() {
    if command -v docker >/dev/null 2>&1; then
        log "docker already present, skipping install"
        return
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        fail "docker is missing and this installer needs apt to bootstrap it, install Docker manually then re-run"
    fi
    log "docker not found, installing via the official convenience script"
    apt-get update >>"${LOG_FILE}" 2>&1 || log "warning apt-get update returned nonzero"
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl >>"${LOG_FILE}" 2>&1 \
        || fail "failed to install curl, see ${LOG_FILE}"
    local script_path="${SCRIPT_DIR}/get-docker.sh"
    curl -fsSL https://get.docker.com -o "${script_path}" \
        || fail "failed to download the docker install script, the host may lack egress to get.docker.com"
    sh "${script_path}" >>"${LOG_FILE}" 2>&1 \
        || fail "the docker install script failed, see ${LOG_FILE}"
    rm -f "${script_path}"
}

start_docker() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable docker >>"${LOG_FILE}" 2>&1 || log "warning could not enable the docker service"
        systemctl start docker >>"${LOG_FILE}" 2>&1 || log "warning could not start the docker service"
    fi
}

verify_docker() {
    docker version >>"${LOG_FILE}" 2>&1 || fail "docker is installed but not responding, check the daemon"
    log "docker is responding"
}

add_docker_group() {
    local target="${SUDO_USER:-}"
    if [ -n "${target}" ] && [ "${target}" != "root" ]; then
        if getent group docker >/dev/null 2>&1; then
            if usermod -aG docker "${target}" >>"${LOG_FILE}" 2>&1; then
                log "added ${target} to the docker group, log out and back in for it to take effect"
            else
                log "warning could not add ${target} to the docker group"
            fi
        fi
    fi
}

build_image() {
    log "building image ${IMAGE_NAME}"
    docker build -t "${IMAGE_NAME}" "${SCRIPT_DIR}" 2>&1 | tee -a "${LOG_FILE}"
    local status="${PIPESTATUS[0]}"
    if [ "${status}" -ne 0 ]; then
        fail "docker build failed with status ${status}, see ${LOG_FILE}"
    fi
    log "image ${IMAGE_NAME} built"
}

main() {
    log "starting darkweb recon install"
    require_root
    install_docker
    start_docker
    verify_docker
    add_docker_group
    build_image
    log "install complete"
    echo ""
    echo "run a manual search"
    echo "    docker run --rm ${IMAGE_NAME} --term \"acme corp breach\" --engagement acme"
    echo ""
    echo "or with persistent tor state via compose"
    echo "    docker compose -f ${SCRIPT_DIR}/docker-compose.yml run --rm recon --term \"acme corp\" --engagement acme"
}

main "$@"
