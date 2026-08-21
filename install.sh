#!/usr/bin/env bash
#
# Instalador do Inocmon - Sistema de retencao de logs de NAT (Marco Civil, art. 13)
#
# Uso:
#   curl -fsSL https://SEU_DOMINIO/install.sh -o install.sh
#   chmod +x install.sh
#   sudo ./install.sh
#
set -euo pipefail

INSTALL_DIR="/opt/inocmon"
REPO_ZIP_URL="${INOCMON_ZIP_URL:-}"   # opcional: URL de onde baixar o pacote do projeto
COMPOSE_CMD="docker compose"

log()  { echo -e "\033[1;32m[inocmon]\033[0m $1"; }
warn() { echo -e "\033[1;33m[inocmon]\033[0m $1"; }
err()  { echo -e "\033[1;31m[inocmon]\033[0m $1" >&2; }

require_root() {
  if [ "$EUID" -ne 0 ]; then
    err "Execute este script como root (sudo ./install.sh)"
    exit 1
  fi
}

detect_os() {
  if [ ! -f /etc/os-release ]; then
    err "Sistema operacional nao suportado (esperado Ubuntu/Debian)."
    exit 1
  fi
  . /etc/os-release
  log "Sistema detectado: $PRETTY_NAME"
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then
    log "Docker ja instalado, pulando."
  else
    log "Instalando Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
  fi

  if ! docker compose version >/dev/null 2>&1; then
    err "Docker Compose plugin nao encontrado apos instalacao do Docker."
    exit 1
  fi
}

install_portainer() {
  if docker ps -a --format '{{.Names}}' | grep -q '^portainer$'; then
    log "Portainer ja esta rodando, pulando."
    return
  fi
  log "Instalando Portainer..."
  docker volume create portainer_data >/dev/null
  docker run -d -p 9443:9443 --name portainer --restart=always \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    portainer/portainer-ce:latest >/dev/null
  log "Portainer disponivel em https://SEU_IP:9443"
}

setup_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    log "Configurando firewall (ufw)..."
    ufw allow OpenSSH >/dev/null 2>&1 || true
    ufw allow 8443/tcp comment 'inocmon ingestion' >/dev/null 2>&1 || true
    ufw allow 9443/tcp comment 'portainer' >/dev/null 2>&1 || true
    ufw --force enable >/dev/null 2>&1 || true
  else
    warn "ufw nao encontrado, configure o firewall manualmente (portas 8443 e 9443)."
  fi
}

gen_secret() {
  openssl rand -hex 24
}

prepare_project() {
  log "Preparando diretorio do projeto em $INSTALL_DIR..."
  mkdir -p "$INSTALL_DIR"
  cd "$INSTALL_DIR"

  if [ -n "$REPO_ZIP_URL" ]; then
    log "Baixando pacote do projeto..."
    curl -fsSL "$REPO_ZIP_URL" -o inocmon.zip
    unzip -oq inocmon.zip -d "$INSTALL_DIR"
    rm inocmon.zip
  elif [ -f "$OLDPWD/docker-compose.yml" ]; then
    log "Copiando projeto local para $INSTALL_DIR..."
    cp -r "$OLDPWD"/* "$INSTALL_DIR"/
  else
    err "Nenhum pacote do projeto encontrado. Defina INOCMON_ZIP_URL ou rode o instalador de dentro da pasta do projeto."
    exit 1
  fi
}

configure_env() {
  if [ -f "$INSTALL_DIR/.env" ]; then
    log "Arquivo .env ja existe, mantendo configuracao atual."
    return
  fi

  log "Gerando arquivo .env com credenciais seguras..."
  DB_PASSWORD=$(gen_secret)
  cat > "$INSTALL_DIR/.env" <<EOF
DB_USER=inocmon
DB_PASSWORD=${DB_PASSWORD}
EOF
  chmod 600 "$INSTALL_DIR/.env"
  log "Credenciais geradas e salvas em $INSTALL_DIR/.env (guarde este arquivo em local seguro)."
}

deploy_stack() {
  log "Subindo a stack com Docker Compose..."
  cd "$INSTALL_DIR"
  $COMPOSE_CMD up -d --build
}

wait_healthy() {
  log "Aguardando o servico de ingestao ficar disponivel..."
  for i in $(seq 1 30); do
    if curl -fsS http://localhost:8443/health >/dev/null 2>&1; then
      log "Servico de ingestao respondendo em http://localhost:8443"
      return
    fi
    sleep 2
  done
  warn "Servico ainda nao respondeu apos 60s. Verifique com: docker logs inocmon-ingestion"
}

print_summary() {
  IP=$(curl -fsS ifconfig.me 2>/dev/null || echo "SEU_IP")
  echo ""
  log "Instalacao concluida!"
  echo ""
  echo "  Painel Portainer:      https://${IP}:9443"
  echo "  Endpoint de ingestao:  http://${IP}:8443/v1/logs  (colocar atras de TLS antes de producao)"
  echo "  Diretorio do projeto:  ${INSTALL_DIR}"
  echo "  Credenciais do banco:  ${INSTALL_DIR}/.env"
  echo ""
  echo "  Proximo passo recomendado: configurar TLS (Traefik/Nginx + Let's Encrypt)"
  echo "  antes de conectar roteadores reais em producao."
  echo ""
}

main() {
  require_root
  detect_os
  install_docker
  install_portainer
  setup_firewall
  prepare_project
  configure_env
  deploy_stack
  wait_healthy
  print_summary
}

main "$@"
