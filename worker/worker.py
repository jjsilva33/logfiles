import os
import shutil
import asyncio
import logging
import subprocess
import json
from datetime import datetime, timezone
from pathlib import Path

import asyncpg

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("inocmon-worker")

DATABASE_URL = os.environ["DATABASE_URL"]
ARCHIVE_DIR = Path(os.environ.get("ARCHIVE_DIR", "/var/inocmon/archive"))
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", 900))  # 15 min
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", 5000))  # registros por lote arquivado
RCLONE_REMOTE = os.environ.get("RCLONE_REMOTE", "gdrive")  # nome do remote configurado no rclone

ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)


def get_dir_size_gb(path: Path) -> float:
    """Calcula o tamanho total de um diretorio em GB."""
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return total / (1024 ** 3)


def upload_to_drive(local_path: Path, remote_folder_id: str) -> bool:
    """
    Envia um arquivo para o Google Drive via rclone.
    Requer que o rclone esteja configurado com um remote chamado RCLONE_REMOTE
    (via service account ou config compartilhada). Para o modelo multi-tenant
    com OAuth individual por cliente, cada tenant precisara de um remote proprio
    -- isso e o proximo passo (fluxo de conexao do Drive por tenant).
    """
    try:
        destino = f"{RCLONE_REMOTE}:{remote_folder_id}/{local_path.name}"
        result = subprocess.run(
            ["rclone", "copy", str(local_path), f"{RCLONE_REMOTE}:{remote_folder_id}/"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            log.error(f"Falha no upload de {local_path.name}: {result.stderr}")
            return False
        log.info(f"Upload concluido: {local_path.name} -> {destino}")
        return True
    except Exception as e:
        log.error(f"Erro ao rodar rclone para {local_path.name}: {e}")
        return False


async def processar_tenant(conn: asyncpg.Connection, tenant: dict):
    tenant_id = tenant["tenant_id"]
    limite_gb = tenant["espaco_local_limite_gb"] or 50
    drive_folder_id = tenant["drive_folder_id"]

    tenant_dir = ARCHIVE_DIR / str(tenant_id)
    tenant_dir.mkdir(parents=True, exist_ok=True)

    uso_atual_gb = get_dir_size_gb(tenant_dir)
    log.info(f"Tenant {tenant_id}: uso local = {uso_atual_gb:.2f}GB / limite = {limite_gb}GB")

    if uso_atual_gb <= limite_gb:
        log.info(f"Tenant {tenant_id}: dentro do limite, nada a fazer.")
        return

    if not drive_folder_id:
        log.warning(
            f"Tenant {tenant_id}: acima do limite ({uso_atual_gb:.2f}GB) mas sem "
            f"Google Drive configurado ainda -- pulando ate a conexao ser feita."
        )
        return

    log.info(f"Tenant {tenant_id}: acima do limite, arquivando lote mais antigo...")

    rows = await conn.fetch(
        """
        SELECT id, ts_inicio, roteador_id, ip_publico, porta_publica,
               ip_privado, porta_privada, protocolo, ts_fim
        FROM nat_logs
        WHERE tenant_id = $1 AND status = 'local'
        ORDER BY ts_inicio ASC
        LIMIT $2
        """,
        tenant_id,
        BATCH_SIZE,
    )

    if not rows:
        log.info(f"Tenant {tenant_id}: nenhum registro 'local' para arquivar (uso de disco pode ser de outra origem).")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    arquivo_nome = f"nat_logs_{tenant_id}_{timestamp}.jsonl"
    arquivo_path = tenant_dir / arquivo_nome

    with open(arquivo_path, "w") as f:
        for row in rows:
            registro = dict(row)
            registro["id"] = str(registro["id"])
            registro["roteador_id"] = str(registro["roteador_id"])
            registro["ip_publico"] = str(registro["ip_publico"])
            registro["ip_privado"] = str(registro["ip_privado"])
            registro["ts_inicio"] = registro["ts_inicio"].isoformat()
            if registro["ts_fim"]:
                registro["ts_fim"] = registro["ts_fim"].isoformat()
            f.write(json.dumps(registro) + "\n")

    log.info(f"Tenant {tenant_id}: {len(rows)} registros escritos em {arquivo_nome}")

    sucesso = upload_to_drive(arquivo_path, drive_folder_id)

    if sucesso:
        ids = [row["id"] for row in rows]
        await conn.execute(
            """
            UPDATE nat_logs
            SET status = 'enviado_drive', arquivo_drive = $1, arquivo_local = NULL
            WHERE id = ANY($2::bigint[])
            """,
            arquivo_nome,
            ids,
        )
        arquivo_path.unlink(missing_ok=True)
        log.info(f"Tenant {tenant_id}: {len(rows)} registros atualizados para 'enviado_drive', arquivo local removido.")
    else:
        log.warning(f"Tenant {tenant_id}: upload falhou, arquivo mantido localmente para retry.")


async def ciclo_de_verificacao(pool: asyncpg.Pool):
    async with pool.acquire() as conn:
        tenants = await conn.fetch(
            """
            SELECT t.id AS tenant_id, d.espaco_local_limite_gb, d.drive_folder_id
            FROM tenants t
            LEFT JOIN tenant_drive_config d ON d.tenant_id = t.id
            WHERE t.status = 'ativo'
            """
        )

    log.info(f"Verificando {len(tenants)} tenant(s) ativo(s)...")

    async with pool.acquire() as conn:
        for tenant in tenants:
            try:
                await processar_tenant(conn, dict(tenant))
            except Exception as e:
                log.error(f"Erro ao processar tenant {tenant['tenant_id']}: {e}")


async def main():
    log.info(f"Worker iniciado. Verificacao a cada {CHECK_INTERVAL_SECONDS}s. Diretorio: {ARCHIVE_DIR}")
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)

    while True:
        try:
            await ciclo_de_verificacao(pool)
        except Exception as e:
            log.error(f"Erro no ciclo de verificacao: {e}")

        await asyncio.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
