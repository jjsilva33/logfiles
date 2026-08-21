import os
import logging
from datetime import datetime, timezone
from typing import Optional

import asyncpg
import httpx
from cryptography.fernet import Fernet
from fastapi import FastAPI, Header, HTTPException, Depends, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, IPvAnyAddress

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("inocmon-ingestion")

DATABASE_URL = os.environ["DATABASE_URL"]

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
OAUTH_REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")

fernet = Fernet(ENCRYPTION_KEY.encode()) if ENCRYPTION_KEY else None

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_DRIVE_API = "https://www.googleapis.com/drive/v3"
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"

app = FastAPI(title="Inocmon Ingestion Service")

pool: Optional[asyncpg.Pool] = None


SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nome TEXT NOT NULL,
  cnpj TEXT UNIQUE,
  status TEXT DEFAULT 'ativo',
  plano TEXT DEFAULT 'basico',
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_drive_config (
  tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  drive_refresh_token TEXT,
  drive_folder_id TEXT,
  espaco_local_limite_gb INTEGER DEFAULT 50,
  prazo_retencao_dias INTEGER DEFAULT 365,
  atualizado_em TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS usuarios (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  senha_hash TEXT NOT NULL,
  papel TEXT DEFAULT 'operador',
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(tenant_id, email)
);

CREATE TABLE IF NOT EXISTS roteadores (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  nome TEXT NOT NULL,
  identificador TEXT NOT NULL,
  token_ingestao TEXT NOT NULL UNIQUE,
  ativo BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_roteadores_token ON roteadores(token_ingestao);

CREATE TABLE IF NOT EXISTS nat_logs (
  id BIGSERIAL,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  roteador_id UUID NOT NULL REFERENCES roteadores(id),
  ip_publico INET NOT NULL,
  porta_publica INTEGER NOT NULL,
  ip_privado INET NOT NULL,
  porta_privada INTEGER,
  protocolo TEXT,
  ts_inicio TIMESTAMPTZ NOT NULL,
  ts_fim TIMESTAMPTZ,
  arquivo_local TEXT,
  arquivo_drive TEXT,
  status TEXT DEFAULT 'local',
  created_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (id, ts_inicio)
) PARTITION BY RANGE (ts_inicio);

CREATE INDEX IF NOT EXISTS idx_nat_busca ON nat_logs (tenant_id, ip_publico, porta_publica, ts_inicio);
CREATE INDEX IF NOT EXISTS idx_nat_status ON nat_logs (tenant_id, status);

CREATE TABLE IF NOT EXISTS nat_logs_2026_08 PARTITION OF nat_logs
  FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS nat_logs_2026_09 PARTITION OF nat_logs
  FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE IF NOT EXISTS nat_logs_2026_10 PARTITION OF nat_logs
  FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');

CREATE TABLE IF NOT EXISTS auditoria_consultas (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  usuario_id UUID REFERENCES usuarios(id),
  solicitante TEXT,
  ip_pesquisado INET,
  porta_pesquisada INTEGER,
  ts_pesquisado TIMESTAMPTZ,
  resultado_encontrado BOOLEAN,
  executado_em TIMESTAMPTZ DEFAULT now()
);

DO $$
BEGIN
  ALTER TABLE auditoria_consultas ALTER COLUMN usuario_id DROP NOT NULL;
EXCEPTION WHEN others THEN NULL;
END $$;

DO $$
BEGIN
  ALTER TABLE auditoria_consultas ADD COLUMN IF NOT EXISTS solicitante TEXT;
EXCEPTION WHEN others THEN NULL;
END $$;
"""

SEED_SQL = """
INSERT INTO tenants (id, nome, cnpj) VALUES
  ('11111111-1111-1111-1111-111111111111', 'ISP Teste', '00.000.000/0001-00')
ON CONFLICT (id) DO NOTHING;

INSERT INTO roteadores (id, tenant_id, nome, identificador, token_ingestao) VALUES
  ('22222222-2222-2222-2222-222222222222',
   '11111111-1111-1111-1111-111111111111',
   'Roteador Teste', '192.168.0.1', 'token-teste-123456')
ON CONFLICT (id) DO NOTHING;
"""


@app.on_event("startup")
async def startup():
    global pool
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    log.info("Pool de conexao com Postgres criado")

    async with pool.acquire() as conn:
        log.info("Aplicando schema (idempotente)...")
        await conn.execute(SCHEMA_SQL)
        await conn.execute(SEED_SQL)
        log.info("Schema aplicado com sucesso")


@app.on_event("shutdown")
async def shutdown():
    await pool.close()


class NatLogEvent(BaseModel):
    ip_publico: IPvAnyAddress
    porta_publica: int
    ip_privado: IPvAnyAddress
    porta_privada: Optional[int] = None
    protocolo: Optional[str] = "tcp"
    ts_inicio: datetime
    ts_fim: Optional[datetime] = None


async def validar_roteador(token: str) -> dict:
    """Valida o token de ingestao e retorna tenant_id/roteador_id."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id AS roteador_id, tenant_id, ativo
            FROM roteadores
            WHERE token_ingestao = $1
            """,
            token,
        )
    if row is None:
        raise HTTPException(status_code=401, detail="Token de roteador invalido")
    if not row["ativo"]:
        raise HTTPException(status_code=403, detail="Roteador desativado")
    return dict(row)


async def get_roteador(x_router_token: str = Header(..., alias="X-Router-Token")) -> dict:
    return await validar_roteador(x_router_token)


async def exigir_admin(x_admin_key: str = Header(..., alias="X-Admin-Key")):
    """
    Protecao provisoria enquanto nao existe login de usuario por tenant
    (isso sera substituido pelo sistema de autenticacao do painel web).
    """
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=500, detail="ADMIN_API_KEY nao configurada no servidor")
    if x_admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Chave de administrador invalida")


@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/v1/logs")
async def receber_log(evento: NatLogEvent, roteador: dict = Depends(get_roteador)):
    """
    Recebe um evento de NAT de um roteador autenticado e grava no indice.
    O roteador (ou agente instalado nele) deve enviar:
      Header: X-Router-Token: <token do roteador>
      Body JSON: campos do NatLogEvent
    """
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO nat_logs (
                tenant_id, roteador_id, ip_publico, porta_publica,
                ip_privado, porta_privada, protocolo, ts_inicio, ts_fim, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'local')
            """,
            roteador["tenant_id"],
            roteador["roteador_id"],
            str(evento.ip_publico),
            evento.porta_publica,
            str(evento.ip_privado),
            evento.porta_privada,
            evento.protocolo,
            evento.ts_inicio,
            evento.ts_fim,
        )
    return {"status": "recebido"}


@app.post("/v1/logs/batch")
async def receber_log_lote(eventos: list[NatLogEvent], roteador: dict = Depends(get_roteador)):
    """Mesma coisa, mas em lote -- reduz overhead de rede para roteadores
    que acumulam eventos e enviam a cada X segundos."""
    if not eventos:
        return {"status": "vazio", "gravados": 0}

    registros = [
        (
            roteador["tenant_id"],
            roteador["roteador_id"],
            str(e.ip_publico),
            e.porta_publica,
            str(e.ip_privado),
            e.porta_privada,
            e.protocolo,
            e.ts_inicio,
            e.ts_fim,
        )
        for e in eventos
    ]

    async with pool.acquire() as conn:
        await conn.executemany(
            """
            INSERT INTO nat_logs (
                tenant_id, roteador_id, ip_publico, porta_publica,
                ip_privado, porta_privada, protocolo, ts_inicio, ts_fim, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'local')
            """,
            registros,
        )
    return {"status": "recebido", "gravados": len(registros)}


@app.get("/v1/tenants/{tenant_id}/drive/connect")
async def conectar_drive(tenant_id: str):
    """
    Gera a URL de autorizacao do Google para o tenant conectar a propria
    conta do Drive. O admin do ISP acessa essa URL, loga com a conta Google
    dele, e autoriza o Inocmon a criar/gerenciar arquivos numa pasta dedicada.
    """
    if not GOOGLE_CLIENT_ID or not OAUTH_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="OAuth do Google nao configurado no servidor")

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": DRIVE_SCOPE,
        "access_type": "offline",   # necessario para receber refresh_token
        "prompt": "consent",        # forca gerar refresh_token mesmo se ja autorizou antes
        "state": tenant_id,
    }
    query = "&".join(f"{k}={httpx.QueryParams({k: v})[k]}" for k, v in params.items())
    url = f"{GOOGLE_AUTH_URL}?{query}"
    return RedirectResponse(url)


@app.get("/v1/oauth/callback")
async def oauth_callback(code: str = Query(...), state: str = Query(...)):
    """
    Google redireciona para ca apos o usuario autorizar. Trocamos o 'code'
    por um refresh_token, criamos (ou reaproveitamos) uma pasta dedicada
    no Drive do tenant, e salvamos tudo criptografado no banco.
    """
    tenant_id = state

    if not fernet:
        raise HTTPException(status_code=500, detail="ENCRYPTION_KEY nao configurada no servidor")

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": OAUTH_REDIRECT_URI,
            },
        )
    if token_resp.status_code != 200:
        log.error(f"Falha ao trocar code por token: {token_resp.text}")
        raise HTTPException(status_code=400, detail="Falha na autorizacao com o Google")

    tokens = token_resp.json()
    refresh_token = tokens.get("refresh_token")
    access_token = tokens["access_token"]

    if not refresh_token:
        # Acontece se o usuario ja tinha autorizado antes sem 'prompt=consent'.
        raise HTTPException(
            status_code=400,
            detail="Google nao retornou refresh_token. Revogue o acesso em "
                   "myaccount.google.com/permissions e tente conectar novamente.",
        )

    # Cria (ou localiza) a pasta dedicada "Inocmon Logs" no Drive do tenant
    async with httpx.AsyncClient() as client:
        search = await client.get(
            f"{GOOGLE_DRIVE_API}/files",
            headers={"Authorization": f"Bearer {access_token}"},
            params={
                "q": "name='Inocmon Logs' and mimeType='application/vnd.google-apps.folder' and trashed=false",
                "fields": "files(id,name)",
            },
        )
        existentes = search.json().get("files", [])

        if existentes:
            folder_id = existentes[0]["id"]
        else:
            criar = await client.post(
                f"{GOOGLE_DRIVE_API}/files",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"name": "Inocmon Logs", "mimeType": "application/vnd.google-apps.folder"},
            )
            folder_id = criar.json()["id"]

    refresh_token_criptografado = fernet.encrypt(refresh_token.encode()).decode()

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO tenant_drive_config (tenant_id, drive_refresh_token, drive_folder_id, atualizado_em)
            VALUES ($1, $2, $3, now())
            ON CONFLICT (tenant_id) DO UPDATE
            SET drive_refresh_token = EXCLUDED.drive_refresh_token,
                drive_folder_id = EXCLUDED.drive_folder_id,
                atualizado_em = now()
            """,
            tenant_id,
            refresh_token_criptografado,
            folder_id,
        )

    log.info(f"Tenant {tenant_id}: Google Drive conectado com sucesso (pasta {folder_id})")
    return {
        "status": "conectado",
        "tenant_id": tenant_id,
        "drive_folder_id": folder_id,
        "mensagem": "Google Drive conectado com sucesso. Pode fechar esta janela.",
    }


@app.get("/v1/tenants/{tenant_id}/drive/status")
async def status_drive(tenant_id: str):
    """Verifica se o tenant ja conectou o Google Drive."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT drive_folder_id, espaco_local_limite_gb, prazo_retencao_dias, atualizado_em "
            "FROM tenant_drive_config WHERE tenant_id = $1",
            tenant_id,
        )
    if row is None:
        return {"conectado": False}
    return {
        "conectado": row["drive_folder_id"] is not None,
        "drive_folder_id": row["drive_folder_id"],
        "espaco_local_limite_gb": row["espaco_local_limite_gb"],
        "prazo_retencao_dias": row["prazo_retencao_dias"],
        "atualizado_em": row["atualizado_em"].isoformat() if row["atualizado_em"] else None,
    }


@app.get("/v1/tenants/{tenant_id}/search")
async def buscar_log(
    tenant_id: str,
    ip_publico: str = Query(..., description="IP publico informado na ordem judicial"),
    porta_publica: int = Query(..., description="Porta publica informada na ordem judicial"),
    timestamp: datetime = Query(..., description="Data/hora do fato, formato ISO 8601 (ex: 2026-08-20T14:30:00Z)"),
    solicitante: Optional[str] = Query(None, description="Identificacao de quem esta consultando (ex: numero do processo, nome do operador)"),
    _admin: None = Depends(exigir_admin),
):
    """
    Busca central do sistema: dado IP publico + porta + horario (dados
    tipicamente presentes em uma ordem judicial), retorna qual IP privado
    estava usando aquele IP:porta naquele momento, permitindo o cruzamento
    posterior com o sistema de gerencia de clientes (IXC, RBX, etc).

    A busca considera registros com ts_inicio <= timestamp, priorizando
    aqueles cujo ts_fim (se existir) tambem cobre o timestamp pesquisado.
    Funciona tanto para registros ainda locais quanto ja arquivados no
    Drive -- o indice no Postgres nunca e apagado, so o arquivo bruto muda
    de lugar.
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                nl.id, nl.ip_publico, nl.porta_publica, nl.ip_privado, nl.porta_privada,
                nl.protocolo, nl.ts_inicio, nl.ts_fim, nl.status, nl.arquivo_drive,
                r.nome AS roteador_nome, r.identificador AS roteador_identificador
            FROM nat_logs nl
            JOIN roteadores r ON r.id = nl.roteador_id
            WHERE nl.tenant_id = $1
              AND nl.ip_publico = $2
              AND nl.porta_publica = $3
              AND nl.ts_inicio <= $4
              AND (nl.ts_fim IS NULL OR nl.ts_fim >= $4)
            ORDER BY nl.ts_inicio DESC
            LIMIT 20
            """,
            tenant_id,
            ip_publico,
            porta_publica,
            timestamp,
        )

        if not rows:
            # Fallback: nenhum registro cobre exatamente o timestamp (ts_fim pode
            # nao ter sido preenchido pelo roteador) -- pega o mais proximo antes dele.
            rows = await conn.fetch(
                """
                SELECT
                    nl.id, nl.ip_publico, nl.porta_publica, nl.ip_privado, nl.porta_privada,
                    nl.protocolo, nl.ts_inicio, nl.ts_fim, nl.status, nl.arquivo_drive,
                    r.nome AS roteador_nome, r.identificador AS roteador_identificador
                FROM nat_logs nl
                JOIN roteadores r ON r.id = nl.roteador_id
                WHERE nl.tenant_id = $1
                  AND nl.ip_publico = $2
                  AND nl.porta_publica = $3
                  AND nl.ts_inicio <= $4
                ORDER BY nl.ts_inicio DESC
                LIMIT 5
                """,
                tenant_id,
                ip_publico,
                porta_publica,
                timestamp,
            )

        await conn.execute(
            """
            INSERT INTO auditoria_consultas
                (tenant_id, solicitante, ip_pesquisado, porta_pesquisada, ts_pesquisado, resultado_encontrado)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            tenant_id,
            solicitante,
            ip_publico,
            porta_publica,
            timestamp,
            len(rows) > 0,
        )

    resultados = [
        {
            "ip_privado": str(r["ip_privado"]),
            "porta_privada": r["porta_privada"],
            "protocolo": r["protocolo"],
            "ts_inicio": r["ts_inicio"].isoformat(),
            "ts_fim": r["ts_fim"].isoformat() if r["ts_fim"] else None,
            "roteador": r["roteador_nome"],
            "roteador_identificador": r["roteador_identificador"],
            "status_armazenamento": r["status"],
            "arquivo_drive": r["arquivo_drive"],
        }
        for r in rows
    ]

    return {
        "encontrado": len(resultados) > 0,
        "consulta": {
            "ip_publico": ip_publico,
            "porta_publica": porta_publica,
            "timestamp": timestamp.isoformat(),
        },
        "resultados": resultados,
    }
