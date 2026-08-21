import os
import logging
from datetime import datetime, timezone
from typing import Optional

import asyncpg
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel, IPvAnyAddress

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("inocmon-ingestion")

DATABASE_URL = os.environ["DATABASE_URL"]

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
  usuario_id UUID NOT NULL REFERENCES usuarios(id),
  ip_pesquisado INET,
  porta_pesquisada INTEGER,
  ts_pesquisado TIMESTAMPTZ,
  resultado_encontrado BOOLEAN,
  executado_em TIMESTAMPTZ DEFAULT now()
);
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
