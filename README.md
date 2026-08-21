# Inocmon - Sistema de Retenção de Logs de NAT

Sistema para atender ao art. 13 da Lei nº 12.965/2014 (Marco Civil da Internet),
mantendo registros de conexão (NAT) de forma segura, com retenção em camadas
(local + Google Drive) e busca por IP público/porta/horário.

## Deploy via Portainer (Stack por repositório Git)

1. No Portainer: Stacks → Add Stack → aba "Repository"
2. URL do repositório: (cole a URL deste repo)
3. Branch: main
4. Compose path: docker-compose.yml
5. Environment variables:
   - DB_USER=inocmon
   - DB_PASSWORD=<senha forte>
   - INGESTION_DOMAIN=filelogs.cloudy.app.br
   - TRAEFIK_CERTRESOLVER=leresolver
6. Deploy the stack

## Testar após o deploy

```bash
curl https://filelogs.cloudy.app.br/health

curl -X POST https://filelogs.cloudy.app.br/v1/logs \
  -H "Content-Type: application/json" \
  -H "X-Router-Token: token-teste-123456" \
  -d '{
    "ip_publico": "200.200.200.222",
    "porta_publica": 43211,
    "ip_privado": "10.0.0.55",
    "porta_privada": 51423,
    "protocolo": "tcp",
    "ts_inicio": "2026-08-20T14:30:00Z"
  }'
```
