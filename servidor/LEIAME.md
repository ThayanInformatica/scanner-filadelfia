# Servidor de autorizacao do Scanner Filadelfia

Sem um codigo valido emitido aqui, o scanner nao roda. O exe vazado nao serve para nada.

## Subir

```
./build.sh
scp dist/scanner-auth SEU_SERVIDOR:/opt/scanner-auth/
```

Variaveis obrigatorias:

- `DATABASE_URL` - `postgres://usuario:senha@127.0.0.1:5432/banco?sslmode=disable`
- `PAINEL_SENHA` - senha unica do painel da equipe
- `PORTA` - padrao 8090

As tabelas (`scanner_licencas`, `scanner_sessoes`, `scanner_config`) sao criadas sozinhas no primeiro start.

### systemd

```
[Unit]
Description=Scanner Filadelfia auth
After=network.target postgresql.service

[Service]
Environment=DATABASE_URL=postgres://scanner:SENHA@127.0.0.1:5432/scanner?sslmode=disable
Environment=PAINEL_SENHA=TROQUE_ISSO
Environment=PORTA=8090
ExecStart=/opt/scanner-auth/scanner-auth
Restart=always
User=scanner

[Install]
WantedBy=multi-user.target
```

## Expor para os jogadores

Se o dominio da sua cidade estiver com o DNS na Cloudflare, da para usar Cloudflare Tunnel
sem abrir porta nenhuma no roteador. Rode no proprio servidor:

```
cloudflared tunnel login
cloudflared tunnel create scanner
cloudflared tunnel route dns scanner scanner.suacidade.com
cloudflared tunnel route dns scanner painel.suacidade.com
```

`~/.cloudflared/config.yml`:

```yaml
tunnel: scanner
credentials-file: /root/.cloudflared/scanner.json
ingress:
  - hostname: scanner.suacidade.com
    service: http://127.0.0.1:8090
  - hostname: painel.suacidade.com
    service: http://127.0.0.1:8090
  - service: http_404
```

```
cloudflared service install
systemctl enable --now cloudflared
```

A Cloudflare entrega o certificado, entao o endereco ja nasce em HTTPS.

### Trancar o painel

Poe Cloudflare Access na frente de `painel.suacidade.com` (Zero Trust, gratis ate 50 pessoas)
e libere so os emails da staff. A senha do painel vira a segunda tranca, e `scanner.suacidade.com`
continua aberto porque o exe do jogador precisa alcancar `/v1/sessao`.

## Compilar o scanner apontando para ca

```
./build.sh https://scanner.suacidade.com
```

O endereco fica gravado no exe. Sem `-api` na linha de comando ele usa esse.

## Rotas

| rota | quem usa | para que |
| --- | --- | --- |
| `POST /v1/sessao` | o exe | troca codigo por token, valida versao e prende o codigo a um PC |
| `POST /v1/encerrar` | o exe | fecha a sessao quando o scanner fecha |
| `GET /v1/saude` | voce | conferir se esta no ar |
| `/` | a equipe | painel de codigos |
