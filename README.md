# assinador-jwt

JWT e JWS escritos do zero sobre o `node:crypto`: HS, RS, PS e ES, validação
das reivindicações e uma linha de comando para olhar um token **sem colar ele
num site**. **Zero dependências.**

```bash
$ jwt assinar '{"sub":"ana","papel":"admin"}' -k segredo-de-exemplo -e 3600
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbmEiLCJwYXBlbCI6ImFkbWluIiwi…

$ jwt verificar <token> -k segredo-de-exemplo
assinatura confere
algoritmo: HS256
sub: "ana"
papel: "admin"
iat: 2026-09-22T13:28:05.000Z (em 0 s)
exp: 2026-09-22T14:28:05.000Z (em 1 h)
situação: dentro do prazo

$ jwt verificar <token> -k chave-errada
Assinatura inválida. [assinatura]
```

Um JWT costuma carregar identificador de usuário, papel e às vezes e-mail.
Colar isso num depurador online é entregar o conteúdo para um terceiro.

## Por que existe

JWT é simples de ler e cheio de armadilha de implementar. Cada uma das cinco
abaixo já derrubou biblioteca conhecida.

### 1. O algoritmo `none`

O padrão prevê `"alg":"none"` para tokens já protegidos por outro meio.
Bibliotecas que aceitavam isso davam acesso a quem simplesmente **apagasse a
assinatura** e trocasse o cabeçalho. Foi a falha mais famosa da história do
formato.

Aqui `none` não existe: nem para assinar, nem para verificar.

### 2. A troca de algoritmo

Essa é mais sutil e continua acontecendo. O servidor usa RS256, e a chave
pública é — por definição — pública. O atacante:

1. troca o cabeçalho para `HS256`;
2. assina o token usando **a chave pública como se fosse o segredo do HMAC**;
3. manda.

Um verificador que pergunta ao token qual algoritmo usar confere HMAC com essa
mesma chave pública, e aceita.

A defesa não é sanitizar o cabeçalho. É **nunca perguntar ao token**. Por isso
`verificar` exige a lista:

```js
verificar(token, chave, { algoritmos: ['RS256'] });   // certo
verificar(token, chave);                              // lança, de propósito
```

Há um teste que monta o ataque inteiro, confirma que o token forjado **é** um
HMAC válido com a chave pública, e mostra que mesmo assim ele é recusado.

### 3. Base64url não é base64

Três diferenças: `+` vira `-`, `/` vira `_` e o `=` do fim some. Quem usa
base64 comum produz um token que *quase* funciona — ele só quebra quando o
conteúdo por acaso gera um `+` ou uma `/`, o que acontece o tempo todo.

### 4. ECDSA em DER não é ECDSA em JWS

O `node:crypto` assina ECDSA em **DER** (começa com `0x30`, tamanho variável).
O JWS exige os dois números concatenados crus, R‖S, 64 bytes fixos no ES256.

Trocar um pelo outro gera um token que parece certo, confere no seu próprio
código e **nenhuma outra biblioteca do mundo aceita**. A opção
`dsaEncoding: 'ieee-p1363'` é o que resolve, e há um teste que confere o
tamanho e o primeiro byte para garantir que não voltou a DER.

### 5. Comparar assinatura com `===` vaza a assinatura

Uma comparação que para no primeiro byte diferente leva tempos diferentes
conforme quantos bytes iniciais o atacante acertou. Com medições suficientes,
dá para descobrir a assinatura byte a byte. Aqui a comparação do HMAC é
`timingSafeEqual`.

## A API

```js
import { assinar, verificar, lerSemVerificar } from 'assinador-jwt';

const token = assinar({ sub: 'ana', papel: 'admin' }, segredo, {
  algoritmo: 'HS256',
  expiraEm: 3600,
  emissor: 'https://conde',
  publico: ['api', 'web'],
});

const dados = verificar(token, segredo, {
  algoritmos: ['HS256'],   // obrigatório
  emissor: 'https://conde',
  publico: 'api',
  tolerancia: 30,          // folga de relógio, em segundos
  exigirExpiracao: true,
  maximaIdade: 86_400,
});

lerSemVerificar(token);    // para depurar e achar o `kid`; não confere nada
```

O nome `lerSemVerificar` é longo de propósito: um `decodificar` curto e
inocente é o que faz gente confiar num token não verificado.

**Algoritmos:** `HS256/384/512`, `RS256/384/512`, `PS256/384/512`,
`ES256/384/512`.

**Erros** vêm com `codigo`, para tratar cada caso sem casar texto:
`formato`, `algoritmo`, `assinatura`, `expirado`, `nbf`, `idade`, `iss`,
`aud`, `sub`.

### Tolerância de relógio

`tolerancia` existe porque relógios de máquinas diferentes não batem. Sem ela,
um servidor três segundos adiantado recusa tokens recém-emitidos com um erro
que parece bug de autenticação e é problema de NTP.

## Linha de comando

```
jwt ler <token>                     cabeçalho e reivindicações, sem conferir
jwt verificar <token> -k <chave>    confere assinatura e prazos
jwt assinar '<json>' -k <chave>     emite um token

-a, --algoritmo <nome>   padrão HS256
-k, --chave <texto>      segredo do HMAC
-K, --chave-arquivo <f>  arquivo PEM
-e, --expira <segundos>
-t, --tolerancia <s>
```

Código de saída `1` quando o token não presta, `2` em erro de uso.

## Estrutura

```
src/base64url.js    a codificação que não é base64
src/algoritmos.js   HMAC, RSA e ECDSA sobre node:crypto
src/jwt.js          montar, conferir e validar reivindicações
src/cli.js          ler, verificar e assinar
```

## Rodando

```bash
npm test
```

57 testes. Os seis primeiros reproduzem o **apêndice A.1 do RFC 7515** byte a
byte: a especificação publica o cabeçalho, o corpo, a chave e a assinatura, e
este projeto tem que chegar exatamente nos mesmos valores. Um deles confere que
o corpo do exemplo tem `\r\n` no meio — que é a prova de que a assinatura cobre
o **texto** e não o objeto.

Node 20 ou mais novo.

## Limites conhecidos

- **Só JWS, não JWE.** O token é assinado, não criptografado: qualquer um lê o
  conteúdo. Não ponha segredo dentro de um JWT.
- **Sem JWK e sem JWKS.** As chaves entram como PEM ou `KeyObject`; não há
  conversão de JSON Web Key nem busca de chave por URL.
- **Sem cabeçalho `crit`**, sem `x5c`, sem `jku`. Um `kid` desconhecido é
  ignorado em vez de resolver chave sozinho — resolver é decisão da aplicação.
- **Sem serialização JSON do JWS** (só a compacta, com pontos) e sem
  assinaturas múltiplas.
- **Sem revogação.** `jti` é emitido e devolvido, mas manter a lista de
  revogados é trabalho de quem usa.
- `EdDSA` não está implementado.

## Licença

MIT.
