/**
 * Os algoritmos de assinatura.
 *
 * Três famílias, e uma armadilha em cada:
 *
 * - **HS** (HMAC + SHA): segredo compartilhado. A comparação da assinatura
 *   precisa ser em tempo constante, senão o tempo de resposta vaza quantos
 *   bytes iniciais o atacante acertou.
 * - **RS / PS** (RSA): chave privada assina, pública confere. `PS` usa PSS,
 *   que tem prova de segurança melhor; `RS` usa o PKCS#1 v1.5, que continua
 *   no padrão por compatibilidade.
 * - **ES** (ECDSA): o `node:crypto` produz assinatura em **DER**, e o JWS
 *   exige **R‖S cru**. Trocar um pelo outro gera um token que parece certo e
 *   nenhuma outra biblioteca aceita. É o erro mais caro de depurar aqui, e a
 *   opção `dsaEncoding: 'ieee-p1363'` é o que resolve.
 *
 * E `none`. O algoritmo `none` existe no padrão para tokens já protegidos por
 * outro meio, e foi a origem da falha mais famosa de JWT: bibliotecas que
 * aceitavam um token com `"alg":"none"` e assinatura vazia davam acesso a
 * quem simplesmente apagasse a assinatura. Aqui ele nunca é aceito na
 * verificação.
 */

import { createHmac, createSign, createVerify, timingSafeEqual } from 'node:crypto';

import { codificar, decodificar } from './base64url.js';

/** O algoritmo não é conhecido ou não pode ser usado. */
export class ErroDeAlgoritmo extends Error {
  constructor(mensagem) {
    super(mensagem);
    this.name = 'ErroDeAlgoritmo';
  }
}

/** Como cada algoritmo do padrão é implementado. */
export const ALGORITMOS = {
  HS256: { familia: 'HMAC', digestao: 'sha256' },
  HS384: { familia: 'HMAC', digestao: 'sha384' },
  HS512: { familia: 'HMAC', digestao: 'sha512' },
  RS256: { familia: 'RSA', digestao: 'sha256', preenchimento: 'pkcs1' },
  RS384: { familia: 'RSA', digestao: 'sha384', preenchimento: 'pkcs1' },
  RS512: { familia: 'RSA', digestao: 'sha512', preenchimento: 'pkcs1' },
  PS256: { familia: 'RSA', digestao: 'sha256', preenchimento: 'pss' },
  PS384: { familia: 'RSA', digestao: 'sha384', preenchimento: 'pss' },
  PS512: { familia: 'RSA', digestao: 'sha512', preenchimento: 'pss' },
  ES256: { familia: 'ECDSA', digestao: 'sha256', curva: 'prime256v1' },
  ES384: { familia: 'ECDSA', digestao: 'sha384', curva: 'secp384r1' },
  ES512: { familia: 'ECDSA', digestao: 'sha512', curva: 'secp521r1' },
};

/** Os nomes aceitos. */
export const NOMES = Object.keys(ALGORITMOS);

/** Descreve um algoritmo, recusando o que não existe e o `none`. */
export function descrever(nome) {
  if (nome === 'none') {
    throw new ErroDeAlgoritmo(
      'O algoritmo "none" não é aceito: um token sem assinatura pode ser forjado por qualquer um.',
    );
  }

  const algoritmo = ALGORITMOS[nome];

  if (!algoritmo) throw new ErroDeAlgoritmo(`Algoritmo desconhecido: ${JSON.stringify(nome)}.`);

  return algoritmo;
}

/**
 * Opções do `crypto` para RSA.
 *
 * A chave pode chegar de três formas: PEM em texto, `KeyObject` do
 * `node:crypto`, ou um objeto de opções que já traz `key` dentro. Espalhar um
 * `KeyObject` com `{...chave}` devolve um objeto **vazio** — ele não tem
 * propriedades próprias enumeráveis —, e o erro que aparece lá na frente é
 * "privateKey.key must be of type string… received undefined".
 */
function opcoesRsa(algoritmo, chave) {
  const ehOpcoes = chave !== null && typeof chave === 'object' && 'key' in chave;
  const base = ehOpcoes ? { ...chave } : { key: chave };

  if (algoritmo.preenchimento !== 'pss') return base;

  return {
    ...base,
    // 1 é RSA_PKCS1_PSS_PADDING; o sal com o tamanho da digestão é o que o
    // padrão manda para PS.
    padding: 6,
    saltLength: { sha256: 32, sha384: 48, sha512: 64 }[algoritmo.digestao],
  };
}

/** Assina os bytes e devolve a assinatura crua. */
export function assinarBytes(nome, entrada, chave) {
  const algoritmo = descrever(nome);

  if (algoritmo.familia === 'HMAC') {
    if (!chave || (typeof chave !== 'string' && !Buffer.isBuffer(chave))) {
      throw new ErroDeAlgoritmo(`${nome} precisa de um segredo em texto ou Buffer.`);
    }

    return createHmac(algoritmo.digestao, chave).update(entrada).digest();
  }

  const assinador = createSign(algoritmo.digestao);

  assinador.update(entrada);

  if (algoritmo.familia === 'ECDSA') {
    // Sem `ieee-p1363` a saída vem em DER e o token não é aceito por nenhuma
    // outra biblioteca de JWT.
    return assinador.sign({ key: chave, dsaEncoding: 'ieee-p1363' });
  }

  return assinador.sign(opcoesRsa(algoritmo, chave));
}

/** Confere a assinatura. Nunca levanta por assinatura errada: devolve false. */
export function conferirBytes(nome, entrada, assinatura, chave) {
  const algoritmo = descrever(nome);

  if (algoritmo.familia === 'HMAC') {
    const esperada = createHmac(algoritmo.digestao, chave).update(entrada).digest();

    return iguaisEmTempoConstante(esperada, assinatura);
  }

  const conferidor = createVerify(algoritmo.digestao);

  conferidor.update(entrada);

  try {
    if (algoritmo.familia === 'ECDSA') {
      return conferidor.verify({ key: chave, dsaEncoding: 'ieee-p1363' }, assinatura);
    }

    return conferidor.verify(opcoesRsa(algoritmo, chave), assinatura);
  } catch {
    // Assinatura malformada faz o OpenSSL lançar; para quem verifica, isso é
    // só um token inválido.
    return false;
  }
}

/**
 * Compara em tempo constante.
 *
 * Com `===` ou `equals`, a comparação para no primeiro byte diferente — e a
 * diferença de tempo entre "errou no primeiro byte" e "errou no décimo" deixa
 * um atacante descobrir a assinatura byte a byte.
 *
 * O tamanho é conferido antes porque `timingSafeEqual` exige buffers iguais;
 * vazar o **tamanho** da assinatura não ajuda ninguém, já que ele é fixo por
 * algoritmo e público.
 */
export function iguaisEmTempoConstante(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) return false;

  return timingSafeEqual(a, b);
}

/** Assina e devolve em base64url, que é o que vai no token. */
export function assinar(nome, entrada, chave) {
  return codificar(assinarBytes(nome, entrada, chave));
}

/** Confere uma assinatura que veio em base64url. */
export function conferir(nome, entrada, assinatura, chave) {
  let bytes;

  try {
    bytes = decodificar(assinatura);
  } catch {
    return false;
  }

  return conferirBytes(nome, entrada, bytes, chave);
}
