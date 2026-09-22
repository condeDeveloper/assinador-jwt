/**
 * O token.
 *
 * Um JWT é `cabecalho.reivindicacoes.assinatura`, cada parte em base64url. O
 * que é assinado é exatamente o texto `cabecalho.reivindicacoes` — e é por
 * isso que **a assinatura cobre a codificação, não o objeto**: dois JSON
 * equivalentes com as chaves em outra ordem produzem tokens diferentes, e
 * reserializar antes de conferir quebra tudo.
 *
 * A decisão mais importante deste arquivo é que `verificar` **exige** a lista
 * de algoritmos aceitos. Ver o porquê em `confusaoDeAlgoritmo` abaixo.
 */

import { codificarJson, decodificarJson } from './base64url.js';
import { ErroDeAlgoritmo, assinar as assinarBytes, conferir, descrever } from './algoritmos.js';

/** O token não presta, e `codigo` diz por quê. */
export class ErroDeToken extends Error {
  constructor(mensagem, codigo) {
    super(mensagem);
    this.name = 'ErroDeToken';
    this.codigo = codigo;
  }
}

/** Reivindicações com significado no padrão (RFC 7519 §4.1). */
export const REGISTRADAS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];

/** Segundos desde 1970, que é a unidade de `exp`, `nbf` e `iat`. */
export function agora() {
  return Math.floor(Date.now() / 1000);
}

/**
 * Assina um token.
 *
 * @param {object} reivindicacoes
 * @param {string|Buffer|object} chave segredo (HS) ou chave privada
 * @param {{
 *   algoritmo?: string, expiraEm?: number, valeApartirDe?: number,
 *   emissor?: string, assunto?: string, publico?: string|string[],
 *   id?: string, emitidoEm?: number|false, cabecalho?: object,
 * }} opcoes
 */
export function assinar(reivindicacoes, chave, opcoes = {}) {
  const algoritmo = opcoes.algoritmo ?? 'HS256';

  descrever(algoritmo);

  if (reivindicacoes === null || typeof reivindicacoes !== 'object' || Array.isArray(reivindicacoes)) {
    throw new ErroDeToken('As reivindicações precisam ser um objeto.', 'reivindicacoes');
  }

  const instante = opcoes.emitidoEm === false ? null : (opcoes.emitidoEm ?? agora());
  const corpo = { ...reivindicacoes };

  if (instante !== null) corpo.iat = instante;
  if (opcoes.emissor !== undefined) corpo.iss = opcoes.emissor;
  if (opcoes.assunto !== undefined) corpo.sub = opcoes.assunto;
  if (opcoes.publico !== undefined) corpo.aud = opcoes.publico;
  if (opcoes.id !== undefined) corpo.jti = opcoes.id;

  if (opcoes.expiraEm !== undefined) {
    if (!Number.isFinite(opcoes.expiraEm) || opcoes.expiraEm <= 0) {
      throw new ErroDeToken('expiraEm é em segundos e precisa ser positivo.', 'opcoes');
    }

    corpo.exp = (instante ?? agora()) + opcoes.expiraEm;
  }

  if (opcoes.valeApartirDe !== undefined) corpo.nbf = (instante ?? agora()) + opcoes.valeApartirDe;

  // `typ` é informativo, mas sua ausência confunde quem depura com uma
  // ferramenta genérica; `alg` é obrigatório.
  const cabecalho = { alg: algoritmo, typ: 'JWT', ...opcoes.cabecalho };

  const entrada = `${codificarJson(cabecalho)}.${codificarJson(corpo)}`;

  return `${entrada}.${assinarBytes(algoritmo, entrada, chave)}`;
}

/**
 * Lê um token **sem conferir nada**.
 *
 * Existe para depurar e para descobrir qual chave usar (pelo `kid`). O nome é
 * longo de propósito: `decodificar` curto e inocente é o que faz gente
 * confiar num token não verificado.
 */
export function lerSemVerificar(token) {
  const partes = String(token).split('.');

  if (partes.length !== 3) {
    throw new ErroDeToken(`Um JWT tem três partes separadas por ponto; este tem ${partes.length}.`, 'formato');
  }

  return {
    cabecalho: decodificarJson(partes[0], 'cabeçalho'),
    reivindicacoes: decodificarJson(partes[1], 'corpo'),
    assinatura: partes[2],
    entrada: `${partes[0]}.${partes[1]}`,
  };
}

/**
 * Por que `algoritmos` é obrigatório.
 *
 * Se o verificador confiar no `alg` que vem **dentro do token**, quem ataca
 * escolhe o algoritmo. O caso clássico: o servidor usa RS256 e a chave
 * pública é, por definição, pública. O atacante troca o cabeçalho para HS256
 * e assina com essa chave pública como se fosse o segredo do HMAC. O
 * servidor, obediente, confere HMAC com a mesma chave pública — e aceita.
 *
 * A defesa não é sanitizar o cabeçalho: é **nunca perguntar ao token qual
 * algoritmo usar**.
 */
export const confusaoDeAlgoritmo = Symbol('documentação');

/**
 * Confere um token e devolve as reivindicações.
 *
 * @param {string} token
 * @param {string|Buffer|object} chave
 * @param {{
 *   algoritmos: string[], tolerancia?: number, agora?: number,
 *   emissor?: string|string[], publico?: string|string[], assunto?: string,
 *   exigirExpiracao?: boolean, maximaIdade?: number,
 * }} opcoes
 */
export function verificar(token, chave, opcoes = {}) {
  const aceitos = opcoes.algoritmos;

  if (!Array.isArray(aceitos) || aceitos.length === 0) {
    throw new ErroDeAlgoritmo(
      'Informe os algoritmos aceitos. Confiar no "alg" do token permite a troca de algoritmo — veja o README.',
    );
  }

  for (const nome of aceitos) descrever(nome);

  const { cabecalho, reivindicacoes, assinatura, entrada } = lerSemVerificar(token);

  if (!aceitos.includes(cabecalho.alg)) {
    throw new ErroDeToken(
      `O token diz ${JSON.stringify(cabecalho.alg)} e aqui só valem ${aceitos.join(', ')}.`,
      'algoritmo',
    );
  }

  if (!conferir(cabecalho.alg, entrada, assinatura, chave)) {
    throw new ErroDeToken('Assinatura inválida.', 'assinatura');
  }

  conferirReivindicacoes(reivindicacoes, opcoes);

  return { ...reivindicacoes, cabecalho };
}

/** Confere as reivindicações de tempo e de destinatário. */
export function conferirReivindicacoes(reivindicacoes, opcoes = {}) {
  const instante = opcoes.agora ?? agora();
  const tolerancia = opcoes.tolerancia ?? 0;

  if (opcoes.exigirExpiracao && reivindicacoes.exp === undefined) {
    throw new ErroDeToken('O token não tem "exp" e esta aplicação exige expiração.', 'exp');
  }

  if (reivindicacoes.exp !== undefined) {
    exigirNumero(reivindicacoes.exp, 'exp');

    // A tolerância existe porque relógios de máquinas diferentes não batem;
    // sem ela, um servidor 3 segundos adiantado recusa tokens recém-emitidos.
    if (instante >= reivindicacoes.exp + tolerancia) {
      throw new ErroDeToken(`Token expirado em ${new Date(reivindicacoes.exp * 1000).toISOString()}.`, 'expirado');
    }
  }

  if (reivindicacoes.nbf !== undefined) {
    exigirNumero(reivindicacoes.nbf, 'nbf');

    if (instante + tolerancia < reivindicacoes.nbf) {
      throw new ErroDeToken(`Token só vale a partir de ${new Date(reivindicacoes.nbf * 1000).toISOString()}.`, 'nbf');
    }
  }

  if (reivindicacoes.iat !== undefined) exigirNumero(reivindicacoes.iat, 'iat');

  if (opcoes.maximaIdade !== undefined) {
    if (reivindicacoes.iat === undefined) {
      throw new ErroDeToken('Sem "iat" não dá para medir a idade do token.', 'iat');
    }

    if (instante - reivindicacoes.iat > opcoes.maximaIdade + tolerancia) {
      throw new ErroDeToken(`O token tem mais de ${opcoes.maximaIdade} s de emitido.`, 'idade');
    }
  }

  if (opcoes.emissor !== undefined) {
    const aceitos = [].concat(opcoes.emissor);

    if (!aceitos.includes(reivindicacoes.iss)) {
      throw new ErroDeToken(`Emissor ${JSON.stringify(reivindicacoes.iss)} não está entre os aceitos.`, 'iss');
    }
  }

  if (opcoes.assunto !== undefined && reivindicacoes.sub !== opcoes.assunto) {
    throw new ErroDeToken(`Assunto ${JSON.stringify(reivindicacoes.sub)} não é o esperado.`, 'sub');
  }

  if (opcoes.publico !== undefined) {
    // `aud` pode ser texto ou lista; basta um em comum.
    const nosso = [].concat(opcoes.publico);
    const dele = [].concat(reivindicacoes.aud ?? []);

    if (!dele.some((a) => nosso.includes(a))) {
      throw new ErroDeToken(`Este token não é para nós: aud = ${JSON.stringify(reivindicacoes.aud)}.`, 'aud');
    }
  }

  return reivindicacoes;
}

function exigirNumero(valor, campo) {
  if (typeof valor !== 'number' || !Number.isFinite(valor)) {
    throw new ErroDeToken(`A reivindicação "${campo}" precisa ser um número de segundos.`, campo);
  }
}
