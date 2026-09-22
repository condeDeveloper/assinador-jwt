#!/usr/bin/env node
/**
 * A linha de comando.
 *
 * Útil para olhar um token sem colar ele num site — um JWT costuma carregar
 * identificador de usuário, papel e às vezes e-mail, e colar isso num
 * depurador online é entregar o conteúdo para um terceiro.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { NOMES } from './algoritmos.js';
import { ErroDeToken, agora, assinar, lerSemVerificar, verificar } from './jwt.js';

const AJUDA = `assinador-jwt — JWT do zero, sem colar token em site nenhum

  jwt ler <token>                     mostra cabeçalho e reivindicações
  jwt verificar <token> -k <chave>    confere assinatura e prazos
  jwt assinar '<json>' -k <chave>     emite um token

  -a, --algoritmo <nome>   padrão HS256 (${NOMES.join(', ')})
  -k, --chave <texto>      segredo do HMAC
  -K, --chave-arquivo <f>  arquivo PEM da chave
  -e, --expira <segundos>  acrescenta exp
  -t, --tolerancia <s>     folga de relógio na verificação
  -h, --ajuda`;

/** Lê os argumentos. */
export function lerArgumentos(argumentos) {
  const opcoes = {
    comando: null,
    valor: null,
    algoritmo: 'HS256',
    chave: null,
    chaveArquivo: null,
    expira: null,
    tolerancia: 0,
    ajuda: false,
  };

  const soltos = [];

  for (let i = 0; i < argumentos.length; i += 1) {
    const arg = argumentos[i];
    const proximo = () => {
      const valor = argumentos[++i];

      if (valor === undefined) throw new Error(`Faltou o valor depois de ${arg}.`);

      return valor;
    };

    if (arg === '-h' || arg === '--ajuda') opcoes.ajuda = true;
    else if (arg === '-a' || arg === '--algoritmo') opcoes.algoritmo = proximo();
    else if (arg === '-k' || arg === '--chave') opcoes.chave = proximo();
    else if (arg === '-K' || arg === '--chave-arquivo') opcoes.chaveArquivo = proximo();
    else if (arg === '-e' || arg === '--expira') {
      opcoes.expira = Number(proximo());

      if (!Number.isFinite(opcoes.expira) || opcoes.expira <= 0) throw new Error('expira é em segundos e precisa ser positivo.');
    } else if (arg === '-t' || arg === '--tolerancia') {
      opcoes.tolerancia = Number(proximo());

      if (!Number.isFinite(opcoes.tolerancia) || opcoes.tolerancia < 0) throw new Error('tolerancia precisa ser um número não negativo.');
    } else if (arg.startsWith('-')) {
      throw new Error(`Opção desconhecida: ${arg}.`);
    } else {
      soltos.push(arg);
    }
  }

  [opcoes.comando = null, opcoes.valor = null] = soltos;

  return opcoes;
}

/** Mostra quanto falta ou faz que passou de um instante. */
export function prazoLegivel(segundos, instante = agora()) {
  const diferenca = segundos - instante;
  const abs = Math.abs(diferenca);
  const unidade = abs < 60 ? [abs, 's'] : abs < 3600 ? [Math.round(abs / 60), 'min'] : [Math.round(abs / 3600), 'h'];

  return `${new Date(segundos * 1000).toISOString()} (${diferenca >= 0 ? 'em' : 'há'} ${unidade[0]} ${unidade[1]})`;
}

/** Descreve um token em texto. */
export function descreverToken(lido, instante = agora()) {
  const linhas = [`algoritmo: ${lido.cabecalho.alg}`];

  if (lido.cabecalho.kid) linhas.push(`chave (kid): ${lido.cabecalho.kid}`);

  for (const [chave, valor] of Object.entries(lido.reivindicacoes)) {
    if (['exp', 'nbf', 'iat'].includes(chave) && typeof valor === 'number') {
      linhas.push(`${chave}: ${prazoLegivel(valor, instante)}`);
      continue;
    }

    linhas.push(`${chave}: ${JSON.stringify(valor)}`);
  }

  if (typeof lido.reivindicacoes.exp === 'number') {
    linhas.push(lido.reivindicacoes.exp <= instante ? 'situação: EXPIRADO' : 'situação: dentro do prazo');
  }

  return linhas.join('\n');
}

/** Roda um comando e devolve o código de saída. */
export async function principal(argumentos, escrever = console.log, ler = (c) => readFile(c, 'utf8')) {
  let opcoes;

  try {
    opcoes = lerArgumentos(argumentos);
  } catch (erro) {
    escrever(erro.message);
    return 2;
  }

  if (opcoes.ajuda || opcoes.comando === null) {
    escrever(AJUDA);
    return opcoes.ajuda ? 0 : 2;
  }

  if (!['ler', 'verificar', 'assinar'].includes(opcoes.comando)) {
    escrever(`Comando desconhecido: ${opcoes.comando}.\n\n${AJUDA}`);
    return 2;
  }

  if (opcoes.valor === null) {
    escrever(opcoes.comando === 'assinar' ? 'Informe as reivindicações em JSON.' : 'Informe o token.');
    return 2;
  }

  let chave = opcoes.chave;

  if (opcoes.chaveArquivo !== null) {
    try {
      chave = await ler(opcoes.chaveArquivo);
    } catch (erro) {
      escrever(`Não consegui ler a chave: ${erro.message}`);
      return 2;
    }
  }

  try {
    if (opcoes.comando === 'ler') {
      // De propósito sem chave: `ler` não confere nada, e o texto diz isso.
      escrever(descreverToken(lerSemVerificar(opcoes.valor)));
      escrever('\n(assinatura NÃO conferida; use "verificar" para isso)');

      return 0;
    }

    if (chave === null) {
      escrever('Informe a chave com -k ou -K.');
      return 2;
    }

    if (opcoes.comando === 'verificar') {
      // `verificar` junta o cabeçalho ao resultado; aqui ele é separado de
      // novo, senão apareceria listado como se fosse uma reivindicação.
      const { cabecalho, ...reivindicacoes } = verificar(opcoes.valor, chave, {
        algoritmos: [opcoes.algoritmo],
        tolerancia: opcoes.tolerancia,
      });

      escrever('assinatura confere');
      escrever(descreverToken({ cabecalho, reivindicacoes }));

      return 0;
    }

    const corpo = JSON.parse(opcoes.valor);

    escrever(assinar(corpo, chave, {
      algoritmo: opcoes.algoritmo,
      ...(opcoes.expira === null ? {} : { expiraEm: opcoes.expira }),
    }));

    return 0;
  } catch (erro) {
    escrever(erro instanceof ErroDeToken ? `${erro.message} [${erro.codigo}]` : erro.message);
    return 1;
  }
}

/* c8 ignore start */
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  principal(process.argv.slice(2)).then((codigo) => {
    process.exitCode = codigo;
  });
}
/* c8 ignore stop */
