import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';

import { ErroDeToken, agora, assinar, conferirReivindicacoes, lerSemVerificar, verificar } from '../src/jwt.js';
import { codificarJson } from '../src/base64url.js';
import { descreverToken, lerArgumentos, prazoLegivel, principal } from '../src/cli.js';

const SEGREDO = 'um segredo bem comprido para o teste nao reclamar';
const INSTANTE = 1_800_000_000;

/** Captura o erro para olhar o código dele. */
function pegar(fn) {
  try {
    fn();
  } catch (erro) {
    return erro;
  }

  return null;
}

/** Roda a CLI capturando a saída. */
async function rodar(argumentos, arquivos = {}) {
  const linhas = [];
  const codigo = await principal(argumentos, (l) => linhas.push(String(l)), async (caminho) => {
    if (!(caminho in arquivos)) throw new Error('não existe');

    return arquivos[caminho];
  });

  return { codigo, saida: linhas.join('\n') };
}

describe('assinar e verificar', () => {
  it('as reivindicações voltam inteiras', () => {
    const token = assinar({ sub: 'ana', papel: 'admin' }, SEGREDO);
    const lido = verificar(token, SEGREDO, { algoritmos: ['HS256'] });

    assert.equal(lido.sub, 'ana');
    assert.equal(lido.papel, 'admin');
    assert.equal(lido.cabecalho.alg, 'HS256');
  });

  it('o token tem três partes', () => {
    assert.equal(assinar({ a: 1 }, SEGREDO).split('.').length, 3);
  });

  it('o iat é posto sozinho e dá para desligar', () => {
    assert.ok(lerSemVerificar(assinar({}, SEGREDO)).reivindicacoes.iat);
    assert.equal(lerSemVerificar(assinar({}, SEGREDO, { emitidoEm: false })).reivindicacoes.iat, undefined);
  });

  it('os atalhos viram as reivindicações registradas', () => {
    const token = assinar({}, SEGREDO, {
      emissor: 'https://conde',
      assunto: 'ana',
      publico: ['api', 'web'],
      id: 'abc-123',
      expiraEm: 3600,
      valeApartirDe: 60,
      emitidoEm: INSTANTE,
    });

    const { reivindicacoes } = lerSemVerificar(token);

    assert.equal(reivindicacoes.iss, 'https://conde');
    assert.equal(reivindicacoes.sub, 'ana');
    assert.deepEqual(reivindicacoes.aud, ['api', 'web']);
    assert.equal(reivindicacoes.jti, 'abc-123');
    assert.equal(reivindicacoes.exp, INSTANTE + 3600);
    assert.equal(reivindicacoes.nbf, INSTANTE + 60);
  });

  it('um byte trocado no corpo invalida a assinatura', () => {
    const token = assinar({ papel: 'usuario' }, SEGREDO);
    const [cabecalho, , assinatura] = token.split('.');
    const forjado = `${cabecalho}.${codificarJson({ papel: 'admin' })}.${assinatura}`;

    const erro = pegar(() => verificar(forjado, SEGREDO, { algoritmos: ['HS256'] }));

    assert.equal(erro.codigo, 'assinatura');
  });

  it('a assinatura cobre o texto, não o objeto', () => {
    // Dois JSON equivalentes com as chaves em outra ordem dão tokens
    // diferentes; reserializar antes de conferir quebraria tudo.
    const um = assinar({ a: 1, b: 2 }, SEGREDO, { emitidoEm: INSTANTE });
    const dois = assinar({ b: 2, a: 1 }, SEGREDO, { emitidoEm: INSTANTE });

    assert.notEqual(um, dois);
    assert.doesNotThrow(() => verificar(um, SEGREDO, { algoritmos: ['HS256'], agora: INSTANTE }));
  });

  it('token com formato errado é recusado com clareza', () => {
    for (const ruim of ['', 'a', 'a.b', 'a.b.c.d']) {
      const erro = pegar(() => lerSemVerificar(ruim));

      assert.equal(erro.codigo, 'formato', `deveria recusar ${JSON.stringify(ruim)}`);
    }
  });

  it('reivindicações que não são objeto são recusadas', () => {
    assert.throws(() => assinar('texto', SEGREDO), /precisam ser um objeto/);
    assert.throws(() => assinar([1], SEGREDO), ErroDeToken);
  });

  it('expiraEm precisa ser positivo', () => {
    assert.throws(() => assinar({}, SEGREDO, { expiraEm: 0 }), /precisa ser positivo/);
    assert.throws(() => assinar({}, SEGREDO, { expiraEm: -1 }), ErroDeToken);
  });

  it('funciona ponta a ponta com RS256 e ES256', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

    const comRsa = assinar({ sub: 'ana' }, rsa.privateKey, { algoritmo: 'RS256' });
    const comEc = assinar({ sub: 'ana' }, ec.privateKey, { algoritmo: 'ES256' });

    assert.equal(verificar(comRsa, rsa.publicKey, { algoritmos: ['RS256'] }).sub, 'ana');
    assert.equal(verificar(comEc, ec.publicKey, { algoritmos: ['ES256'] }).sub, 'ana');

    // A chave do outro par não serve.
    assert.throws(() => verificar(comRsa, generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey, { algoritmos: ['RS256'] }), /Assinatura inválida/);
  });
});

describe('prazos', () => {
  it('token expirado é recusado', () => {
    const token = assinar({}, SEGREDO, { expiraEm: 60, emitidoEm: INSTANTE });
    const erro = pegar(() => verificar(token, SEGREDO, { algoritmos: ['HS256'], agora: INSTANTE + 61 }));

    assert.equal(erro.codigo, 'expirado');
  });

  it('no segundo exato da expiração já não vale', () => {
    const token = assinar({}, SEGREDO, { expiraEm: 60, emitidoEm: INSTANTE });

    assert.throws(() => verificar(token, SEGREDO, { algoritmos: ['HS256'], agora: INSTANTE + 60 }), /expirado/);
    assert.doesNotThrow(() => verificar(token, SEGREDO, { algoritmos: ['HS256'], agora: INSTANTE + 59 }));
  });

  it('a tolerância cobre relógio fora de hora', () => {
    // Sem ela, um servidor 3 segundos adiantado recusa token recém-emitido.
    const token = assinar({}, SEGREDO, { expiraEm: 60, emitidoEm: INSTANTE });

    assert.doesNotThrow(() =>
      verificar(token, SEGREDO, { algoritmos: ['HS256'], agora: INSTANTE + 63, tolerancia: 5 }),
    );
  });

  it('nbf segura o token que ainda não vale', () => {
    const token = assinar({}, SEGREDO, { valeApartirDe: 600, emitidoEm: INSTANTE });
    const erro = pegar(() => verificar(token, SEGREDO, { algoritmos: ['HS256'], agora: INSTANTE + 1 }));

    assert.equal(erro.codigo, 'nbf');
    assert.doesNotThrow(() => verificar(token, SEGREDO, { algoritmos: ['HS256'], agora: INSTANTE + 600 }));
  });

  it('dá para exigir que o token tenha expiração', () => {
    const token = assinar({ sub: 'ana' }, SEGREDO);

    assert.doesNotThrow(() => verificar(token, SEGREDO, { algoritmos: ['HS256'] }));
    assert.throws(() => verificar(token, SEGREDO, { algoritmos: ['HS256'], exigirExpiracao: true }), /exige expiração/);
  });

  it('a idade máxima limita token antigo mesmo sem exp', () => {
    const token = assinar({}, SEGREDO, { emitidoEm: INSTANTE });

    assert.throws(
      () => verificar(token, SEGREDO, { algoritmos: ['HS256'], agora: INSTANTE + 100, maximaIdade: 60 }),
      /mais de 60 s/,
    );
  });

  it('prazo que não é número é recusado', () => {
    assert.throws(() => conferirReivindicacoes({ exp: 'amanhã' }), /precisa ser um número/);
    assert.throws(() => conferirReivindicacoes({ nbf: null }), /precisa ser um número/);
  });
});

describe('destinatário', () => {
  it('o emissor precisa estar entre os aceitos', () => {
    const token = assinar({}, SEGREDO, { emissor: 'https://outro' });

    assert.throws(() => verificar(token, SEGREDO, { algoritmos: ['HS256'], emissor: 'https://conde' }), /Emissor/);
    assert.doesNotThrow(() =>
      verificar(token, SEGREDO, { algoritmos: ['HS256'], emissor: ['https://conde', 'https://outro'] }),
    );
  });

  it('aud pode ser texto ou lista, e basta um em comum', () => {
    const umSo = assinar({}, SEGREDO, { publico: 'api' });
    const varios = assinar({}, SEGREDO, { publico: ['api', 'web'] });

    assert.doesNotThrow(() => verificar(umSo, SEGREDO, { algoritmos: ['HS256'], publico: 'api' }));
    assert.doesNotThrow(() => verificar(varios, SEGREDO, { algoritmos: ['HS256'], publico: ['web'] }));
    assert.throws(() => verificar(umSo, SEGREDO, { algoritmos: ['HS256'], publico: 'admin' }), /não é para nós/);
  });

  it('token sem aud é recusado quando a aplicação exige', () => {
    assert.throws(() => verificar(assinar({}, SEGREDO), SEGREDO, { algoritmos: ['HS256'], publico: 'api' }), /aud/);
  });

  it('o assunto é conferido quando pedido', () => {
    const token = assinar({}, SEGREDO, { assunto: 'ana' });

    assert.doesNotThrow(() => verificar(token, SEGREDO, { algoritmos: ['HS256'], assunto: 'ana' }));
    assert.throws(() => verificar(token, SEGREDO, { algoritmos: ['HS256'], assunto: 'joao' }), /Assunto/);
  });
});

describe('linha de comando', () => {
  it('lê os argumentos', () => {
    const opcoes = lerArgumentos(['assinar', '{"a":1}', '-a', 'HS512', '-k', 'x', '-e', '60', '-t', '5']);

    assert.equal(opcoes.comando, 'assinar');
    assert.equal(opcoes.algoritmo, 'HS512');
    assert.equal(opcoes.chave, 'x');
    assert.equal(opcoes.expira, 60);
    assert.equal(opcoes.tolerancia, 5);
  });

  it('recusa opção e valor inválidos', () => {
    assert.throws(() => lerArgumentos(['--inventada']), /desconhecida/);
    assert.throws(() => lerArgumentos(['ler', 'x', '-k']), /Faltou o valor/);
    assert.throws(() => lerArgumentos(['ler', 'x', '-e', 'abc']), /precisa ser positivo/);
    assert.throws(() => lerArgumentos(['ler', 'x', '-t', '-1']), /não negativo/);
  });

  it('assina e verifica pela linha de comando', async () => {
    const emitido = await rodar(['assinar', '{"sub":"ana"}', '-k', SEGREDO, '-e', '3600']);

    assert.equal(emitido.codigo, 0);
    assert.equal(emitido.saida.split('.').length, 3);

    const conferido = await rodar(['verificar', emitido.saida, '-k', SEGREDO]);

    assert.equal(conferido.codigo, 0);
    assert.match(conferido.saida, /assinatura confere/);
    assert.match(conferido.saida, /sub: "ana"/);
  });

  it('ler não confere nada, e avisa isso', async () => {
    const token = assinar({ sub: 'ana' }, SEGREDO);
    const { codigo, saida } = await rodar(['ler', token]);

    assert.equal(codigo, 0);
    assert.match(saida, /algoritmo: HS256/);
    assert.match(saida, /NÃO conferida/);
  });

  it('chave errada sai com 1', async () => {
    const token = assinar({}, SEGREDO);
    const { codigo, saida } = await rodar(['verificar', token, '-k', 'outra']);

    assert.equal(codigo, 1);
    assert.match(saida, /\[assinatura\]/);
  });

  it('a chave pode vir de arquivo', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const privado = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publico = publicKey.export({ type: 'spki', format: 'pem' });

    const emitido = await rodar(['assinar', '{"sub":"ana"}', '-K', 'chave.pem', '-a', 'RS256'], { 'chave.pem': privado });

    assert.equal(emitido.codigo, 0);

    const conferido = await rodar(['verificar', emitido.saida, '-K', 'pub.pem', '-a', 'RS256'], { 'pub.pem': publico });

    assert.equal(conferido.codigo, 0);
  });

  it('argumentos faltando saem com 2', async () => {
    assert.equal((await rodar([])).codigo, 2);
    assert.equal((await rodar(['voar', 'x'])).codigo, 2);
    assert.equal((await rodar(['ler'])).codigo, 2);
    assert.equal((await rodar(['verificar', 'a.b.c'])).codigo, 2);
    assert.equal((await rodar(['assinar', '{}', '-K', 'sumiu.pem'])).codigo, 2);
  });

  it('a ajuda sai com 0', async () => {
    const { codigo, saida } = await rodar(['--ajuda']);

    assert.equal(codigo, 0);
    assert.match(saida, /assinador-jwt/);
  });

  it('o prazo sai legível', () => {
    assert.match(prazoLegivel(INSTANTE + 30, INSTANTE), /em 30 s/);
    assert.match(prazoLegivel(INSTANTE + 600, INSTANTE), /em 10 min/);
    assert.match(prazoLegivel(INSTANTE - 7200, INSTANTE), /há 2 h/);
  });

  it('a descrição marca o token vencido', () => {
    const lido = lerSemVerificar(assinar({}, SEGREDO, { expiraEm: 10, emitidoEm: INSTANTE }));

    assert.match(descreverToken(lido, INSTANTE + 100), /EXPIRADO/);
    assert.match(descreverToken(lido, INSTANTE), /dentro do prazo/);
  });

  it('o kid aparece quando existe', () => {
    const token = assinar({}, SEGREDO, { cabecalho: { kid: 'chave-2026' } });

    assert.match(descreverToken(lerSemVerificar(token)), /chave \(kid\): chave-2026/);
  });
});

describe('agora', () => {
  it('devolve segundos, não milissegundos', () => {
    const valor = agora();

    assert.ok(Number.isInteger(valor));
    assert.ok(Math.abs(valor - Date.now() / 1000) < 2);
  });
});
