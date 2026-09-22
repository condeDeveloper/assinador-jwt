import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';

import { codificar, codificarJson, decodificar, decodificarTexto, ErroDeBase64url } from '../src/base64url.js';
import { ErroDeAlgoritmo, assinar as assinarBytes, conferir, descrever, iguaisEmTempoConstante } from '../src/algoritmos.js';
import { ErroDeToken, assinar, lerSemVerificar, verificar } from '../src/jwt.js';

/**
 * O exemplo do apêndice A.1 do RFC 7515, byte a byte.
 *
 * A especificação publica o cabeçalho, o corpo, a chave e o token final. Se
 * este projeto reproduz os três pedaços exatamente, a codificação e o HMAC
 * estão certos — não por eu ter escrito um teste que concorda comigo, mas por
 * concordar com o padrão.
 */
const A1 = {
  cabecalho: [123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125],
  corpo: [
    123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
  ],
  chave: [
    3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163,
  ],
  cabecalhoCodificado: 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
  corpoCodificado:
    'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
  assinatura: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
};

describe('o exemplo A.1 do RFC 7515', () => {
  it('o cabeçalho codifica exatamente como está publicado', () => {
    assert.equal(codificar(Buffer.from(A1.cabecalho)), A1.cabecalhoCodificado);
  });

  it('o corpo codifica exatamente como está publicado', () => {
    assert.equal(codificar(Buffer.from(A1.corpo)), A1.corpoCodificado);
  });

  it('a assinatura HS256 bate byte a byte', () => {
    const entrada = `${A1.cabecalhoCodificado}.${A1.corpoCodificado}`;

    assert.equal(assinarBytes('HS256', entrada, Buffer.from(A1.chave)), A1.assinatura);
  });

  it('e o token inteiro é o do padrão', () => {
    const token = `${A1.cabecalhoCodificado}.${A1.corpoCodificado}.${A1.assinatura}`;

    assert.doesNotThrow(() =>
      verificar(token, Buffer.from(A1.chave), {
        algoritmos: ['HS256'],
        agora: 1_300_819_000,
      }),
    );
  });

  it('a decodificação devolve os bytes publicados', () => {
    assert.deepEqual([...decodificar(A1.cabecalhoCodificado)], A1.cabecalho);
    assert.deepEqual([...decodificar(A1.corpoCodificado)], A1.corpo);
  });

  it('o corpo tem as quebras de linha que a especificação mostra', () => {
    // O JSON do exemplo é formatado com `\r\n`, e é isso que prova que a
    // assinatura cobre o **texto**, não o objeto: reserializar mudaria tudo.
    assert.ok(decodificarTexto(A1.corpoCodificado).includes('\r\n'));
  });
});

describe('base64url não é base64', () => {
  it('troca + por -, / por _ e tira o enchimento', () => {
    // Um token com `/` no meio seria lido como caminho numa URL.
    const bytes = Buffer.from([0xfb, 0xef, 0xbe]);

    assert.equal(bytes.toString('base64'), '++++');
    assert.equal(codificar(bytes), '----');
    assert.equal(codificar(Buffer.from([0xff, 0xff, 0xfe])), '___-');
    assert.equal(codificar(Buffer.from('a')), 'YQ');
    assert.ok(!codificar(Buffer.from('a')).includes('='));
  });

  it('vai e volta com qualquer byte', () => {
    for (let tamanho = 0; tamanho < 20; tamanho += 1) {
      const bytes = Buffer.from(Array.from({ length: tamanho }, (_, i) => (i * 37) % 256));

      assert.deepEqual(decodificar(codificar(bytes)), bytes);
    }
  });

  it('recusa caractere que não existe em base64url', () => {
    assert.throws(() => decodificar('abc+def'), ErroDeBase64url);
    assert.throws(() => decodificar('abc/def'), ErroDeBase64url);
    assert.throws(() => decodificar('abc='), ErroDeBase64url);
    assert.throws(() => decodificar(null), ErroDeBase64url);
  });

  it('recusa comprimento impossível', () => {
    // 4 caracteres valem 3 bytes; 1 sobrando é sempre lixo.
    assert.throws(() => decodificar('abcde'), /sobra 1 caractere/);
  });

  it('o JSON precisa ser um objeto', () => {
    assert.throws(() => lerSemVerificar(`${codificarJson([1, 2])}.${codificarJson({})}.x`), /não é um objeto/);
  });
});

describe('as três famílias assinam e conferem', () => {
  const entrada = 'cabecalho.corpo';

  it('HMAC, nos três tamanhos', () => {
    for (const nome of ['HS256', 'HS384', 'HS512']) {
      const assinatura = assinarBytes(nome, entrada, 'segredo bem comprido para o teste');

      assert.equal(conferir(nome, entrada, assinatura, 'segredo bem comprido para o teste'), true);
      assert.equal(conferir(nome, entrada, assinatura, 'outro segredo'), false);
    }
  });

  it('o HMAC bate com o node:crypto direto', () => {
    const esperado = createHmac('sha256', 'chave').update(entrada).digest();

    assert.equal(assinarBytes('HS256', entrada, 'chave'), codificar(esperado));
  });

  it('RSA com PKCS#1 e com PSS', () => {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

    for (const nome of ['RS256', 'RS384', 'RS512', 'PS256', 'PS512']) {
      const assinatura = assinarBytes(nome, entrada, privateKey);

      assert.equal(conferir(nome, entrada, assinatura, publicKey), true, `${nome} não conferiu`);
      assert.equal(conferir(nome, `${entrada}x`, assinatura, publicKey), false);
    }
  });

  it('PSS assina diferente a cada vez, PKCS#1 não', () => {
    // O PSS usa um sal aleatório; é por isso que duas assinaturas do mesmo
    // conteúdo não são iguais, e por isso que comparar assinaturas de PS não
    // faz sentido — só conferir faz.
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

    assert.notEqual(assinarBytes('PS256', entrada, privateKey), assinarBytes('PS256', entrada, privateKey));
    assert.equal(assinarBytes('RS256', entrada, privateKey), assinarBytes('RS256', entrada, privateKey));
  });

  it('ECDSA nas três curvas', () => {
    for (const [nome, curva] of [['ES256', 'prime256v1'], ['ES384', 'secp384r1'], ['ES512', 'secp521r1']]) {
      const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: curva });
      const assinatura = assinarBytes(nome, entrada, privateKey);

      assert.equal(conferir(nome, entrada, assinatura, publicKey), true, `${nome} não conferiu`);
    }
  });

  it('a assinatura ES sai em R‖S cru, não em DER', () => {
    // Em DER ela começa com 0x30 e tem tamanho variável. O JWS exige os dois
    // números concatenados, com 32 bytes cada no ES256 — trocar um pelo outro
    // gera um token que nenhuma outra biblioteca aceita.
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const bytes = decodificar(assinarBytes('ES256', entrada, privateKey));

    assert.equal(bytes.length, 64);
    assert.notEqual(bytes[0], 0x30);
  });

  it('assinatura malformada devolve false em vez de explodir', () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

    assert.equal(conferir('RS256', entrada, 'nao-e-assinatura', publicKey), false);
    assert.equal(conferir('RS256', entrada, 'tem+sinal', publicKey), false);
  });

  it('a comparação do HMAC é em tempo constante', () => {
    const a = Buffer.from('mesmo tamanho');

    assert.equal(iguaisEmTempoConstante(a, Buffer.from('mesmo tamanho')), true);
    assert.equal(iguaisEmTempoConstante(a, Buffer.from('outro conteudo')), false);
    assert.equal(iguaisEmTempoConstante(a, Buffer.from('curto')), false);
    assert.equal(iguaisEmTempoConstante('texto', 'texto'), false);
  });

  it('HMAC sem segredo é recusado', () => {
    assert.throws(() => assinarBytes('HS256', entrada, null), /precisa de um segredo/);
  });
});

describe('o algoritmo none', () => {
  it('nunca é aceito', () => {
    // A falha mais famosa de JWT: bibliotecas que aceitavam um token com
    // "alg":"none" e assinatura vazia davam acesso a quem apagasse a
    // assinatura.
    assert.throws(() => descrever('none'), /não é aceito/);
    assert.throws(() => assinar({ a: 1 }, 'x', { algoritmo: 'none' }), ErroDeAlgoritmo);

    const forjado = `${codificarJson({ alg: 'none', typ: 'JWT' })}.${codificarJson({ admin: true })}.`;

    assert.throws(() => verificar(forjado, 'x', { algoritmos: ['none'] }), ErroDeAlgoritmo);
    assert.throws(() => verificar(forjado, 'x', { algoritmos: ['HS256'] }), /só valem HS256/);
  });

  it('algoritmo desconhecido também', () => {
    assert.throws(() => descrever('HS128'), /desconhecido/);
    assert.throws(() => verificar('a.b.c', 'x', { algoritmos: ['HS128'] }), ErroDeAlgoritmo);
  });
});

describe('troca de algoritmo', () => {
  it('verificar exige a lista de algoritmos aceitos', () => {
    const token = assinar({ a: 1 }, 'segredo');

    assert.throws(() => verificar(token, 'segredo'), /Informe os algoritmos/);
    assert.throws(() => verificar(token, 'segredo', { algoritmos: [] }), ErroDeAlgoritmo);
  });

  it('o ataque clássico não passa', () => {
    // O servidor usa RS256 e a chave pública é, por definição, pública. O
    // atacante troca o cabeçalho para HS256 e assina com essa chave pública
    // como se fosse o segredo do HMAC. Quem confia no "alg" do token aceita.
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = publicKey.export({ type: 'spki', format: 'pem' });

    const cabecalho = codificarJson({ alg: 'HS256', typ: 'JWT' });
    const corpo = codificarJson({ sub: 'admin' });
    const forjado = `${cabecalho}.${corpo}.${assinarBytes('HS256', `${cabecalho}.${corpo}`, pem)}`;

    // O token forjado é válido como HMAC com a chave pública...
    assert.equal(conferir('HS256', `${cabecalho}.${corpo}`, forjado.split('.')[2], pem), true);

    // ...e mesmo assim é recusado, porque aqui só vale o que o servidor disse.
    assert.throws(() => verificar(forjado, pem, { algoritmos: ['RS256'] }), /O token diz "HS256"/);

    const legitimo = assinar({ sub: 'ana' }, privateKey, { algoritmo: 'RS256' });

    assert.equal(verificar(legitimo, pem, { algoritmos: ['RS256'] }).sub, 'ana');
  });
});
