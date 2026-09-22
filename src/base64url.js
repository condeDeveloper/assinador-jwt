/**
 * Base64url.
 *
 * Não é base64. As diferenças são três, e cada uma tem um motivo:
 *
 * - `+` vira `-` e `/` vira `_`, porque um JWT viaja em URL e em cabeçalho, e
 *   `/` ali seria lido como separador de caminho.
 * - **O `=` do fim some.** Ele só existe para completar o bloco de 4, e o
 *   tamanho já diz quantos bytes vieram.
 * - Não há quebra de linha a cada 76 caracteres, herança do MIME que não faz
 *   sentido num token.
 *
 * Trocar base64url por base64 é o erro mais comum de quem implementa JWT na
 * mão. O token "quase funciona": falha só quando o conteúdo por acaso produz
 * um `+` ou uma `/`, o que acontece em mais ou menos um token a cada poucos.
 */

/** O `=` do fim é enchimento e não entra. */
export function codificar(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);

  return buffer.toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

/** Codifica um texto UTF-8. */
export function codificarTexto(texto) {
  return codificar(Buffer.from(texto, 'utf8'));
}

/** Codifica um objeto como JSON. */
export function codificarJson(valor) {
  return codificarTexto(JSON.stringify(valor));
}

/** O texto não é base64url válido. */
export class ErroDeBase64url extends Error {
  constructor(mensagem) {
    super(mensagem);
    this.name = 'ErroDeBase64url';
  }
}

/** Só estes caracteres existem em base64url. */
const VALIDO = /^[A-Za-z0-9_-]*$/;

/** Decodifica para bytes. */
export function decodificar(texto) {
  if (typeof texto !== 'string' || !VALIDO.test(texto)) {
    throw new ErroDeBase64url(`Não é base64url: ${JSON.stringify(String(texto).slice(0, 40))}`);
  }

  // Um pedaço de 1 caractere não corresponde a byte nenhum: 4 caracteres
  // valem 3 bytes, e 1 sobrando é sempre lixo.
  if (texto.length % 4 === 1) {
    throw new ErroDeBase64url('Comprimento impossível para base64url (sobra 1 caractere).');
  }

  return Buffer.from(texto.replaceAll('-', '+').replaceAll('_', '/'), 'base64');
}

/** Decodifica para texto UTF-8. */
export function decodificarTexto(texto) {
  return decodificar(texto).toString('utf8');
}

/** Decodifica um JSON, dizendo qual parte falhou. */
export function decodificarJson(texto, parte = 'parte') {
  const cru = decodificarTexto(texto);

  try {
    const valor = JSON.parse(cru);

    if (valor === null || typeof valor !== 'object' || Array.isArray(valor)) {
      throw new Error('não é um objeto');
    }

    return valor;
  } catch (erro) {
    throw new ErroDeBase64url(`O ${parte} do token não é um objeto JSON válido: ${erro.message}`);
  }
}
