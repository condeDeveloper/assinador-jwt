/**
 * assinador-jwt — JWT e JWS do zero sobre node:crypto.
 */

export {
  ErroDeBase64url,
  codificar,
  codificarJson,
  codificarTexto,
  decodificar,
  decodificarJson,
  decodificarTexto,
} from './base64url.js';

export {
  ALGORITMOS,
  ErroDeAlgoritmo,
  NOMES,
  assinarBytes,
  conferir,
  conferirBytes,
  descrever,
  iguaisEmTempoConstante,
} from './algoritmos.js';

export {
  ErroDeToken,
  REGISTRADAS,
  agora,
  assinar,
  conferirReivindicacoes,
  lerSemVerificar,
  verificar,
} from './jwt.js';
