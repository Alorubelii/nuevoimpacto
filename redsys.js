/**
 * ============================================================================
 *  FIRMA DE PAGOS REDSYS  ·  Nuevo Impacto Soluciones Gráficas
 * ============================================================================
 *
 *  POR QUÉ EXISTE ESTE ARCHIVO
 *  ---------------------------
 *  Redsys obliga a firmar cada pago con una clave secreta que entrega el banco.
 *  Esa clave NO puede estar en la web: cualquiera abriría el código fuente,
 *  la copiaría y podría generar cobros en nombre del comercio. Por eso la firma
 *  se hace aquí, en un servidor, y la web solo recibe el formulario ya firmado.
 *
 *  DÓNDE SE DESPLIEGA
 *  ------------------
 *  Netlify  ->  guarda este archivo en  netlify/functions/redsys.js
 *  Vercel   ->  guarda este archivo en  api/redsys.js
 *  Ambos despliegan desde el mismo repositorio de GitHub que ya usas, y el
 *  plan gratuito sobra para el volumen de una imprenta.
 *
 *  VARIABLES DE ENTORNO (se configuran en el panel de Netlify/Vercel,
 *  nunca en el código):
 *    REDSYS_CLAVE      clave SHA-256 en base64 que da el banco
 *    REDSYS_COMERCIO   número de comercio (FUC), 9 dígitos
 *    REDSYS_TERMINAL   terminal, normalmente 001
 *    REDSYS_ENTORNO    "pruebas" o "real"
 *    WEB_URL           https://tudominio.es  (para las URLs de vuelta)
 *
 *  PRUEBAS ANTES DE COBRAR DE VERDAD
 *  ---------------------------------
 *  El banco da un comercio de pruebas. Con REDSYS_ENTORNO=pruebas se usa el
 *  entorno sis-t de Redsys, donde se paga con tarjetas de prueba y no se mueve
 *  dinero. No pases a "real" hasta que una compra de prueba llegue completa.
 * ============================================================================
 */

const crypto = require('crypto');

const ENTORNOS = {
  pruebas: 'https://sis-t.redsys.es:25443/sis/realizarPago',
  real:    'https://sis.redsys.es/sis/realizarPago'
};

/* --- Firma: 3DES sobre el número de pedido + HMAC SHA256 ------------------ */

function rellenarCeros(texto) {
  const b = Buffer.from(texto, 'utf8');
  const largo = Math.ceil(b.length / 8) * 8;      // múltiplo de 8 bytes
  const salida = Buffer.alloc(largo, 0);
  b.copy(salida);
  return salida;
}

function claveDelPedido(claveBase64, numeroPedido) {
  const clave = Buffer.from(claveBase64, 'base64');
  const iv = Buffer.alloc(8, 0);
  const cifrador = crypto.createCipheriv('des-ede3-cbc', clave, iv);
  cifrador.setAutoPadding(false);
  return Buffer.concat([cifrador.update(rellenarCeros(numeroPedido)), cifrador.final()]);
}

function firmar(claveBase64, numeroPedido, parametrosBase64) {
  return crypto
    .createHmac('sha256', claveDelPedido(claveBase64, numeroPedido))
    .update(parametrosBase64)
    .digest('base64');
}

/* --- Utilidades ---------------------------------------------------------- */

// Redsys admite 12 caracteres y los 4 primeros deben ser numéricos.
// "NI-2026-0009" no vale, así que se convierte a algo como "00090826NI".
function pedidoRedsys(referencia) {
  const digitos = (referencia.match(/\d/g) || []).join('').slice(-8).padStart(8, '0');
  const letras = (referencia.match(/[A-Za-z]/g) || []).join('').toUpperCase().slice(0, 4);
  return (digitos + letras).slice(0, 12);
}

const base64Url = s => s.replace(/-/g, '+').replace(/_/g, '/');

/* --- Manejador ----------------------------------------------------------- */

exports.handler = async (evento) => {
  const cabeceras = {
    'Access-Control-Allow-Origin': process.env.WEB_URL || '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (evento.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cabeceras, body: '' };
  if (evento.httpMethod !== 'POST') {
    return { statusCode: 405, headers: cabeceras, body: JSON.stringify({ error: 'Solo POST' }) };
  }

  const clave = process.env.REDSYS_CLAVE;
  if (!clave) {
    return { statusCode: 500, headers: cabeceras,
             body: JSON.stringify({ error: 'Falta REDSYS_CLAVE en las variables de entorno' }) };
  }

  let datos;
  try { datos = JSON.parse(evento.body || '{}'); }
  catch { return { statusCode: 400, headers: cabeceras, body: JSON.stringify({ error: 'JSON inválido' }) }; }

  const { referencia, importe, descripcion } = datos;

  // El importe llega en euros y Redsys lo quiere en céntimos, sin decimales.
  const centimos = Math.round(Number(importe) * 100);
  if (!referencia || !Number.isFinite(centimos) || centimos <= 0) {
    return { statusCode: 400, headers: cabeceras,
             body: JSON.stringify({ error: 'Faltan referencia o importe válidos' }) };
  }

  // IMPORTANTE: el importe debería recalcularse aquí a partir del pedido
  // guardado en Firestore, no fiarse del que manda el navegador. Mientras el
  // cobro se revise a mano antes de producir, el riesgo es asumible; en cuanto
  // se automatice, cambia esto por una lectura del pedido en la base de datos.

  const pedido = pedidoRedsys(String(referencia));
  const web = process.env.WEB_URL || '';

  const parametros = {
    DS_MERCHANT_AMOUNT: String(centimos),
    DS_MERCHANT_ORDER: pedido,
    DS_MERCHANT_MERCHANTCODE: process.env.REDSYS_COMERCIO,
    DS_MERCHANT_CURRENCY: '978',              // euros
    DS_MERCHANT_TRANSACTIONTYPE: '0',         // autorización
    DS_MERCHANT_TERMINAL: process.env.REDSYS_TERMINAL || '001',
    DS_MERCHANT_PRODUCTDESCRIPTION: String(descripcion || 'Pedido ' + referencia).slice(0, 125),
    DS_MERCHANT_MERCHANTURL: `${web}/.netlify/functions/redsys-aviso`,
    DS_MERCHANT_URLOK: `${web}/?pago=ok&ref=${encodeURIComponent(referencia)}`,
    DS_MERCHANT_URLKO: `${web}/?pago=ko&ref=${encodeURIComponent(referencia)}`
  };

  const parametrosBase64 = Buffer.from(JSON.stringify(parametros), 'utf8').toString('base64');

  return {
    statusCode: 200,
    headers: cabeceras,
    body: JSON.stringify({
      url: ENTORNOS[process.env.REDSYS_ENTORNO === 'real' ? 'real' : 'pruebas'],
      Ds_SignatureVersion: 'HMAC_SHA256_V1',
      Ds_MerchantParameters: parametrosBase64,
      Ds_Signature: firmar(clave, pedido, parametrosBase64),
      pedidoRedsys: pedido
    })
  };
};

/* ============================================================================
 *  SEGUNDA FUNCIÓN: aviso del banco (guárdala como redsys-aviso.js)
 *  ----------------------------------------------------------------------------
 *  Redsys avisa del resultado a este servidor, no al navegador. Es la única
 *  confirmación fiable: si el cliente cierra el navegador tras pagar, la
 *  vuelta a la web no llega, pero este aviso sí.
 *
 *  exports.handler = async (evento) => {
 *    const p = new URLSearchParams(evento.body);
 *    const parametros = p.get('Ds_MerchantParameters');
 *    const firmaRecibida = base64Url(p.get('Ds_Signature'));
 *    const datos = JSON.parse(Buffer.from(parametros, 'base64').toString('utf8'));
 *
 *    // comprobar que la firma es del banco y no de un tercero
 *    const esperada = firmar(process.env.REDSYS_CLAVE, datos.Ds_Order, parametros);
 *    if (esperada !== firmaRecibida) return { statusCode: 403, body: 'Firma incorrecta' };
 *
 *    const codigo = parseInt(datos.Ds_Response, 10);
 *    const pagado = codigo >= 0 && codigo <= 99;   // 0000-0099 = autorizado
 *
 *    // Aquí se marca el pedido como cobrado en Firestore:
 *    //   await db.collection('sitio').doc('datos') ... buscar por Ds_Order
 *    //   y poner pago.estado = 'Pagado'
 *
 *    return { statusCode: 200, body: 'OK' };   // Redsys solo espera un 200
 *  };
 * ============================================================================
 */
