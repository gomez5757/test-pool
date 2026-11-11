'use strict';
// node cifra.cjs c|d entrada salida  (clave hex de 32 bytes en la variable CLAVE)
const fs = require('node:fs');
const crypto = require('node:crypto');
const [modo, entrada, salida] = process.argv.slice(2);
const clave = Buffer.from(String(process.env.CLAVE || '').trim(), 'hex');
if (clave.length !== 32 || !['c', 'd'].includes(modo)) { console.error('uso incorrecto'); process.exit(2); }
const datos = fs.readFileSync(entrada);
if (modo === 'c') {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', clave, iv);
  const cuerpo = Buffer.concat([c.update(datos), c.final()]);
  fs.writeFileSync(salida, Buffer.concat([iv, c.getAuthTag(), cuerpo]));
} else {
  const d = crypto.createDecipheriv('aes-256-gcm', clave, datos.subarray(0, 12));
  d.setAuthTag(datos.subarray(12, 28));
  fs.writeFileSync(salida, Buffer.concat([d.update(datos.subarray(28)), d.final()]));
}
