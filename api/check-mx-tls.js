import net from 'node:net';
import tls from 'node:tls';

function smtpTlsCheck(host) {
  return new Promise((resolve) => {
    const result = { host };
    const socket = net.createConnection({ host, port: 25 });
    let buffer = '';
    let stage = 'banner';
    const timer = setTimeout(() => {
      result.ok = false;
      result.error = 'timeout';
      socket.destroy();
      resolve(result);
    }, 12000);

    function done(data) {
      clearTimeout(timer);
      resolve({ ...result, ...data });
    }

    socket.setEncoding('utf8');
    socket.on('data', (chunk) => {
      buffer += chunk;
      if (stage === 'banner' && /(^|\n)220[ -]/.test(buffer)) {
        result.banner = buffer.trim();
        buffer = '';
        stage = 'ehlo';
        socket.write('EHLO mta-sts.renovagt.com\r\n');
      } else if (stage === 'ehlo' && /(^|\n)250 /.test(buffer)) {
        result.ehlo = buffer.trim();
        result.starttlsAdvertised = /(^|\n)250[- ]STARTTLS\r?$/mi.test(buffer);
        if (!result.starttlsAdvertised) {
          socket.end();
          done({ ok: false, error: 'STARTTLS not advertised' });
          return;
        }
        buffer = '';
        stage = 'starttls';
        socket.write('STARTTLS\r\n');
      } else if (stage === 'starttls' && /(^|\n)220[ -]/.test(buffer)) {
        socket.removeAllListeners('data');
        const secure = tls.connect({ socket, servername: host, rejectUnauthorized: true }, () => {
          const cert = secure.getPeerCertificate();
          done({
            ok: secure.authorized,
            authorized: secure.authorized,
            authorizationError: secure.authorizationError ?? null,
            protocol: secure.getProtocol(),
            cipher: secure.getCipher()?.name ?? null,
            certificate: {
              subject: cert.subject,
              issuer: cert.issuer,
              valid_from: cert.valid_from,
              valid_to: cert.valid_to,
              subjectaltname: cert.subjectaltname
            }
          });
          secure.end();
        });
        secure.on('error', (error) => done({ ok: false, error: error.message }));
      }
    });
    socket.on('error', (error) => done({ ok: false, error: error.message }));
  });
}

export default async function handler(_request, response) {
  const results = await Promise.all([
    smtpTlsCheck('mx1.hostinger.com'),
    smtpTlsCheck('mx2.hostinger.com')
  ]);
  response.setHeader('Cache-Control', 'no-store');
  response.status(200).json(results);
}
