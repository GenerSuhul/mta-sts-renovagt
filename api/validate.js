import dns from 'node:dns/promises';

export default async function handler(_request, response) {
  const checks = {
    cname: ['mta-sts.renovagt.com', 'CNAME'],
    mtaStsTxt: ['_mta-sts.renovagt.com', 'TXT'],
    tlsRptTxt: ['_smtp._tls.renovagt.com', 'TXT'],
    dmarcTxt: ['_dmarc.renovagt.com', 'TXT'],
    mx: ['renovagt.com', 'MX']
  };

  const results = {};
  for (const [key, [hostname, type]] of Object.entries(checks)) {
    try {
      let value;
      if (type === 'TXT') value = await dns.resolveTxt(hostname);
      else if (type === 'CNAME') value = await dns.resolveCname(hostname);
      else value = await dns.resolveMx(hostname);
      results[key] = { ok: true, hostname, type, value };
    } catch (error) {
      results[key] = { ok: false, hostname, type, error: error?.code ?? String(error) };
    }
  }

  response.setHeader('Cache-Control', 'no-store');
  response.status(200).json(results);
}
