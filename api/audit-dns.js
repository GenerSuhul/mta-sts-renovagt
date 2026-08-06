const queries = [
  ['NS','renovagt.com','NS'],
  ['DS','renovagt.com','DS'],
  ['DNSKEY','renovagt.com','DNSKEY'],
  ['CAA','renovagt.com','CAA'],
  ['SPF','renovagt.com','TXT'],
  ['DMARC','_dmarc.renovagt.com','TXT'],
  ['MTA_STS','_mta-sts.renovagt.com','TXT'],
  ['TLS_RPT','_smtp._tls.renovagt.com','TXT'],
  ['DKIM_RESEND','resend._domainkey.renovagt.com','TXT'],
  ['DKIM_HOSTINGER_A','hostingermail-a._domainkey.renovagt.com','CNAME'],
  ['DKIM_HOSTINGER_B','hostingermail-b._domainkey.renovagt.com','CNAME'],
  ['DKIM_HOSTINGER_C','hostingermail-c._domainkey.renovagt.com','CNAME'],
  ['DKIM_DEFAULT','default._domainkey.renovagt.com','TXT'],
  ['DKIM_SELECTOR1','selector1._domainkey.renovagt.com','TXT'],
  ['DKIM_SELECTOR2','selector2._domainkey.renovagt.com','TXT']
];

async function doh(name, type) {
  const url = new URL('https://cloudflare-dns.com/dns-query');
  url.searchParams.set('name', name);
  url.searchParams.set('type', type);
  const response = await fetch(url, { headers: { accept: 'application/dns-json' } });
  const data = await response.json();
  return {
    status: data.Status,
    authenticated_data: data.AD,
    answer: (data.Answer ?? []).map(({ name, type, TTL, data }) => ({ name, type, TTL, data }))
  };
}

export default async function handler(_request, response) {
  const results = {};
  for (const [key, name, type] of queries) {
    try {
      results[key] = await doh(name, type);
    } catch (error) {
      results[key] = { error: error?.message ?? String(error) };
    }
  }
  response.setHeader('Cache-Control', 'no-store');
  response.status(200).json(results);
}
