/* ---------------- ipv6 helpers, shared by the map and calculator views ---------------- */
const FULL_MASK = (1n<<128n)-1n;

function sizeOf(prefixLen){ return 1n << BigInt(128-prefixLen); }

function networkAddress(addr, prefixLen){
  if(prefixLen<=0) return 0n;
  if(prefixLen>=128) return addr & FULL_MASK;
  const hostBits = BigInt(128-prefixLen);
  return addr & (FULL_MASK ^ ((1n<<hostBits)-1n));
}

function parseIPv6(str){
  str = str.trim();
  if(str==='') throw new Error('empty address');
  if((str.match(/::/g)||[]).length>1) throw new Error('address may only contain one "::"');
  let groups;
  if(str.includes('::')){
    const [leftStr, rightStr] = str.split('::');
    const left = leftStr ? leftStr.split(':') : [];
    const right = rightStr ? rightStr.split(':') : [];
    const missing = 8 - left.length - right.length;
    if(missing<0) throw new Error('too many groups for compressed address');
    groups = [...left, ...Array(missing).fill('0'), ...right];
  } else {
    groups = str.split(':');
  }
  if(groups.length!==8) throw new Error('expected 8 groups, got '+groups.length);
  let addr = 0n;
  for(const g of groups){
    if(g==='' || !/^[0-9a-fA-F]{1,4}$/.test(g)) throw new Error('invalid group "'+g+'"');
    addr = (addr<<16n) | BigInt(parseInt(g,16));
  }
  return addr;
}

function parseCIDR(str){
  str = str.trim();
  const parts = str.split('/');
  if(parts.length!==2) throw new Error('expected format address/prefix, e.g. 2001:db8::/32');
  const addr = parseIPv6(parts[0]);
  const prefixLen = parseInt(parts[1],10);
  if(!Number.isInteger(prefixLen) || prefixLen<0 || prefixLen>128) throw new Error('prefix length must be between 0 and 128');
  return {addr, prefixLen};
}

function toHextets(addr){
  const hex = addr.toString(16).padStart(32,'0');
  const groups = [];
  for(let i=0;i<8;i++) groups.push(hex.slice(i*4,i*4+4));
  return groups;
}

function formatIPv6(addr){
  const raw = toHextets(addr);
  const values = raw.map(g=>parseInt(g,16));
  let bestStart=-1,bestLen=0,curStart=-1,curLen=0;
  for(let i=0;i<8;i++){
    if(values[i]===0){
      if(curStart===-1) curStart=i;
      curLen++;
      if(curLen>bestLen){ bestLen=curLen; bestStart=curStart; }
    } else { curStart=-1; curLen=0; }
  }
  const hexGroups = values.map(v=>v.toString(16));
  if(bestLen>=2){
    const before = hexGroups.slice(0,bestStart);
    const after = hexGroups.slice(bestStart+bestLen);
    const left = before.join(':');
    const right = after.join(':');
    if(left==='' && right==='') return '::';
    if(left==='') return '::'+right;
    if(right==='') return left+'::';
    return left+'::'+right;
  }
  return hexGroups.join(':');
}

function fmtBig(n){ return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ','); }

/* ---------------- RDAP (Registration Data Access Protocol) ---------------- */
/* IANA's bootstrap file maps CIDR ranges to the RIR that's authoritative for RDAP over them
   (RFC 7484) — fetched once and cached, then resolved locally per address via longest-prefix
   match so any block (not just ones we already classified) can be looked up. */
const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/ipv6.json';
let rdapBootstrapPromise = null;
function loadRdapBootstrap(){
  if(!rdapBootstrapPromise){
    rdapBootstrapPromise = fetch(RDAP_BOOTSTRAP_URL).then(res=>{
      if(!res.ok) throw new Error('RDAP bootstrap fetch failed (HTTP '+res.status+')');
      return res.json();
    });
    rdapBootstrapPromise.catch(()=>{ rdapBootstrapPromise = null; });
  }
  return rdapBootstrapPromise;
}

function findRdapBase(bootstrap, addr){
  let best = null, bestPrefixLen = -1;
  for(const [cidrs, urls] of bootstrap.services){
    for(const cidr of cidrs){
      let base, prefixLen;
      try{ ({addr:base, prefixLen} = parseCIDR(cidr)); base = networkAddress(base, prefixLen); }
      catch(e){ continue; }
      if(addr>=base && addr<base+sizeOf(prefixLen) && prefixLen>bestPrefixLen){
        bestPrefixLen = prefixLen;
        best = urls[0];
      }
    }
  }
  return best;
}

async function rdapUrlFor(addr, prefixLen){
  const bootstrap = await loadRdapBootstrap();
  const base = findRdapBase(bootstrap, addr);
  if(!base) return null;
  const withSlash = base.endsWith('/') ? base : base+'/';
  return withSlash + 'ip/' + formatIPv6(addr) + (prefixLen!=null ? '/'+prefixLen : '');
}

const rdapCache = new Map();
/* returns a promise of the raw RDAP JSON for a block; in-flight/successful lookups are cached
   so re-selecting the same tile doesn't re-fetch, while transient failures are evicted so a
   retry actually retries */
function fetchRdap(addr, prefixLen){
  const key = addr.toString()+'/'+prefixLen;
  if(rdapCache.has(key)) return rdapCache.get(key);
  const promise = (async()=>{
    const url = await rdapUrlFor(addr, prefixLen);
    if(!url){
      const err = new Error('No RDAP service is delegated for this range — it may be an IETF-reserved block rather than an RIR allocation.');
      err.rdapNotFound = true;
      throw err;
    }
    const res = await fetch(url, {headers:{Accept:'application/rdap+json'}});
    if(res.status===404){
      const err = new Error('No RDAP record exists for this exact range (it may only exist for a larger covering block).');
      err.rdapNotFound = true;
      throw err;
    }
    if(!res.ok) throw new Error('RDAP request failed (HTTP '+res.status+')');
    const json = await res.json();
    json.__rdapUrl = url;
    return json;
  })();
  rdapCache.set(key, promise);
  promise.catch(err=>{ if(!err || !err.rdapNotFound) rdapCache.delete(key); });
  return promise;
}

function findVCardValue(vcardArray, propName){
  if(!vcardArray || !Array.isArray(vcardArray[1])) return null;
  const prop = vcardArray[1].find(p=>p[0]===propName);
  return prop ? prop[3] : null;
}
/* best-effort extraction of the fields worth showing — RIRs vary somewhat in how they
   populate entities/vcards, so every field here is optional */
function normalizeRdap(json){
  const events = json.events || [];
  const findEvent = action => { const e = events.find(e=>e.eventAction===action); return e ? e.eventDate : null; };
  const entities = json.entities || [];
  const abuseEntity = entities.find(e=> (e.roles||[]).includes('abuse'));
  const registrantEntity = entities.find(e=> (e.roles||[]).includes('registrant')) || entities[0];
  const abuseEmail = abuseEntity ? findVCardValue(abuseEntity.vcardArray, 'email') : null;
  return {
    handle: json.handle || null,
    name: json.name || (registrantEntity && findVCardValue(registrantEntity.vcardArray,'fn')) || null,
    country: json.country || null,
    type: json.type || null,
    status: Array.isArray(json.status) && json.status.length ? json.status.join(', ') : null,
    registered: findEvent('registration'),
    lastChanged: findEvent('last changed'),
    abuseEmail,
    remarks: (json.remarks||[]).map(r=>({title:r.title||null, description:(r.description||[]).join(' ')})).filter(r=>r.description),
    selfUrl: json.__rdapUrl || (((json.links||[]).find(l=>l.rel==='self')||{}).href) || null
  };
}
