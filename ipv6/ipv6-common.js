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
