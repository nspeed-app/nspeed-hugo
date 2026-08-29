/* ---------------- tab / cross-view navigation ---------------- */
function getParams(){ return new URLSearchParams(location.search); }
function setParam(key, value){
  const p = getParams();
  if(value===null || value===undefined || value==='') p.delete(key); else p.set(key, value);
  const qs = p.toString();
  history.replaceState(null, '', location.pathname + (qs ? '?'+qs : ''));
}
let activeTab = 'map';
function setActiveTab(tab, opts){
  opts = opts || {};
  activeTab = tab;
  document.getElementById('view-map').hidden = tab!=='map';
  document.getElementById('view-calc').hidden = tab!=='calc';
  document.getElementById('tabBtnMap').classList.toggle('active', tab==='map');
  document.getElementById('tabBtnCalc').classList.toggle('active', tab==='calc');
  if(opts.updateUrl!==false) setParam('view', tab==='calc' ? 'calc' : null);
}
document.getElementById('tabBtnMap').addEventListener('click', ()=>setActiveTab('map'));
document.getElementById('tabBtnCalc').addEventListener('click', ()=>setActiveTab('calc'));

function openInCalculator(cidr){
  document.getElementById('cidrInput').value = cidr;
  document.getElementById('calcBtn').click();
  setActiveTab('calc');
  setParam('net', cidr);
  setParam('tree', null);
}

/* ---------------- classification ---------------- */
function classifyTop(allocation){
  const a = allocation.toLowerCase();
  if(a.includes('global unicast')) return {category:'global'};
  if(a.includes('unique local')) return {category:'unique'};
  if(a.includes('link-scoped') || a.includes('link-local')) return {category:'link'};
  if(a.includes('multicast')) return {category:'multicast'};
  return {category:'reserved'};
}
function classifyUnicast(designation, status){
  if(status==='RESERVED'){
    if(designation==='Documentation') return {category:'documentation'};
    return {category:'reserved'};
  }
  switch(designation){
    case 'APNIC': return {category:'apnic'};
    case 'ARIN': return {category:'arin'};
    case 'RIPE NCC': return {category:'ripe'};
    case 'LACNIC': return {category:'lacnic'};
    case 'AFRINIC': return {category:'afrinic'};
    case '6to4': return {category:'sixtofour'};
    case 'Documentation': return {category:'documentation'};
    case 'IANA': return {category:'iana'};
    default: return {category:'reserved'};
  }
}

const CATEGORY_META = {
  reserved:      {label:'Reserved by IETF', color:'var(--c-reserved)', textDim:true},
  global:        {label:'Global Unicast',   color:'var(--c-global)'},
  unique:        {label:'Unique Local',     color:'var(--c-unique)'},
  link:          {label:'Link-Scoped',      color:'var(--c-link)'},
  multicast:     {label:'Multicast',        color:'var(--c-multicast)'},
  apnic:         {label:'APNIC',            color:'var(--c-apnic)'},
  arin:          {label:'ARIN',             color:'var(--c-arin)'},
  ripe:          {label:'RIPE NCC',         color:'var(--c-ripe)'},
  lacnic:        {label:'LACNIC',           color:'var(--c-lacnic)'},
  afrinic:       {label:'AFRINIC',          color:'var(--c-afrinic)'},
  iana:          {label:'IANA-held',        color:'var(--c-iana)'},
  sixtofour:     {label:'6to4 (historic)',  color:'var(--c-sixtofour)'},
  documentation: {label:'Documentation',    color:'var(--c-documentation)'},
  unallocated:   {label:'Unallocated',      color:'var(--c-unallocated)', textDim:true}
};

function fmtAddrCount(n){
  const asNum = Number(n);
  if(asNum < 1e15) return fmtBig(n)+' addresses';
  const [mantissa, exponent] = asNum.toExponential(2).split('e+');
  return '≈'+mantissa+' × 10'+sup(exponent)+' addresses';
}
function sup(n){ return '<sup>'+n+'</sup>'; }
function fmtPct(frac){
  if(frac*100>=0.01) return (frac*100).toFixed(frac<0.1?4:2)+'%';
  return (frac*100).toExponential(2)+'%';
}

/* ---------------- resolve + gap fill ---------------- */
function resolveTop(raw){
  return raw.map(e=>{
    const {addr,prefixLen} = parseCIDR(e.prefix);
    const base = networkAddress(addr,prefixLen);
    const cls = classifyTop(e.allocation);
    return {kind:'top', prefix:e.prefix, base, prefixLen, size:sizeOf(prefixLen), allocation:e.allocation, note:e.note, ...cls};
  });
}
function resolveUnicast(raw){
  return raw.map(e=>{
    const {addr,prefixLen} = parseCIDR(e.prefix);
    const base = networkAddress(addr,prefixLen);
    const cls = classifyUnicast(e.designation, e.status);
    return {kind:'unicast', prefix:e.prefix, base, prefixLen, size:sizeOf(prefixLen), designation:e.designation, date:e.date, status:e.status, note:e.note, ...cls};
  });
}
/* per-RIR public record lookup — friendly web UI where one exists, that RIR's RDAP endpoint otherwise */
const RIR_LINKS = {
  ARIN:      (base,len)=> `https://search.arin.net/rdap/?query=${encodeURIComponent(formatIPv6(base)+'/'+len)}`,
  'RIPE NCC':(base,len)=> `https://apps.db.ripe.net/db-web-ui/query?searchtext=${encodeURIComponent(formatIPv6(base)+'/'+len)}`,
  APNIC:     (base,len)=> `https://rdap.apnic.net/ip/${formatIPv6(base)}/${len}`,
  LACNIC:    (base,len)=> `https://rdap.lacnic.net/rdap/ip/${formatIPv6(base)}/${len}`,
  AFRINIC:   (base,len)=> `https://rdap.afrinic.net/rdap/ip/${formatIPv6(base)}/${len}`
};

function resolveSpecial(raw){
  return raw.map(e=>{
    const {addr,prefixLen} = parseCIDR(e.prefix);
    const base = networkAddress(addr,prefixLen);
    return {kind:'special', prefix:e.prefix, base, prefixLen, size:sizeOf(prefixLen), name:e.name, rfc:e.rfc, date:e.date, term:e.term};
  });
}
function trailingZeroBits(x){
  if(x===0n) return 128;
  let n=0;
  while((x & 1n)===0n){ x >>= 1n; n++; }
  return n;
}
/* an arbitrary [start,end) range rarely lines up with a single power-of-2 block —
   decompose it into the minimal set of CIDR-aligned blocks, same as route summarization */
function rangeToCidrBlocks(start, end){
  const blocks = [];
  let cursor = start;
  while(cursor<end){
    let alignBits = trailingZeroBits(cursor);
    let blockSize = 1n << BigInt(alignBits);
    while(blockSize>end-cursor){ blockSize >>= 1n; alignBits--; }
    blocks.push({base:cursor, size:blockSize, prefixLen:128-alignBits});
    cursor += blockSize;
  }
  return blocks;
}
function gapFill(parentBase, parentPrefixLen, children){
  const parentSize = sizeOf(parentPrefixLen);
  const parentEnd = parentBase + parentSize;
  const sorted = children.slice().sort((a,b)=> a.base<b.base?-1:(a.base>b.base?1:0));
  const out = [];
  let cursor = parentBase;
  function pushGap(gapStart, gapEnd){
    for(const blk of rangeToCidrBlocks(gapStart, gapEnd)){
      out.push({kind:'gap', base:blk.base, size:blk.size, prefixLen:blk.prefixLen, prefix:formatIPv6(blk.base)+'/'+blk.prefixLen, category:'unallocated', allocation:'Unallocated', note:'Not yet listed in this IANA registry as an allocation.'});
    }
  }
  for(const c of sorted){
    if(c.base>cursor) pushGap(cursor, c.base);
    out.push(c);
    const cEnd = c.base+c.size;
    if(cEnd>cursor) cursor=cEnd;
  }
  if(cursor<parentEnd) pushGap(cursor, parentEnd);
  return out;
}

let topResolved = gapFill(0n,0,resolveTop(TOP_RAW));
let unicastParent = parseCIDR('2000::/3');
let unicastResolved = gapFill(networkAddress(unicastParent.addr,3), 3, resolveUnicast(UNICAST_RAW));
let specialResolved = resolveSpecial(SPECIAL_RAW).sort((a,b)=> a.base<b.base?-1:(a.base>b.base?1:0));

/* one flat, fully-tiling dataset: the "2000::/3 Global Unicast" placeholder from the top-level
   registry is replaced by its actual RIR breakdown, so the whole address space is a single
   treemap — drilling in (scroll) is how you get from the continent-sized blocks down to the
   individual RIR allocations, instead of a separate click-to-swap-dataset view. */
let allResolved = topResolved.flatMap(e => e.category==='global' ? unicastResolved : [e]);

/* special-purpose entries don't tile the space — they nest inside top/unicast blocks, so
   look up whichever ones fall entirely within the currently selected tile's range */
function findSpecialWithin(base, size){
  const end = base+size;
  return specialResolved.filter(s => s.base>=base && (s.base+s.size)<=end);
}

/* ---------------- squarified treemap ---------------- */
/* plain squarify only guarantees equal AREA for equal-valued items — two tiles of the
   same address count can still land in different rows and come out as different
   rectangles (one wide, one tall). Pack same-valued items as a single super-tile so
   squarify places them together, then split that rectangle into a uniform grid so
   every tied tile renders as an identical shape. */
function subdivideGrid(x,y,w,h,n){
  if(n<=0) return [];
  if(n===1) return [{x,y,w,h}];
  let rows = Math.round(Math.sqrt(n * h / w));
  rows = Math.max(1, Math.min(n, rows));
  const base = Math.floor(n/rows), extra = n % rows;
  const cellH = h/rows;
  const cells = [];
  let cy = y;
  for(let ri=0; ri<rows; ri++){
    const cnt = base + (ri<extra ? 1 : 0);
    const cellW = w/cnt;
    let cx = x;
    for(let ci=0; ci<cnt; ci++){
      cells.push({x:cx, y:cy, w:cellW, h:cellH});
      cx += cellW;
    }
    cy += cellH;
  }
  return cells;
}
function squarify(items, x0,y0,x1,y1){
  const groups = new Map();
  for(const it of items){
    if(!groups.has(it.value)) groups.set(it.value, []);
    groups.get(it.value).push(it);
  }
  const packItems = [];
  for(const [value, members] of groups){
    packItems.push(members.length===1 ? members[0] : {__group:members, value:value*members.length});
  }

  const total = packItems.reduce((s,i)=>s+i.value,0);
  if(total<=0) return [];
  const area = (x1-x0)*(y1-y0);
  let rest = packItems.slice().sort((a,b)=>b.value-a.value).map(i=>({...i, area: i.value/total*area}));
  const result = [];
  let rectX=x0, rectY=y0, rectW=x1-x0, rectH=y1-y0;
  let row = [];

  function worst(r, length){
    if(r.length===0) return Infinity;
    const sum = r.reduce((s,x)=>s+x.area,0);
    const mx = Math.max(...r.map(x=>x.area));
    const mn = Math.min(...r.map(x=>x.area));
    const s2=sum*sum, l2=length*length;
    return Math.max((l2*mx)/s2, s2/(l2*mn));
  }
  function layoutRow(r, length){
    const rowArea = r.reduce((s,x)=>s+x.area,0);
    const thickness = length>0 ? rowArea/length : 0;
    if(rectW>=rectH){
      let cy=rectY;
      for(const it of r){
        const h = thickness>0 ? it.area/thickness : 0;
        result.push({...it, x:rectX, y:cy, w:thickness, h});
        cy+=h;
      }
      rectX+=thickness; rectW-=thickness;
    } else {
      let cx=rectX;
      for(const it of r){
        const w = thickness>0 ? it.area/thickness : 0;
        result.push({...it, x:cx, y:rectY, w, h:thickness});
        cx+=w;
      }
      rectY+=thickness; rectH-=thickness;
    }
  }

  while(rest.length>0){
    const length = Math.min(rectW, rectH);
    const testRow = [...row, rest[0]];
    if(row.length===0 || worst(row,length) >= worst(testRow,length)){
      row = testRow; rest = rest.slice(1);
    } else {
      layoutRow(row, Math.min(rectW,rectH));
      row = [];
    }
  }
  if(row.length>0) layoutRow(row, Math.min(rectW,rectH));

  const expanded = [];
  for(const r of result){
    if(r.__group){
      const cells = subdivideGrid(r.x, r.y, r.w, r.h, r.__group.length);
      r.__group.forEach((member, idx)=> expanded.push({...member, ...cells[idx]}));
    } else {
      expanded.push(r);
    }
  }
  return expanded;
}

/* ---------------- map view state + render ---------------- */
let pulseTarget = null;     // base BigInt of tile to pulse-highlight after a locate
let selectedBase = null;    // base BigInt of the currently selected (clicked/tapped) tile

const svg = document.getElementById('mapSvg');
const legendEl = document.getElementById('legend');
const breadcrumbEl = document.getElementById('breadcrumb');
const detailEl = document.getElementById('detailCard');

function renderBreadcrumb(){
  breadcrumbEl.innerHTML = '';
  const root = document.createElement('span');
  root.className = 'crumb';
  root.textContent = 'Whole IPv6 address space (::/0)';
  root.title = 'Reset zoom to the full address space';
  root.addEventListener('click', ()=>{ resetDrillImmediate(); drawTiles(); });
  breadcrumbEl.appendChild(root);
}

function showDetail(entry){
  if(!entry){ detailEl.innerHTML = '<div class="detail-empty">Click or tap a block to see its details.</div>'; return; }
  const meta = CATEGORY_META[entry.category];
  const pctTotal = fmtPct(Number(entry.size)/Number(1n<<128n));
  const prefixLabel = entry.prefix ? (entry.prefix) : (formatIPv6(entry.base)+' – '+formatIPv6(entry.base+entry.size-1n));
  const hostBits = entry.prefixLen!==undefined ? (128-entry.prefixLen) : null;
  const sizeLabel = hostBits!==null ? ('2'+sup(hostBits)+' addresses') : fmtAddrCount(entry.size);

  let rows = '';
  if(entry.kind==='top'){
    rows = `<div><span class="k">Allocation</span><span class="v">${entry.allocation}</span></div>
            <div><span class="k">Total addresses</span><span class="v">${sizeLabel}</span></div>
            <div><span class="k">Share of IPv6 space</span><span class="v">${pctTotal}</span></div>`;
  } else if(entry.kind==='unicast'){
    const rirLink = RIR_LINKS[entry.designation];
    const designationHtml = rirLink
      ? `${entry.designation} <a href="${rirLink(entry.base, entry.prefixLen)}" target="_blank" rel="noopener noreferrer">look up ↗</a>`
      : entry.designation;
    rows = `<div><span class="k">Designation</span><span class="v">${designationHtml}</span></div>
            <div><span class="k">Status</span><span class="v">${entry.status}</span></div>
            <div><span class="k">Allocated</span><span class="v">${entry.date}</span></div>
            <div><span class="k">Total addresses</span><span class="v">${sizeLabel}</span></div>
            <div><span class="k">Share of IPv6 space</span><span class="v">${pctTotal}</span></div>`;
  } else {
    rows = `<div><span class="k">Status</span><span class="v">Unallocated</span></div>
            <div><span class="k">Total addresses</span><span class="v">${sizeLabel}</span></div>
            <div><span class="k">Share of IPv6 space</span><span class="v">${pctTotal}</span></div>`;
  }

  const specialMatches = findSpecialWithin(entry.base, entry.size);
  const specialHtml = specialMatches.length ? `
    <div class="detail-special">
      <span class="k">Special-purpose registrations in this range (IANA)</span>
      <ul>${specialMatches.map(s=>`<li><span class="sp-prefix">${s.prefix}</span><span class="sp-name">${s.name}</span><span class="sp-rfc">${s.rfc}</span></li>`).join('')}</ul>
    </div>` : '';

  const openInCalcHtml = entry.prefix
    ? `<div class="detail-actions"><button class="btn ghost small" id="openInCalcBtn">Open in Calculator →</button></div>`
    : '';

  detailEl.innerHTML = `
    <div class="detail-top">
      <div class="detail-prefix">${prefixLabel}</div>
      <div class="detail-tag" style="background:${meta.color};color:#0A0D12">${meta.label}</div>
    </div>
    <div class="detail-grid">${rows}</div>
    ${entry.note ? `<div class="detail-note">${entry.note}</div>` : ''}
    ${specialHtml}
    ${openInCalcHtml}
  `;

  if(entry.prefix){
    document.getElementById('openInCalcBtn').addEventListener('click', ()=> openInCalculator(entry.prefix));
  }
}

function renderLegend(list){
  const cats = [...new Set(list.map(e=>e.category))];
  legendEl.innerHTML = cats.map(c=>{
    const m = CATEGORY_META[c];
    return `<span><i style="background:${m.color}"></i>${m.label}</span>`;
  }).join('');
}

/* squarify() lays every tile out once over the full MAP_BOUNDS rectangle ("virtual space").
   Scrolling doesn't visually scale that layout (which would blow up text/strokes) — instead it
   narrows a "drill window" onto a sub-region of the virtual space and remaps that sub-region to
   fill MAP_BOUNDS again, so tiles (and their labels, recomputed from their new mapped size) are
   redrawn at their true drilled-in size, same as if the map had been laid out that way natively. */
const MAP_BOUNDS = {x0:4, y0:4, x1:992, y1:592};
let cachedRects = [];                     // full layout for the current list, in virtual space
let drillView = {...MAP_BOUNDS};          // currently displayed drill window (eases toward target)
let drillTarget = {...MAP_BOUNDS};        // authoritative drill window
let drillRafId = null;

function mapToDrillView(r){
  const scaleX = (MAP_BOUNDS.x1-MAP_BOUNDS.x0)/(drillView.x1-drillView.x0);
  const scaleY = (MAP_BOUNDS.y1-MAP_BOUNDS.y0)/(drillView.y1-drillView.y0);
  return {
    x: MAP_BOUNDS.x0 + (r.x-drillView.x0)*scaleX,
    y: MAP_BOUNDS.y0 + (r.y-drillView.y0)*scaleY,
    w: r.w*scaleX,
    h: r.h*scaleY
  };
}

function drawTiles(){
  svg.innerHTML = '';
  for(const r of cachedRects){
    const m = mapToDrillView(r);
    const g = document.createElementNS('http://www.w3.org/2000/svg','g');
    const rect = document.createElementNS('http://www.w3.org/2000/svg','rect');
    rect.setAttribute('x', m.x.toFixed(2));
    rect.setAttribute('y', m.y.toFixed(2));
    rect.setAttribute('width', Math.max(m.w,0).toFixed(2));
    rect.setAttribute('height', Math.max(m.h,0).toFixed(2));
    const meta = CATEGORY_META[r.category];
    rect.style.fill = meta.color;
    rect.setAttribute('stroke', '#0A0D12');
    rect.setAttribute('stroke-width', '1.5');
    const cls = ['tile'];
    if(meta.textDim) cls.push('dim-fill');
    if(selectedBase!==null && r.base===selectedBase) cls.push('tile-selected');
    g.setAttribute('class', cls.join(' '));
    g.addEventListener('click', ()=>{ selectedBase = r.base; renderAll(); });
    g.appendChild(rect);

    if(m.w>54 && m.h>20){
      const label = document.createElementNS('http://www.w3.org/2000/svg','text');
      label.setAttribute('x', (m.x+6).toFixed(2));
      label.setAttribute('y', (m.y+16).toFixed(2));
      label.setAttribute('font-size', Math.min(13, Math.max(9, m.h/5)).toFixed(1));
      label.setAttribute('class','tile-label');
      label.textContent = r.kind==='unicast' ? r.designation : (r.kind==='top' ? r.allocation : 'Unallocated');
      g.appendChild(label);
      if(m.h>36){
        const sub = document.createElementNS('http://www.w3.org/2000/svg','text');
        sub.setAttribute('x', (m.x+6).toFixed(2));
        sub.setAttribute('y', (m.y+30).toFixed(2));
        sub.setAttribute('font-size', Math.min(11, Math.max(8, m.h/7)).toFixed(1));
        sub.setAttribute('class','tile-sub');
        sub.textContent = r.prefix ? r.prefix : (formatIPv6(r.base)+' …');
        g.appendChild(sub);
      }
    }

    if(pulseTarget!==null && r.base===pulseTarget){
      rect.setAttribute('stroke','#ffffff');
      rect.classList.add('tile-pulse');
    }

    svg.appendChild(g);
  }
}

function renderAll(){
  renderBreadcrumb();
  const items = allResolved.map(e=>({...e, value:Number(e.size)}));
  cachedRects = squarify(items, MAP_BOUNDS.x0, MAP_BOUNDS.y0, MAP_BOUNDS.x1, MAP_BOUNDS.y1);
  drawTiles();
  pulseTarget = null;

  renderLegend(allResolved);
  const selEntry = selectedBase!==null ? cachedRects.find(r=>r.base===selectedBase) : null;
  showDetail(selEntry || null);
}

/* ---------------- map drill zoom: smooth, cursor-anchored, mouse-wheel driven ---------------- */
/* the dataset spans from /3-sized reserved continents down to /23 RIR allocations — a
   ~2^20 difference in address count, i.e. ~2^10 (1024x) in linear treemap size. The drill
   window needs to shrink about that far for the smallest tiles to ever cross the label
   threshold. */
const DRILL_MIN_FRACTION = 1/1600; // how far in you can drill (~1600x)

function clampDrillTarget(){
  const fullW = MAP_BOUNDS.x1-MAP_BOUNDS.x0, fullH = MAP_BOUNDS.y1-MAP_BOUNDS.y0;
  let vw = drillTarget.x1-drillTarget.x0, vh = drillTarget.y1-drillTarget.y0;
  if(vw>=fullW || vh>=fullH){ drillTarget = {...MAP_BOUNDS}; return; }
  vw = Math.max(fullW*DRILL_MIN_FRACTION, vw);
  vh = Math.max(fullH*DRILL_MIN_FRACTION, vh);
  const x0 = Math.min(MAP_BOUNDS.x1-vw, Math.max(MAP_BOUNDS.x0, drillTarget.x0));
  const y0 = Math.min(MAP_BOUNDS.y1-vh, Math.max(MAP_BOUNDS.y0, drillTarget.y0));
  drillTarget = {x0, y0, x1:x0+vw, y1:y0+vh};
}

function stepDrillAnimation(){
  const ease = 0.22;
  drillView = {
    x0: drillView.x0 + (drillTarget.x0-drillView.x0)*ease,
    y0: drillView.y0 + (drillTarget.y0-drillView.y0)*ease,
    x1: drillView.x1 + (drillTarget.x1-drillView.x1)*ease,
    y1: drillView.y1 + (drillTarget.y1-drillView.y1)*ease
  };
  const settled = ['x0','y0','x1','y1'].every(k => Math.abs(drillTarget[k]-drillView[k])<0.05);
  if(settled){ drillView = {...drillTarget}; updateCursor(); }
  drawTiles();
  drillRafId = settled ? null : requestAnimationFrame(stepDrillAnimation);
}
function scheduleDrillAnimation(){
  if(drillRafId===null) drillRafId = requestAnimationFrame(stepDrillAnimation);
}
function resetDrillImmediate(){
  if(drillRafId!==null){ cancelAnimationFrame(drillRafId); drillRafId=null; }
  drillView = {...MAP_BOUNDS};
  drillTarget = {...MAP_BOUNDS};
  updateCursor();
}
function isAtFullView(){
  return drillView.x0<=MAP_BOUNDS.x0+0.01 && drillView.y0<=MAP_BOUNDS.y0+0.01 &&
         drillView.x1>=MAP_BOUNDS.x1-0.01 && drillView.y1>=MAP_BOUNDS.y1-0.01;
}
function updateCursor(){
  svg.style.cursor = isAtFullView() ? 'zoom-in' : 'grab';
}

svg.addEventListener('wheel', (e)=>{
  e.preventDefault();
  const pt = svg.createSVGPoint();
  pt.x = e.clientX; pt.y = e.clientY;
  const svgP = pt.matrixTransform(svg.getScreenCTM().inverse());
  const factor = Math.exp(-e.deltaY*0.0018); // >1 drill in, <1 drill out
  const curVW = drillTarget.x1-drillTarget.x0, curVH = drillTarget.y1-drillTarget.y0;
  const newVW = curVW/factor, newVH = curVH/factor;
  // virtual-space point currently under the cursor, per the (authoritative) target window
  const scaleX = (MAP_BOUNDS.x1-MAP_BOUNDS.x0)/curVW, scaleY = (MAP_BOUNDS.y1-MAP_BOUNDS.y0)/curVH;
  const vx = drillTarget.x0 + (svgP.x-MAP_BOUNDS.x0)/scaleX;
  const vy = drillTarget.y0 + (svgP.y-MAP_BOUNDS.y0)/scaleY;
  const newScaleX = (MAP_BOUNDS.x1-MAP_BOUNDS.x0)/newVW, newScaleY = (MAP_BOUNDS.y1-MAP_BOUNDS.y0)/newVH;
  const x0 = vx - (svgP.x-MAP_BOUNDS.x0)/newScaleX;
  const y0 = vy - (svgP.y-MAP_BOUNDS.y0)/newScaleY;
  drillTarget = {x0, y0, x1:x0+newVW, y1:y0+newVH};
  clampDrillTarget();
  scheduleDrillAnimation();
}, {passive:false});

/* ---------------- map pan: drag with the mouse once drilled in ---------------- */
const DRAG_THRESHOLD = 4; // px of pointer movement before a press is treated as a pan, not a click
let isPanning = false, panMoved = false, panStartClientX = 0, panStartClientY = 0, panStartView = null;
let suppressNextTileClick = false;

svg.addEventListener('pointerdown', (e)=>{
  if(e.button!==0) return;
  isPanning = true; panMoved = false;
  panStartClientX = e.clientX; panStartClientY = e.clientY;
  panStartView = {...drillTarget};
});

svg.addEventListener('pointermove', (e)=>{
  if(!isPanning) return;
  const dxClient = e.clientX-panStartClientX, dyClient = e.clientY-panStartClientY;
  if(!panMoved){
    if(Math.hypot(dxClient,dyClient)<DRAG_THRESHOLD) return;
    panMoved = true;
    svg.style.cursor = 'grabbing';
    // only capture once we know it's a drag — capturing on every plain click would retarget
    // the resulting synthetic 'click' event to the svg itself, so tiles never see it
    try{ svg.setPointerCapture(e.pointerId); }catch(err){}
  }
  const p0 = svg.createSVGPoint(); p0.x=panStartClientX; p0.y=panStartClientY;
  const p1 = svg.createSVGPoint(); p1.x=e.clientX; p1.y=e.clientY;
  const ctmInv = svg.getScreenCTM().inverse();
  const sp0 = p0.matrixTransform(ctmInv), sp1 = p1.matrixTransform(ctmInv);
  const dSX = sp1.x-sp0.x, dSY = sp1.y-sp0.y;
  const vw = panStartView.x1-panStartView.x0, vh = panStartView.y1-panStartView.y0;
  const scaleX = (MAP_BOUNDS.x1-MAP_BOUNDS.x0)/vw, scaleY = (MAP_BOUNDS.y1-MAP_BOUNDS.y0)/vh;
  const x0 = Math.min(MAP_BOUNDS.x1-vw, Math.max(MAP_BOUNDS.x0, panStartView.x0 - dSX/scaleX));
  const y0 = Math.min(MAP_BOUNDS.y1-vh, Math.max(MAP_BOUNDS.y0, panStartView.y0 - dSY/scaleY));
  if(drillRafId!==null){ cancelAnimationFrame(drillRafId); drillRafId=null; }
  drillTarget = {x0, y0, x1:x0+vw, y1:y0+vh};
  drillView = {...drillTarget};
  drawTiles();
});

function endPan(){
  if(!isPanning) return;
  isPanning = false;
  if(panMoved) suppressNextTileClick = true;
  panMoved = false;
  updateCursor();
}
svg.addEventListener('pointerup', endPan);
svg.addEventListener('pointercancel', endPan);

// swallow the click a drag-release produces before it reaches a tile's own click handler
svg.addEventListener('click', (e)=>{
  if(suppressNextTileClick){ suppressNextTileClick = false; e.stopPropagation(); }
}, true);

/* ---------------- locate ---------------- */
function findContaining(list, addr){
  return list.find(e => addr>=e.base && addr < e.base+e.size);
}
/* smoothly drills the view so the given laid-out rect (from cachedRects) is clearly visible,
   with some surrounding context — not just the bare tile filling the whole area */
function focusOnRect(r, pad){
  const fullW = MAP_BOUNDS.x1-MAP_BOUNDS.x0, fullH = MAP_BOUNDS.y1-MAP_BOUNDS.y0;
  const cx = r.x+r.w/2, cy = r.y+r.h/2;
  let vw = Math.max(r.w*pad, r.h*pad*(fullW/fullH));
  vw = Math.min(fullW, Math.max(fullW*DRILL_MIN_FRACTION, vw));
  const vh = vw*(fullH/fullW);
  const x0 = Math.min(MAP_BOUNDS.x1-vw, Math.max(MAP_BOUNDS.x0, cx-vw/2));
  const y0 = Math.min(MAP_BOUNDS.y1-vh, Math.max(MAP_BOUNDS.y0, cy-vh/2));
  drillTarget = {x0, y0, x1:x0+vw, y1:y0+vh};
  clampDrillTarget();
  scheduleDrillAnimation();
}
function locateAddr(addr){
  const hit = findContaining(allResolved, addr);
  if(!hit) return;
  pulseTarget = hit.base;
  selectedBase = hit.base;
  renderAll();
  const r = cachedRects.find(r=>r.base===hit.base);
  if(r) focusOnRect(r, 8);
}
document.getElementById('searchForm').addEventListener('submit', (e)=>{
  e.preventDefault();
  const raw = document.getElementById('searchInput').value.trim();
  if(!raw) return;
  try{
    let addr;
    if(raw.includes('/')) addr = parseCIDR(raw).addr;
    else addr = parseIPv6(raw);
    locateAddr(addr);
  } catch(err){
    detailEl.innerHTML = '<div class="detail-empty" style="color:var(--red)">Could not parse that address: '+err.message+'</div>';
  }
});

document.getElementById('locateMeBtn').addEventListener('click', async ()=>{
  const btn = document.getElementById('locateMeBtn');
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Detecting…';
  try{
    const res = await fetch('https://api64.ipify.org?format=json');
    if(!res.ok) throw new Error('ipify request failed ('+res.status+')');
    const data = await res.json();
    const ip = data.ip;
    if(!ip || !ip.includes(':')) throw new Error('your connection returned an IPv4 address ('+(ip||'unknown')+') — no IPv6 connectivity detected');
    const addr = parseIPv6(ip);
    document.getElementById('searchInput').value = ip;
    locateAddr(addr);
  } catch(err){
    detailEl.innerHTML = '<div class="detail-empty" style="color:var(--red)">Detection failed: '+err.message+'</div>';
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
});

/* ---------------- calculator: tree state ---------------- */
const HOST_BOUNDARY = 64; // prefix length at which host ID begins
let root = null;
let maxDivide = HOST_BOUNDARY; // prefix length at which the subnet ID is exhausted

function makeRoot(addr, prefixLen){
  const base = networkAddress(addr, prefixLen);
  root = {base, prefixLen, parent:null, children:null};
  maxDivide = Math.max(prefixLen, HOST_BOUNDARY);
}

function divideNode(node){
  if(node.prefixLen>=maxDivide) return;
  const newPrefix = node.prefixLen+1;
  const half = sizeOf(newPrefix);
  node.children = [
    {base:node.base, prefixLen:newPrefix, parent:node, children:null},
    {base:node.base+half, prefixLen:newPrefix, parent:node, children:null}
  ];
}

function joinParent(node){
  if(!node.parent) return;
  node.parent.children = null;
}

function serializeTree(node){
  if(!node.children) return '0';
  return '1'+serializeTree(node.children[0])+serializeTree(node.children[1]);
}

function deserializeTree(node, bits, pos){
  if(pos.i>=bits.length) return;
  const c = bits[pos.i++];
  if(c==='1'){
    divideNode(node);
    if(!node.children) return;
    deserializeTree(node.children[0], bits, pos);
    deserializeTree(node.children[1], bits, pos);
  }
}

function recursiveDivideTo(node, target){
  if(node.prefixLen>=target) return;
  if(!node.children) divideNode(node);
  recursiveDivideTo(node.children[0], target);
  recursiveDivideTo(node.children[1], target);
}

function jumpDivide(node, target){
  if(!Number.isInteger(target) || target<=node.prefixLen || target>maxDivide) return;
  const count = 1n << BigInt(target-node.prefixLen);
  if(count>128){
    showErr('That split would create '+fmtBig(count)+' subnets in one go — try a smaller jump.');
    return;
  }
  recursiveDivideTo(node, target);
  render();
}

function collectLeaves(node, depth, guides, out){
  if(!node.children){ out.push({node, depth, guides}); return; }
  collectLeaves(node.children[0], depth+1, [...guides, true], out);
  collectLeaves(node.children[1], depth+1, [...guides, false], out);
}

function showErr(msg){ document.getElementById('errMsg').textContent = msg || ''; }
function showNote(msg){ document.getElementById('noteMsg').textContent = msg || ''; }

/* ---------------- calculator: rendering ---------------- */
function copyText(text){
  if(navigator.clipboard && window.isSecureContext){
    return navigator.clipboard.writeText(text);
  }
  return new Promise((resolve, reject)=>{
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    let ok = false;
    try{ ok = document.execCommand('copy'); } catch(e){}
    document.body.removeChild(ta);
    ok ? resolve() : reject(new Error('copy failed'));
  });
}

function renderRuler(){
  const rulerEl = document.getElementById('ruler');
  const labelsEl = document.getElementById('rulerLabels');
  rulerEl.innerHTML = '';
  labelsEl.innerHTML = '';
  if(!root){ document.getElementById('rulerNet').textContent = '—'; return; }

  document.getElementById('rulerNet').innerHTML =
    formatIPv6(root.base) + '<span class="slash">/</span><span class="prefixnum">'+root.prefixLen+'</span>';

  const subnetBits = Math.max(0, HOST_BOUNDARY - root.prefixLen);
  document.getElementById('statNet').textContent = '/'+root.prefixLen+' fixed';
  document.getElementById('statSubnetBits').textContent = subnetBits + ' bits';
  document.getElementById('statMaxSub').textContent = fmtBig(1n<<BigInt(subnetBits));
  document.getElementById('statHost').textContent = '64 bits (fixed)';

  if(root.prefixLen > HOST_BOUNDARY){
    showNote('Note: this prefix is longer than /64, so there is no room for a standard subnet ID or a full 64-bit host portion.');
  } else if(root.prefixLen === HOST_BOUNDARY){
    showNote('This is already a /64 — no subnet bits are available, only host addresses within it.');
  } else {
    showNote('');
  }

  for(let g=0; g<8; g++){
    const grp = document.createElement('div');
    grp.className = 'grp';
    for(let b=0; b<16; b++){
      const bitIndex = g*16+b;
      const bit = document.createElement('div');
      let cls = 'bit';
      const inSubnetZone = bitIndex >= root.prefixLen && bitIndex < HOST_BOUNDARY;
      if(bitIndex < root.prefixLen) cls += ' net';
      else if(bitIndex < HOST_BOUNDARY) cls += ''; // subnet zone, default amber-soft bg
      else cls += ' host';
      if(bitIndex === root.prefixLen-1 || bitIndex === HOST_BOUNDARY-1) cls += ' edge';
      const target = bitIndex+1;
      if(inSubnetZone && target<=maxDivide){
        cls += ' subnetZone';
        bit.title = 'Click to split into /'+target;
        bit.addEventListener('click', ()=>{
          if(suppressNextBitClick){ suppressNextBitClick = false; return; }
          showErr(''); jumpDivide(root, target);
        });
      }
      if(bitIndex === root.prefixLen-1 || bitIndex === root.prefixLen){
        cls += ' boundary';
        bit.addEventListener('pointerdown', onBoundaryPointerDown);
      }
      bit.className = cls;
      grp.appendChild(bit);
    }
    rulerEl.appendChild(grp);
    const lbl = document.createElement('div');
    lbl.className = 'grp';
    lbl.textContent = 'g'+g;
    labelsEl.appendChild(lbl);
  }

  const handle = document.createElement('div');
  handle.className = 'rulerHandle' + (draggingBoundary ? ' dragging' : '');
  handle.style.left = (root.prefixLen/128*100)+'%';
  rulerEl.appendChild(handle);
}

let draggingBoundary = false;
let boundaryDragStarted = false;
let boundaryPointerDownX = 0;
let suppressNextBitClick = false;
const BOUNDARY_DRAG_THRESHOLD = 3;

function onBoundaryPointerDown(e){
  boundaryPointerDownX = e.clientX;
  boundaryDragStarted = false;
  window.addEventListener('pointermove', onBoundaryPointerMove);
  window.addEventListener('pointerup', onBoundaryPointerUp);
}

function onBoundaryPointerMove(e){
  if(!boundaryDragStarted){
    if(Math.abs(e.clientX - boundaryPointerDownX) < BOUNDARY_DRAG_THRESHOLD) return;
    boundaryDragStarted = true;
    draggingBoundary = true;
    document.body.style.cursor = 'ew-resize';
    document.body.style.userSelect = 'none';
  }
  e.preventDefault();
  updateBoundaryFromEvent(e);
}

function onBoundaryPointerUp(){
  window.removeEventListener('pointermove', onBoundaryPointerMove);
  window.removeEventListener('pointerup', onBoundaryPointerUp);
  if(boundaryDragStarted){
    draggingBoundary = false;
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
    suppressNextBitClick = true;
    setTimeout(()=>{ suppressNextBitClick = false; }, 0);
    render();
  }
  boundaryDragStarted = false;
}

function updateBoundaryFromEvent(e){
  if(!root) return;
  const rulerEl = document.getElementById('ruler');
  const rect = rulerEl.getBoundingClientRect();
  const frac = Math.min(1, Math.max(0, (e.clientX - rect.left) / rect.width));
  const newPrefix = Math.min(HOST_BOUNDARY, Math.max(0, Math.round(frac*128)));
  if(newPrefix !== root.prefixLen){
    root.prefixLen = newPrefix;
    root.base = networkAddress(root.base, newPrefix);
    root.children = null;
    maxDivide = Math.max(root.prefixLen, HOST_BOUNDARY);
    document.getElementById('cidrInput').value = formatIPv6(root.base)+'/'+root.prefixLen;
    render();
  }
}

function render(){
  renderRuler();
  const rowsEl = document.getElementById('rows');
  rowsEl.innerHTML = '';
  if(!root){
    rowsEl.innerHTML = '<div class="empty">Enter a network above and hit Calculate.</div>';
    document.getElementById('tableCount').textContent = '0 leaves';
    return;
  }

  const leaves = [];
  collectLeaves(root, 0, [], leaves);
  document.getElementById('tableCount').textContent = leaves.length + (leaves.length===1 ? ' leaf' : ' leaves');

  for(const {node, depth, guides} of leaves){
    const row = document.createElement('div');
    row.className = 'row';

    const useBtn = document.createElement('button');
    useBtn.className = 'iconBtn';
    useBtn.textContent = '↳';
    useBtn.title = 'Use as network — recalculate everything from this subnet';
    useBtn.addEventListener('click', ()=>{
      showErr('');
      const cidr = formatIPv6(node.base)+'/'+node.prefixLen;
      document.getElementById('cidrInput').value = cidr;
      makeRoot(node.base, node.prefixLen);
      render();
    });
    row.appendChild(useBtn);

    const guidesEl = document.createElement('div');
    guidesEl.className = 'guides';
    for(const g of guides){
      const gEl = document.createElement('div');
      gEl.className = 'guide' + (g ? ' line' : '');
      guidesEl.appendChild(gEl);
    }
    row.appendChild(guidesEl);

    const main = document.createElement('div');
    main.className = 'rowMain';

    const netCell = document.createElement('div');
    netCell.className = 'cell netCell';
    const addrStr = formatIPv6(node.base);
    const subnetIdBits = Math.max(0, node.prefixLen - root.prefixLen);
    const subnetOpenBits = Math.max(0, HOST_BOUNDARY - node.prefixLen);
    netCell.innerHTML = '<span class="addr" title="Click to copy">'+addrStr+'</span><span class="pfx">/'+node.prefixLen+'</span>' +
      '<div class="minibar">'+
        '<div class="net" style="flex:'+Math.max(root.prefixLen,0)+'"></div>'+
        (subnetIdBits>0 ? '<div class="subnetDone" style="flex:'+subnetIdBits+'"></div>' : '')+
        (subnetOpenBits>0 ? '<div class="subnetOpen" style="flex:'+subnetOpenBits+'"></div>' : '')+
        '<div class="host" style="flex:64"></div>'+
      '</div>';
    const addrEl = netCell.querySelector('.addr');
    addrEl.addEventListener('click', ()=>{
      copyText(addrStr+'/'+node.prefixLen).then(()=>{
        addrEl.classList.add('copied');
        clearTimeout(addrEl._copyTimer);
        addrEl._copyTimer = setTimeout(()=>addrEl.classList.remove('copied'), 700);
      }).catch(()=>{});
    });
    main.appendChild(netCell);

    const last = node.base + sizeOf(node.prefixLen) - 1n;
    const rangeCell = document.createElement('div');
    rangeCell.className = 'cell rangeCell';
    rangeCell.innerHTML = formatIPv6(node.base)+'<br><b>to</b><br>'+formatIPv6(last);
    main.appendChild(rangeCell);

    const countCell = document.createElement('div');
    countCell.className = 'cell countCell';
    const num64 = node.prefixLen<HOST_BOUNDARY ? fmtBig(1n<<BigInt(HOST_BOUNDARY-node.prefixLen))+' × /64' : '1 × /64';
    countCell.innerHTML = num64;
    main.appendChild(countCell);

    row.appendChild(main);

    const actions = document.createElement('div');
    actions.className = 'actions';

    if(node.prefixLen>=maxDivide){
      const boundary = document.createElement('div');
      boundary.className = 'atBoundary';
      boundary.textContent = node.prefixLen===HOST_BOUNDARY ? 'At /64 — host boundary' : 'No subnet bits';
      actions.appendChild(boundary);
    } else {
      const divideBtn = document.createElement('button');
      divideBtn.className = 'btn small';
      divideBtn.textContent = 'Split /'+(node.prefixLen+1);
      divideBtn.addEventListener('click', ()=>{ divideNode(node); render(); });
      actions.appendChild(divideBtn);

      const jumpForm = document.createElement('div');
      jumpForm.className = 'jumpForm';
      const jumpSpan = document.createElement('span');
      jumpSpan.textContent = 'to /';
      const jumpInput = document.createElement('input');
      jumpInput.type = 'number';
      jumpInput.min = node.prefixLen+1;
      jumpInput.max = maxDivide;
      jumpInput.placeholder = String(Math.min(node.prefixLen+4, maxDivide));
      const jumpBtn = document.createElement('button');
      jumpBtn.className = 'btn small ghost';
      jumpBtn.textContent = 'Go';
      jumpBtn.addEventListener('click', ()=>{
        showErr('');
        jumpDivide(node, parseInt(jumpInput.value,10));
      });
      jumpForm.appendChild(jumpSpan);
      jumpForm.appendChild(jumpInput);
      jumpForm.appendChild(jumpBtn);
      actions.appendChild(jumpForm);
    }

    const canJoin = node.parent && node.parent.children && !node.parent.children[0].children && !node.parent.children[1].children;
    const joinBtn = document.createElement('button');
    joinBtn.className = 'btn small ghost';
    joinBtn.textContent = 'Join';
    joinBtn.disabled = !canJoin;
    joinBtn.addEventListener('click', ()=>{ joinParent(node); render(); });
    actions.appendChild(joinBtn);

    row.appendChild(actions);
    rowsEl.appendChild(row);
  }
}

document.getElementById('calcBtn').addEventListener('click', ()=>{
  showErr('');
  try{
    const {addr, prefixLen} = parseCIDR(document.getElementById('cidrInput').value);
    makeRoot(addr, prefixLen);
    render();
  } catch(e){
    showErr(e.message);
  }
});

document.getElementById('resetBtn').addEventListener('click', ()=>{
  if(!root) return;
  root.children = null;
  render();
});

document.getElementById('permalinkBtn').addEventListener('click', ()=>{
  if(!root) return;
  const params = new URLSearchParams();
  params.set('view', 'calc');
  params.set('net', formatIPv6(root.base)+'/'+root.prefixLen);
  const treeStr = serializeTree(root);
  if(treeStr !== '0') params.set('tree', treeStr);
  const url = location.origin+location.pathname+'?'+params.toString();
  const btn = document.getElementById('permalinkBtn');
  const original = btn.textContent;
  copyText(url).then(()=>{
    btn.textContent = 'Copied!';
    clearTimeout(btn._copyTimer);
    btn._copyTimer = setTimeout(()=>{ btn.textContent = original; }, 1200);
  }).catch(()=>{ showErr('Could not copy permalink'); });
});

document.getElementById('cidrInput').addEventListener('keydown', (e)=>{
  if(e.key==='Enter') document.getElementById('calcBtn').click();
});

function openPrefixModal(addr){
  return new Promise((resolve)=>{
    const overlay = document.getElementById('prefixModal');
    document.getElementById('modalAddr').textContent = formatIPv6(addr);
    overlay.hidden = false;

    function cleanup(result){
      overlay.hidden = true;
      overlay.removeEventListener('click', onOverlayClick);
      document.removeEventListener('keydown', onKeydown);
      optionBtns.forEach(b=>b.removeEventListener('click', onOptionClick));
      cancelBtn.removeEventListener('click', onCancel);
      resolve(result);
    }
    function onOptionClick(e){ cleanup(parseInt(e.currentTarget.dataset.prefix,10)); }
    function onCancel(){ cleanup(null); }
    function onOverlayClick(e){ if(e.target===overlay) cleanup(null); }
    function onKeydown(e){ if(e.key==='Escape') cleanup(null); }

    const optionBtns = Array.from(overlay.querySelectorAll('.modalOption'));
    const cancelBtn = document.getElementById('modalCancel');
    optionBtns.forEach(b=>b.addEventListener('click', onOptionClick));
    cancelBtn.addEventListener('click', onCancel);
    overlay.addEventListener('click', onOverlayClick);
    document.addEventListener('keydown', onKeydown);
  });
}

document.getElementById('detectBtn').addEventListener('click', async ()=>{
  showErr('');
  const btn = document.getElementById('detectBtn');
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Detecting…';
  try{
    const res = await fetch('https://api64.ipify.org?format=json');
    if(!res.ok) throw new Error('ipify request failed ('+res.status+')');
    const data = await res.json();
    const ip = data.ip;
    if(!ip || !ip.includes(':')) throw new Error('your connection returned an IPv4 address ('+(ip||'unknown')+') — no IPv6 connectivity detected');
    const addr = parseIPv6(ip);
    btn.disabled = false;
    btn.textContent = original;
    const prefixLen = await openPrefixModal(addr);
    if(prefixLen===null) return;
    const net = networkAddress(addr, prefixLen);
    document.getElementById('cidrInput').value = formatIPv6(net)+'/'+prefixLen;
    document.getElementById('calcBtn').click();
    return;
  } catch(e){
    showErr('Detection failed: '+e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
});

document.getElementById('viewInMapBtn').addEventListener('click', ()=>{
  if(!root) return;
  setActiveTab('map');
  locateAddr(root.base);
  setParam('addr', formatIPv6(root.base)+'/'+root.prefixLen);
});

/* ---------------- init ---------------- */
function initMapView(){
  document.getElementById('footerStatus').textContent =
    'Snapshot · IANA data as of ' + LAST_UPDATED.top + ' / ' + LAST_UPDATED.unicast + ' / ' + LAST_UPDATED.special;
  renderAll();
}
function initCalcView(){
  const params = getParams();
  const netParam = params.get('net');
  if(netParam) document.getElementById('cidrInput').value = netParam;

  document.getElementById('calcBtn').click();

  const treeParam = params.get('tree');
  if(root && treeParam && /^[01]+$/.test(treeParam)){
    try{ deserializeTree(root, treeParam, {i:0}); render(); }catch(e){}
  }
}

initMapView();
initCalcView();

(function initTabFromURL(){
  const params = getParams();
  const addrParam = params.get('addr');
  if(addrParam){
    try{
      const addr = addrParam.includes('/') ? parseCIDR(addrParam).addr : parseIPv6(addrParam);
      locateAddr(addr);
    } catch(e){}
  }
  const initialTab = params.get('view')==='calc' ? 'calc' : 'map';
  setActiveTab(initialTab, {updateUrl:false});
})();
