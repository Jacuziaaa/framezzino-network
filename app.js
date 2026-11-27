// Framezzino Network: codice dell'app (spostato da index.html il 22/11 per le regole anti-intrusione).
// Dopo ogni modifica: aumentare il numero in index.html (app.js?v=N) cosi' i telefoni prendono la versione nuova.
if("serviceWorker" in navigator)navigator.serviceWorker.register("sw.js").catch(function(){});
// ── CONFIG ────────────────────────────────────────────────────────────────
firebase.initializeApp({
  apiKey:"AIzaSyDFY3c8sc_xOOoIiHdnDK7JfKltuVFskpw",
  authDomain:"deliverysync-40d38.firebaseapp.com",
  projectId:"deliverysync-40d38",
  storageBucket:"deliverysync-40d38.firebasestorage.app",
  messagingSenderId:"17838948400",
  appId:"1:17838948400:web:a02bb794024e44aceeedf5"
});
var auth=firebase.auth(), db=firebase.firestore();
// copia dei dati anche sul telefono (come DeliverySync): clienti e schede visibili senza rete; nella copia locale le schede
// restano cifrate. Le due app sono sullo stesso sito e condividono questa copia (synchronizeTabs)
db.enablePersistence({synchronizeTabs:true}).catch(function(){});
var CCOL=db.collection('network_clienti'), META=db.collection('network_meta').doc('cifratura');
var SALT='FramezzinoNetwork-AES256-Salt-v1', CHECK='framezzino-network-ok';
var ZCOL=['#f97316','#0ea5e9','#16a87a','#8b5cf6','#e11d48','#ca8a04','#0d9488','#db2777','#2563eb','#65a30d','#9333ea','#ea580c','#0891b2','#64748b','#b45309','#4f46e5'];
var S={user:null,key:null,clients:[],filtered:[],sel:null,f:{zone:{},prod:{},sig:{},pag:{}},q:'',sort:'zona',me:null,
  // EX CLIENTI SULLA MAPPA (27/11): schede degli ex clienti (documento cifrato network_meta/ex_clienti, rifatto dal 🔄),
  // mostrate a richiesta: 'no' = nascosti, 'insieme' = con i clienti (pallini grigi), 'solo' = solo gli ex
  ex:[],exF:[],exLeggibile:true,exMode:(function(){try{return localStorage.getItem('fn_exmode')||'no';}catch(e){return 'no';}})()};
var map=null,markers={},clusterer=null,unsub=null,unsubMeta=null,unsubEx=null,zoneColor={};
var EXDOC=db.collection('network_meta').doc('ex_clienti');

// ── CIFRATURA AES-256-GCM (chiave non estraibile, salvata in IndexedDB) ───
function deriveKey(pw){var enc=new TextEncoder();
  return crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveKey']).then(function(km){
    return crypto.subtle.deriveKey({name:'PBKDF2',salt:enc.encode(SALT),iterations:310000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);});}
function b64(buf){var s='',b=new Uint8Array(buf);for(var i=0;i<b.length;i+=8192)s+=String.fromCharCode.apply(null,b.subarray(i,i+8192));return btoa(s);}
function enc(obj,key){var iv=crypto.getRandomValues(new Uint8Array(12));
  return crypto.subtle.encrypt({name:'AES-GCM',iv:iv},key||S.key,new TextEncoder().encode(JSON.stringify(obj))).then(function(ct){var o=new Uint8Array(12+ct.byteLength);o.set(iv,0);o.set(new Uint8Array(ct),12);return b64(o);});}
function dec(s,key){var b=Uint8Array.from(atob(s),function(c){return c.charCodeAt(0);});
  return crypto.subtle.decrypt({name:'AES-GCM',iv:b.slice(0,12)},key||S.key,b.slice(12)).then(function(pt){return JSON.parse(new TextDecoder().decode(pt));});}
function idb(mode,fn){return new Promise(function(res,rej){var r=indexedDB.open('fn-keys',1);r.onupgradeneeded=function(){r.result.createObjectStore('k');};
  r.onerror=function(){rej(r.error);};r.onsuccess=function(){var tx=r.result.transaction('k',mode);var st=tx.objectStore('k');var q=fn(st);tx.oncomplete=function(){res(q&&q.result);};tx.onerror=function(){rej(tx.error);};};});}
function saveKey(k){return idb('readwrite',function(st){return st.put(k,'key');}).catch(function(){});}
function loadKey(){return idb('readonly',function(st){return st.get('key');}).catch(function(){return null;});}
function dropKey(){return idb('readwrite',function(st){return st.delete('key');}).catch(function(){});}

// ── UI HELPERS ────────────────────────────────────────────────────────────
var tt;function toast(m,err){var e=document.getElementById('toast');e.textContent=m;e.style.background=err?'var(--red)':'var(--green)';e.classList.add('show');clearTimeout(tt);tt=setTimeout(function(){e.classList.remove('show');},3200);}
function el(tag,a,kids){var e=document.createElement(tag);if(a)for(var k in a){var v=a[k];if(v==null)continue;if(k==='text')e.textContent=v;else if(k==='cls')e.className=v;else if(k==='style')e.style.cssText=v;else if(k.slice(0,2)==='on')e.addEventListener(k.slice(2),v);else e.setAttribute(k,v);}
  (kids||[]).forEach(function(c){if(c!=null)e.appendChild(typeof c==='string'?document.createTextNode(c):c);});return e;}
function show(id){['login','crypto'].forEach(function(p){document.getElementById(p).classList.toggle('show',p===id);});document.getElementById('app').classList.toggle('show',id==='app');document.getElementById('loader').style.display='none';}
function norm(s){return (s||'').toString().normalize('NFD').replace(/[̀-ͯ]/g,'').toLowerCase();}
// NOME DEL REFERENTE (27/11, Jacopo: in "L'Ingrediente Segreto" si vedeva "Referente" invece di "Milena"). Se la scheda non ha
// il nome della persona, o il nome non c'e' piu' nel contatto (rinominato), si prende dal contatto in rubrica: le parole in fondo
// dopo il nome del locale ("Tram Vicenza Bar L'Ingrediente Segreto Milena" -> "Milena"). Solo se sembra un nome di persona
// (1-4 parole di sole lettere, niente ditte, prodotti, email, numeri): altrimenti resta "Referente" (il nome intero e' scritto sotto).
var REF_GENERICHE=['bar','caffe','cafe','caffetteria','pub','bistrot','bistro','ristorante','pizzeria','pasticceria','gelateria','osteria','hostaria',
  'trattoria','panificio','tabacchi','tabaccheria','distributore','distr','eni','enilive','q8','esso','snack','birreria','enoteca','hotel','albergo',
  'chiosco','paninoteca','piadineria','lounge','gastronomia','circolo','farmacia','agriturismo','locanda','spaccio','mensa','tavola','calda'];
var REF_NON_NOME=['srl','sas','snc','spa','srls','soc','ditta','ufficio','uff','uffici','ordini','amministrazione','resp','responsabile','acquisti',
  'mail','email','paga','pag','elle','esse','emme','magnum','maxi','tostoni','sig','om','color','fat','fatt','iva','piva','tv','vr','vi','pd','nuovo',
  'nuova','intestazione','addetta','addetto','collega','fronte','aeroporto','service','servizi','trade','team','group','food','drink','drinks','coffee',
  'cooffee','club','bio','track','shell','petrol','fuel','gas','golf','padel','centro','center','si','no'];
var REF_FERMA=['via','viale','piazza','piazzale','corso','contra','contrada','strada','presso','ex','dal','civico','loc','localita'];
function tokRef(s){return norm(s).replace(/[^a-z0-9]+/g,' ').trim().split(' ').filter(Boolean);}
function nomeDaContatto(contatto,c){
  var parole=String(contatto||'').trim().split(/\s+/).filter(Boolean);
  if(parole.length&&/^ex$/i.test(parole[0]))parole.shift();
  if(parole.length&&/^(tram|tam)$/i.test(parole[0]))parole.shift();
  var loc={};tokRef([c.locale,c.nomeGoogle,c.comune].join(' ')).forEach(function(t){loc[t]=1;});var lk=Object.keys(loc);
  function delLocale(t){if(loc[t]||REF_GENERICHE.indexOf(t)>=0)return true;
    return t.length>=4&&lk.some(function(l){return l.length>=4&&(t.indexOf(l)===0||l.indexOf(t)===0);});}
  var ref=[];
  for(var i=parole.length-1;i>=0;i--){var t=tokRef(parole[i]);if(!t.length)continue;  // emoji: saltate
    if(REF_FERMA.indexOf(t[0])>=0||t.some(delLocale))break;ref.unshift(parole[i]);}
  var parti=[];ref.forEach(function(w){parti=parti.concat(tokRef(w));});
  if(!ref.length||ref.length>=parole.length||ref.length>4||/[0-9@:+\/]/.test(ref.join(' '))||parti.some(function(x){return REF_NON_NOME.indexOf(x)>=0;}))return '';
  return ref.join(' ');}
function nomeRef(r,c){var n=String(r.nome||'').trim();
  if(n&&(!r.contatto||norm(r.contatto).indexOf(norm(n))>=0))return n;
  return nomeDaContatto(r.contatto,c||{})||n;}
function telLink(t){return 'tel:'+t.replace(/[^\d+]/g,'');}
// WhatsApp: cellulare italiano con o senza +39 / 0039 (anche "392 …", "393 …" scritti senza prefisso); '' se non e' un cellulare
function waLink(t){var d=(t||'').replace(/\D/g,'');if(d.indexOf('0039')===0)d=d.slice(2);if(/^3\d{8,9}$/.test(d))d='39'+d;
  return /^393\d{8,9}$/.test(d)?'https://wa.me/'+d:'';}
function isMobile(t){var d=t.replace(/[^\d]/g,'');return /^(39)?3\d{9}$/.test(d);}
document.querySelectorAll('[data-eye]').forEach(function(b){b.addEventListener('click',function(){var i=document.getElementById(b.dataset.eye);i.type=i.type==='password'?'text':'password';});});

// ── AUTH ──────────────────────────────────────────────────────────────────
auth.onAuthStateChanged(function(u){
  if(!u){S.user=null;show('login');return;}
  S.user=u;
  loadKey().then(function(k){
    if(k){S.key=k;return verifyKey(k).then(function(ok){if(ok)startApp();else{S.key=null;dropKey();askCrypto();}});}
    askCrypto();
  }).catch(nonAutorizzato);
});
// utenti autorizzati: li decidono le regole di Firestore (le email non sono scritte nel codice pubblico)
function nonAutorizzato(e){if(!(e&&e.code==='permission-denied'))return false;S.user=null;S.key=null;auth.signOut();show('login');
  document.getElementById('lerr').textContent='Utente non autorizzato.';return true;}
document.getElementById('lbtn').addEventListener('click',function(){
  var em=document.getElementById('lem').value.trim(),pw=document.getElementById('lpw').value,b=this;
  document.getElementById('lerr').textContent='';
  if(!em||!pw){document.getElementById('lerr').textContent='Inserisci email e password.';return;}
  b.textContent='…';b.disabled=true;
  auth.signInWithEmailAndPassword(em,pw).catch(function(e){var m={'auth/too-many-requests':'Troppi tentativi, riprova più tardi.','auth/invalid-login-credentials':'Email o password errate (usa la password di accesso, non quella di cifratura).','auth/invalid-credential':'Email o password errate (usa la password di accesso, non quella di cifratura).','auth/invalid-email':'Email non valida.','auth/network-request-failed':'Nessuna connessione a Firebase.','auth/unauthorized-domain':'Questo indirizzo non è autorizzato in Firebase.'};
    document.getElementById('lerr').textContent=(m[e.code]||'Accesso non riuscito')+' ['+(e.code||'?')+']';}).finally(function(){b.textContent='Accedi';b.disabled=false;});
});
document.getElementById('lpw').addEventListener('keydown',function(e){if(e.key==='Enter')document.getElementById('lbtn').click();});

var firstSetup=false;
function askCrypto(){
  META.get().then(function(d){
    firstSetup=!d.exists;
    document.getElementById('cwarn').style.display=firstSetup?'block':'none';
    document.getElementById('cpw2w').style.display=firstSetup?'block':'none';
    document.getElementById('ctitle').textContent=firstSetup?'Imposta la password di cifratura':'Password di cifratura';
    document.getElementById('cbtn').textContent=firstSetup?'Imposta e accedi':'Sblocca';
    show('crypto');
  }).catch(function(e){if(nonAutorizzato(e))return;show('crypto');document.getElementById('cerr').textContent=permMsg(e);});
}
function permMsg(e){return (e&&e.code==='permission-denied')?'Accesso al database negato: vanno aggiornate le regole di Firestore (vedi istruzioni).':'Errore di connessione: '+(e&&e.message||e);}
function verifyKey(k){return META.get().then(function(d){if(!d.exists)return false;return dec(d.data().check,k).then(function(v){return v===CHECK;}).catch(function(){return false;});});}
document.getElementById('cbtn').addEventListener('click',function(){
  var pw=document.getElementById('cpw').value,b=this,err=document.getElementById('cerr');err.textContent='';
  if(pw.length<12){err.textContent='Minimo 12 caratteri.';return;}
  if(firstSetup&&pw!==document.getElementById('cpw2').value){err.textContent='Le due password non coincidono.';return;}
  b.disabled=true;var lbl=b.textContent;b.textContent='…';
  deriveKey(pw).then(function(k){
    if(firstSetup){return enc(CHECK,k).then(function(c){return META.set({check:c,creato:new Date().toISOString(),da:S.user.email});}).then(function(){return k;});}
    return verifyKey(k).then(function(ok){if(!ok)throw new Error('wrong');return k;});
  }).then(function(k){S.key=k;saveKey(k);document.getElementById('cpw').value='';document.getElementById('cpw2').value='';startApp();})
  .catch(function(e){err.textContent=e.message==='wrong'?'Password di cifratura errata.':permMsg(e);})
  .finally(function(){b.disabled=false;b.textContent=lbl;});
});
document.getElementById('cpw').addEventListener('keydown',function(e){if(e.key==='Enter')document.getElementById('cbtn').click();});

// ── DATI ──────────────────────────────────────────────────────────────────
function startApp(){
  show('app');initMap();loadGis().catch(function(){});
  // "aggiornata oggi alle ... · Marco": ultimo 🔄 andato a buon fine, di chiunque (documento network_meta/aggiornamento)
  if(unsubMeta)unsubMeta();unsubMeta=db.collection('network_meta').doc('aggiornamento').onSnapshot(function(d){S.ultimo=d.exists?d.data():null;mostraAggiornata();},function(){});
  // ex clienti (27/11): schede cifrate in un documento solo; se non si decifra (password cambiata) si rifa' al 🔄
  if(unsubEx)unsubEx();unsubEx=EXDOC.onSnapshot(function(d){var x=d.exists?d.data():null;
    if(!x||!x.d){S.ex=[];S.exSalvato=canonico([]);S.exLeggibile=true;applyFilters();return;}
    decD(x).then(function(o){var l=(o&&o.lista)||[];S.exSalvato=canonico(l);
      S.ex=l.map(function(c){c._id='ex:'+(c.placeId||c.id);c._ex=true;return c;});S.exLeggibile=true;if(o&&o.__dn)finisciRekey([EXDOC]);applyFilters();},
      function(){S.ex=[];S.exLeggibile=false;applyFilters();});},function(){});
  if(unsub)unsub();
  unsub=CCOL.onSnapshot({includeMetadataChanges:true},function(snap){
    var daFinire=[];
    Promise.all(snap.docs.map(function(d){return decD(d.data()).then(function(c){if(c.__dn){delete c.__dn;daFinire.push(d.ref);}c._id=d.id;return c;}).catch(function(){return null;});}))
    .then(function(list){
      if(S.rekeying)return;
      if(daFinire.length)finisciRekey(daFinire);  // cambio password interrotto a meta': lo completo
      if(snap.docs.length&&!list.some(Boolean)){  // password cambiata da un altro dispositivo
        return verifyKey(S.key).then(function(ok){if(ok)return;if(unsub)unsub();S.key=null;S.clients=[];dropKey();toast('La password di cifratura è stata cambiata: inserisci quella nuova.',true);askCrypto();});}
      S.clients=list.filter(Boolean);assignColors();applyFilters();
      document.getElementById('empty').style.display=S.clients.length?'none':'block';
      // prima lettura: se l'accesso Google e' ancora valido la mappa si aggiorna subito dalla rubrica
      S.daCache=snap.metadata.fromCache;
      if(!S.syncAvviato){segnaSync();if(!S.daCache){S.syncAvviato=true;controllaCloud(true);apriDaLink();if(gTok&&gTok.exp>Date.now()+60000)aggiornaDaRubrica(false);}}
      if(S.daCache&&!navigator.onLine&&!S.avvisoRete){S.avvisoRete=true;toast('Senza rete: vedi i clienti salvati sul telefono (la mappa può restare senza sfondo).');}});
  },function(e){toast(permMsg(e),true);});
}
function assignColors(){var zs={};S.clients.forEach(function(c){zs[c.zona]=1;});Object.keys(zs).sort().forEach(function(z,i){zoneColor[z]=z==='Fuori zona'?'#64748b':ZCOL[i%ZCOL.length];});}
function docId(id){return (id||'').replace(/[^A-Za-z0-9_-]/g,'_').slice(0,140);}
function importFile(file){
  var r=new FileReader();r.onload=function(){
    var j;try{j=JSON.parse(r.result);}catch(e){toast('File non valido',true);return;}
    var list=(j&&j.clienti)||[];if(!list.length){toast('Il file non contiene clienti',true);return;}
    var rim=(j&&Array.isArray(j.rimuovi))?j.rimuovi.filter(function(x){return typeof x==='string'&&x;}):[];
    if(!window.confirm('Importare '+list.length+' clienti? I dati verranno cifrati e salvati (i clienti già presenti vengono aggiornati).'+(rim.length?'\n'+rim.length+' schede vecchie o sospese verranno tolte dalla mappa.':'')))return;
    toast('Cifratura e caricamento di '+list.length+' clienti…');
    var chunks=[];for(var i=0;i<list.length;i+=200)chunks.push(list.slice(i,i+200));
    chunks.reduce(function(p,ch){return p.then(function(){
      return Promise.all(ch.map(function(c){return enc(c).then(function(d){return {id:docId(c.id),d:d};});})).then(function(rows){
        var b=db.batch();rows.forEach(function(x){b.set(CCOL.doc(x.id),{d:x.d,v:1,aggiornato:new Date().toISOString(),da:S.user.email});});return b.commit();});
    });},Promise.resolve()).then(function(){
      if(!rim.length)return;var b=db.batch();rim.forEach(function(id){b.delete(CCOL.doc(docId(id)));});return b.commit();
    }).then(function(){toast(list.length+' clienti importati ✓'+(rim.length?' · '+rim.length+' tolti':''));closeOv();}).catch(function(e){toast(permMsg(e),true);});
  };r.readAsText(file);
}
document.getElementById('fileimp').addEventListener('change',function(){if(this.files[0])importFile(this.files[0]);this.value='';});
document.getElementById('emptyimp').addEventListener('click',function(){document.getElementById('fileimp').click();});

// ── MAPPA (Google Maps) ───────────────────────────────────────────────────
function loadMaps(){
  if(window.google&&google.maps&&google.maps.importLibrary)return Promise.resolve();
  if(!window.MAPS_KEY)return new Promise(function(res,rej){var s=document.createElement('script');s.src='config.js?t='+Date.now();
    s.onload=function(){window.MAPS_KEY?res(loadMaps()):rej(new Error('nokey'));};s.onerror=function(){rej(new Error('nokey'));};document.head.appendChild(s);});
  (g=>{var h,a,k,p="The Google Maps JavaScript API",c="google",l="importLibrary",q="__ib__",m=document,b=window;b=b[c]||(b[c]={});var d=b.maps||(b.maps={}),r=new Set,e=new URLSearchParams,u=()=>h||(h=new Promise(async(f,n)=>{await (a=m.createElement("script"));e.set("libraries",[...r]+"");for(k in g)e.set(k.replace(/[A-Z]/g,t=>"_"+t[0].toLowerCase()),g[k]);e.set("callback",c+".maps."+q);a.src=`https://maps.${c}apis.com/maps/api/js?`+e;d[q]=f;a.onerror=()=>h=n(Error(p+" could not load."));a.nonce=m.querySelector("script[nonce]")?.nonce||"";m.head.append(a)}));d[l]?console.warn(p+" only loads once. Ignoring:",g):d[l]=(f,...n)=>r.add(f)&&u().then(()=>d[l](f,...n))})({key:window.MAPS_KEY,v:"weekly",language:"it",region:"IT"});
  return Promise.resolve();
}
function initMap(){
  if(map)return;
  loadMaps().then(function(){return Promise.all([google.maps.importLibrary('maps'),google.maps.importLibrary('marker')]);})
  .then(function(){
    map=new google.maps.Map(document.getElementById('map'),{center:{lat:45.55,lng:11.55},zoom:9,mapId:window.MAPS_MAP_ID||'DEMO_MAP_ID',
      gestureHandling:'greedy',streetViewControl:false,mapTypeControl:false,fullscreenControl:false,clickableIcons:false});
    window.gm_authFailure=function(){mapMsg('La chiave Google Maps non è autorizzata per questo indirizzo. Controlla le limitazioni della chiave nella console Google Cloud.');};
    renderMarkers();
  }).catch(function(e){mapMsg(e.message==='nokey'?'Manca la chiave Google Maps (config.js).':'Impossibile caricare Google Maps: '+e.message);});
}
function mapMsg(t){var m=document.getElementById('mapmsg');m.textContent=t;m.style.display='flex';}
function pin(c){var col=c._ex?'#94a3b8':(zoneColor[c.zona]||'#f97316');  // ex cliente: grigio con scritto "ex"
  var pe=new google.maps.marker.PinElement(Object.assign({background:col,borderColor:'#ffffff',glyphColor:'#ffffff',scale:S.sel===c._id?1.25:1},c._ex?{glyph:'ex'}:{}));return pe.element;}
// cosa si vede (mappa ed elenco): i clienti filtrati, e gli ex clienti se scelto con il tasto "Ex clienti"
function visibili(){return S.exMode==='solo'?S.exF:(S.exMode==='insieme'?S.filtered.concat(S.exF):S.filtered);}
function renderMarkers(){
  if(!map||!google.maps.marker)return;
  if(clusterer)clusterer.clearMarkers();
  Object.keys(markers).forEach(function(k){markers[k].map=null;});markers={};
  var arr=visibili().filter(function(c){return c.lat!=null;}).map(function(c){
    var m=new google.maps.marker.AdvancedMarkerElement({position:{lat:c.lat,lng:c.lng},content:pin(c),title:c.locale+(c._ex?' (ex cliente)':'')});
    m.addListener('click',function(){openDetail(c._id);});markers[c._id]=m;return m;});
  if(window.markerClusterer){
    clusterer=new markerClusterer.MarkerClusterer({map:map,markers:arr,renderer:{render:function(cl){
      var n=cl.count,size=n<10?34:n<50?42:52;
      var d=el('div',{style:'width:'+size+'px;height:'+size+'px;border-radius:50%;background:#f97316;color:#fff;display:flex;align-items:center;justify-content:center;font:800 13px DM Sans,sans-serif;border:3px solid #fff;box-shadow:0 2px 8px rgba(0,0,0,.25)',text:String(n)});
      return new google.maps.marker.AdvancedMarkerElement({position:cl.position,content:d,zIndex:1000+n});}}});
  }else arr.forEach(function(m){m.map=map;});
}
function fitAll(){var v=visibili();if(!map||!v.length)return;var b=new google.maps.LatLngBounds();v.forEach(function(c){if(c.lat!=null)b.extend({lat:c.lat,lng:c.lng});});map.fitBounds(b,60);}

// ── FILTRI E LISTA ────────────────────────────────────────────────────────
function activeF(k){return Object.keys(S.f[k]).filter(function(x){return S.f[k][x];});}
function matchesF(c,k,field){var a=activeF(k);if(!a.length)return true;var v=field==='zona'?[c.zona]:(c[field]||[]);return a.some(function(x){return v.indexOf(x)>=0;});}
function passaFiltri(c,q){
  if(!matchesF(c,'zone','zona')||!matchesF(c,'prod','prodotti')||!matchesF(c,'sig','sigilli')||!matchesF(c,'pag','pagamento'))return false;
  if(q){var hay=norm([c.locale,c.nomeGoogle,c.comune,c.indirizzo,c.zona,c.azienda,c.piva,(c.referenti||[]).map(function(r){return r.nome+' '+r.contatto;}).join(' ')].join(' '));
    if(q.split(/\s+/).some(function(t){return hay.indexOf(t)<0;}))return false;}
  return true;}
function applyFilters(refit){
  var q=norm(S.q).trim();
  S.filtered=S.clients.filter(function(c){return passaFiltri(c,q);});
  S.exF=(S.ex||[]).filter(function(c){return passaFiltri(c,q);});
  var n=['zone','prod','sig','pag'].reduce(function(s,k){return s+activeF(k).length;},0);
  document.getElementById('fdot').classList.toggle('on',n>0);
  segnaEx();renderList();renderMarkers();if(refit)fitAll();
}
// tasto "Ex clienti" sulla mappa (27/11): scelta tra nascosti / insieme ai clienti / solo gli ex
function segnaEx(){var b=document.getElementById('exbtn');if(!b)return;var n=(S.ex||[]).length;
  b.textContent=S.exMode==='solo'?'🗂️ Solo ex clienti ('+n+')':(S.exMode==='insieme'?'🗂️ Ex clienti: visibili ('+n+')':'🗂️ Ex clienti'+(n?' ('+n+')':''));
  b.classList.toggle('on',S.exMode!=='no');}
function openExMode(){
  var n=(S.ex||[]).length;
  function scelta(v,t,msg){return el('button',{cls:'act'+(S.exMode===v?' main':''),type:'button',style:'justify-content:flex-start;width:100%;margin-top:8px',text:(S.exMode===v?'✓ ':'')+t,
    onclick:function(){S.exMode=v;try{localStorage.setItem('fn_exmode',v);}catch(e){}closeOv();applyFilters(true);toast(msg);}});}
  openOv([testata('Ex clienti sulla mappa',n?(n+(n===1?' ex cliente con il locale':' ex clienti con il locale')):'Nessun ex cliente con il locale (si aggiornano con il 🔄)'),
    el('div',{cls:'mbody'},[
      scelta('no','Non mostrarli','Ex clienti nascosti'),
      scelta('insieme','Mostrali insieme ai clienti (pallini grigi «ex»)','Ex clienti visibili insieme ai clienti (grigi)'),
      scelta('solo','Mostra solo gli ex clienti','Solo gli ex clienti'),
      el('p',{cls:'msub',style:'margin-top:12px',text:'Tocca un ex cliente per vederlo: da lì puoi rimetterlo cliente («↩ Ripristina come cliente») o eliminarlo. I filtri e la ricerca valgono anche per gli ex clienti.'})])]);}
function dist(a,b){var R=6371,toR=Math.PI/180,dLa=(b.lat-a.lat)*toR,dLo=(b.lng-a.lng)*toR;var h=Math.sin(dLa/2)**2+Math.cos(a.lat*toR)*Math.cos(b.lat*toR)*Math.sin(dLo/2)**2;return 2*R*Math.asin(Math.sqrt(h));}
function renderList(){
  var L=document.getElementById('list');L.innerHTML='';var arr=visibili().slice();
  if(S.sort==='nome')arr.sort(function(a,b){return (a.locale||'').localeCompare(b.locale||'');});
  else if(S.sort==='vicino'&&S.me)arr.sort(function(a,b){return dist(S.me,a)-dist(S.me,b);});
  else arr.sort(function(a,b){return (a.zona+a.comune+a.locale).localeCompare(b.zona+b.comune+b.locale);});
  var nAtt=arr.filter(function(c){return !c._ex;}).length,nEx=arr.length-nAtt;
  document.getElementById('scount').textContent=S.exMode==='solo'?nEx+(nEx===1?' ex cliente':' ex clienti')+(nEx!==S.ex.length?' di '+S.ex.length:'')
    :nAtt+(nAtt===1?' locale':' locali')+(nAtt!==S.clients.length?' di '+S.clients.length:'')+(nEx?' + '+nEx+' ex':'');mostraAggiornata();
  arr.forEach(function(c){
    var refs=(c.referenti||[]).map(function(r){return nomeRef(r,c);}).filter(Boolean).join(', ');
    var km=S.sort==='vicino'&&S.me?' · '+dist(S.me,c).toFixed(1)+' km':'';
    L.appendChild(el('div',{cls:'row'+(S.sel===c._id?' sel':'')+(c._ex?' exrow':''),onclick:function(){openDetail(c._id,true);}},[
      el('span',{cls:'zdot',style:'background:'+(c._ex?'#94a3b8':(zoneColor[c.zona]||'#f97316'))}),
      el('div',{style:'min-width:0'},[el('div',{cls:'rname',text:c.locale+(c._ex?' · ex cliente':'')}),el('div',{cls:'rsub',text:(c._ex?'ex cliente'+(c.exDal?' dal '+c.exDal:'')+' · ':'')+(c.comune||'')+' · '+c.zona+km+(refs?' · '+refs:'')}),
        el('div',{cls:'pills'},(c.prodotti||[]).slice(0,5).map(function(p){return el('span',{cls:'pill p',text:p});}).concat((c.sigilli||[]).map(function(s){return el('span',{cls:'pill s',text:/^s[iì](\s|$)/i.test(s)?'Sigilli':'Sigilli '+s.toLowerCase()});})))])]));
  });
  if(!arr.length&&S.clients.length)L.appendChild(el('div',{style:'padding:30px;text-align:center;color:var(--muted);font-size:13px',text:'Nessun locale con questi filtri'}));
}
var st;document.getElementById('search').addEventListener('input',function(){S.q=this.value;clearTimeout(st);st=setTimeout(function(){applyFilters(true);},250);});
document.getElementById('sort').addEventListener('change',function(){S.sort=this.value;
  if(S.sort==='vicino'&&!S.me){if(!navigator.geolocation){toast('Posizione non disponibile',true);return;}
    navigator.geolocation.getCurrentPosition(function(p){S.me={lat:p.coords.latitude,lng:p.coords.longitude};renderList();if(map){map.panTo(S.me);map.setZoom(12);}},function(){toast('Permesso posizione negato',true);});}
  renderList();});
// ── pannello dal basso (telefono): 3 altezze — chiuso, metà, grande. Tocco sulla maniglia: chiuso <-> metà;
//    trascinamento dalla maniglia: segue il dito e si ferma sull'altezza più vicina ──
(function(){
  var side=document.getElementById('side'),head=document.getElementById('shead');
  var drag=null,mosso=false,ignoraClick=false;
  function telefono(){return window.innerWidth<640;}
  function altezze(){var tot=side.parentNode.clientHeight;return {min:82,mid:Math.round(tot*0.46),max:tot-12};}
  function stato(nome){side.classList.toggle('min',nome==='min');side.classList.toggle('max',nome==='max');}
  function suPulsante(t){return t.closest&&t.closest('#sort,#newbtn');}
  head.addEventListener('pointerdown',function(e){
    if(!telefono()||suPulsante(e.target))return;
    drag={y:e.clientY,h:side.offsetHeight,id:e.pointerId,t:Date.now()};mosso=false;
    try{head.setPointerCapture(e.pointerId);}catch(x){}
  });
  head.addEventListener('pointermove',function(e){
    if(!drag||e.pointerId!==drag.id)return;
    var dy=drag.y-e.clientY;if(!mosso&&Math.abs(dy)<6)return;
    if(!mosso){mosso=true;side.classList.add('drag');}
    var a=altezze();side.style.height=Math.max(a.min,Math.min(a.max,drag.h+dy))+'px';
  });
  function fine(e){
    if(!drag||e.pointerId!==drag.id)return;
    var d=drag;drag=null;
    if(!mosso)return;                      // era un tocco: ci pensa il click
    ignoraClick=true;setTimeout(function(){ignoraClick=false;},350);
    var a=altezze(),h=side.offsetHeight,v=(d.y-e.clientY)/Math.max(1,Date.now()-d.t);  // px/ms, + = verso l'alto
    var cand=[['min',a.min],['mid',a.mid],['max',a.max]],best=cand[0];
    cand.forEach(function(c){if(Math.abs(c[1]-h)<Math.abs(best[1]-h))best=c;});
    if(Math.abs(v)>0.6){                   // gesto veloce: va all'altezza successiva nella direzione del dito
      var su=cand.filter(function(c){return c[1]>h+5;}),giu=cand.filter(function(c){return c[1]<h-5;});
      if(v>0&&su.length)best=su[0];else if(v<0&&giu.length)best=giu[giu.length-1];
    }
    side.classList.remove('drag');side.style.height='';stato(best[0]);
  }
  head.addEventListener('pointerup',fine);head.addEventListener('pointercancel',fine);
  head.addEventListener('click',function(e){
    if(suPulsante(e.target)||!telefono()||ignoraClick)return;
    stato(side.classList.contains('min')?'mid':'min');
  });
})();

// ── DETTAGLIO ─────────────────────────────────────────────────────────────
// TASTO INDIETRO (review 23/11, Jacopo): una finestra aperta occupa un passo della cronologia, cosi' il tasto indietro
// del telefono chiude la finestra invece di uscire dall'app (e quello che si stava scrivendo non si perde)
// Il passo di una finestra chiusa si toglie subito dopo (setTimeout), solo se intanto non se n'e' aperta un'altra
// (chiudi + apri subito: la finestra nuova usa lo stesso passo; Chrome con back() + pushState insieme tornava indietro di due)
var OV_PASSO=false,SALTA_POP=0,CHIUDI_DOPO=false;
function openOv(content){var m=document.getElementById('modal');m.innerHTML='';m.appendChild(el('div',{cls:'mh'}));content.forEach(function(x){m.appendChild(x);});document.getElementById('ov').classList.add('show');
  CHIUDI_DOPO=false;if(!OV_PASSO){OV_PASSO=true;try{history.pushState({ov:1},'','');}catch(e){}}}
function closeOv(){document.getElementById('ov').classList.remove('show');
  if(!OV_PASSO||CHIUDI_DOPO)return;CHIUDI_DOPO=true;
  setTimeout(function(){if(!CHIUDI_DOPO)return;CHIUDI_DOPO=false;if(document.getElementById('ov').classList.contains('show'))return;
    OV_PASSO=false;if(history.state&&history.state.ov){SALTA_POP++;history.back();}},0);}
window.addEventListener('popstate',function(){if(SALTA_POP>0){SALTA_POP--;return;}  // indietro fatto dall'app chiudendo
  if(OV_PASSO||document.getElementById('ov').classList.contains('show')){OV_PASSO=false;CHIUDI_DOPO=false;document.getElementById('ov').classList.remove('show');}});
document.getElementById('ov').addEventListener('click',function(e){if(e.target.id==='ov')closeOv();});
function openDetail(id,pan){
  var c=S.clients.find(function(x){return x._id===id;})||(S.ex||[]).find(function(x){return x._id===id;});if(!c)return;S.sel=id;renderList();
  if(pan&&map&&c.lat!=null){map.panTo({lat:c.lat,lng:c.lng});if(map.getZoom()<14)map.setZoom(15);}
  if(c._ex){openDetailEx(c);return;}
  var refs=(c.referenti||[]).map(function(r){
    var acts=(r.telefoni||[]).map(function(t){return el('div',{cls:'acts'},[el('a',{cls:'act',href:telLink(t),text:'📞 '+t}),isMobile(t)?el('a',{cls:'act wa',href:waLink(t),target:'_blank',rel:'noopener',text:'WhatsApp'}):null]);});
    return el('div',{cls:'ref'},[el('div',{cls:'refn',text:nomeRef(r,c)||'Referente'}),el('div',{cls:'refc',text:'In rubrica: '+r.contatto})].concat(acts));});
  var kv=[];[['Ragione sociale',c.azienda],['P.IVA',c.piva],['SDI',c.sdi],['Tel. locale',c.telefonoLocale]].forEach(function(x){if(x[1]){kv.push(el('span',{text:x[0]}));kv.push(el('span',{text:x[1]}));}});
  function chips(arr,cls){return el('div',{cls:'pills'},(arr||[]).map(function(p){return el('span',{cls:'pill '+cls,text:p,style:'font-size:12px;padding:4px 10px'});}));}
  openOv([
    el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:c.locale}),el('div',{cls:'msub',text:(c.comune||'')+(c.provincia?' ('+c.provincia+')':'')+' · Zona '+c.zona})]),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},[
      el('div',{},[el('div',{cls:'sec',text:'Indirizzo verificato'}),el('div',{cls:'addr',text:c.indirizzo}),
        el('div',{cls:'acts'},[el('a',{cls:'act main',href:'https://www.google.com/maps/dir/?api=1&destination='+encodeURIComponent(c.indirizzo)+'&destination_place_id='+encodeURIComponent(c.placeId||c.id),target:'_blank',rel:'noopener',text:'🧭 Naviga'}),
          /^https:\/\//i.test(c.maps||'')?el('a',{cls:'act',href:c.maps,target:'_blank',rel:'noopener',text:'Scheda Google Maps'}):null,
          c.telefonoLocale?el('a',{cls:'act',href:telLink(c.telefonoLocale),text:'📞 Locale'}):null])]),
      refs.length?el('div',{},[el('div',{cls:'sec',text:'Referenti'})].concat(refs)):null,
      (c.prodotti||[]).length?el('div',{},[el('div',{cls:'sec',text:'Prodotti'}),chips(c.prodotti,'p')]):null,
      (c.sigilli||[]).length?el('div',{},[el('div',{cls:'sec',text:'Sigilli'}),chips(c.sigilli,'s')]):null,
      (c.pagamento||[]).length?el('div',{},[el('div',{cls:'sec',text:'Pagamento'}),chips(c.pagamento,'')]):null,
      kv.length?el('div',{},[el('div',{cls:'sec',text:'Dati fiscali'}),el('div',{cls:'kv'},kv)]):null,
      (c.note||[]).length?el('div',{},[el('div',{cls:'sec',text:'Note'}),el('div',{cls:'notes',text:c.note.join('\n')})]):null,
      el('div',{cls:'acts',style:'margin-top:4px'},[el('button',{cls:'act',type:'button',text:'✏️ Modifica (rubrica e mappa)',onclick:function(){openModifica(c);}})])
    ])]);
}
// scheda di un EX cliente (27/11): com'era (referenti, prodotti, note) + "Ripristina come cliente" / "Elimina definitivamente"
function openDetailEx(c){
  var refs=(c.referenti||[]).map(function(r){
    var acts=(r.telefoni||[]).map(function(t){return el('div',{cls:'acts'},[el('a',{cls:'act',href:telLink(t),text:'📞 '+t}),isMobile(t)?el('a',{cls:'act wa',href:waLink(t),target:'_blank',rel:'noopener',text:'WhatsApp'}):null]);});
    return el('div',{cls:'ref'},[el('div',{cls:'refn',text:nomeRef(r,c)||'Referente'}),el('div',{cls:'refc',text:'In rubrica: '+r.contatto})].concat(acts));});
  function chips(arr,cls){return el('div',{cls:'pills'},(arr||[]).map(function(p){return el('span',{cls:'pill '+cls,text:p,style:'font-size:12px;padding:4px 10px'});}));}
  var bR=el('button',{cls:'act main',type:'button',text:'↩ Ripristina come cliente',onclick:function(){ripristinaEx(c,bR);}});
  var bE=el('button',{cls:'act',type:'button',style:'color:var(--red)',text:'🗑️ Elimina definitivamente',onclick:function(){eliminaEx(c,bE);}});
  openOv([
    el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:c.locale}),el('div',{cls:'msub',text:'Ex cliente'+(c.exDal?' dal '+c.exDal:'')+' · '+(c.comune||'')+(c.provincia?' ('+c.provincia+')':'')+' · Zona '+c.zona})]),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},[
      el('div',{cls:'exban',text:'Non è più cliente: è in rubrica come «Ex Tram …» con l\'etichetta «Ex clienti Framezzino».'}),
      el('div',{},[el('div',{cls:'sec',text:'Indirizzo'}),el('div',{cls:'addr',text:c.indirizzo||''}),
        el('div',{cls:'acts'},[el('a',{cls:'act',href:'https://www.google.com/maps/dir/?api=1&destination='+encodeURIComponent(c.indirizzo||'')+'&destination_place_id='+encodeURIComponent(c.placeId||c.id),target:'_blank',rel:'noopener',text:'🧭 Naviga'}),
          /^https:\/\//i.test(c.maps||'')?el('a',{cls:'act',href:c.maps,target:'_blank',rel:'noopener',text:'Scheda Google Maps'}):null])]),
      refs.length?el('div',{},[el('div',{cls:'sec',text:'Referenti'})].concat(refs)):null,
      (c.prodotti||[]).length?el('div',{},[el('div',{cls:'sec',text:'Prendeva'}),chips(c.prodotti,'p')]):null,
      (c.sigilli||[]).length?el('div',{},[el('div',{cls:'sec',text:'Sigilli'}),chips(c.sigilli,'s')]):null,
      (c.note||[]).length?el('div',{},[el('div',{cls:'sec',text:'Note'}),el('div',{cls:'notes',text:c.note.join('\n')})]):null,
      el('div',{cls:'acts',style:'margin-top:8px'},[bR]),el('div',{cls:'acts',style:'margin-top:8px'},[bE])])]);
}
// il contatto di un referente nella MIA rubrica Google (prova la mia copia, poi le altre: quella dell'altro dà errore)
function contattoMio(r){
  var rk=String(SY.rubrica||(function(){try{return localStorage.getItem('fn_rubrica')||'';}catch(e){return '';}})()).toLowerCase(),l=[];
  if(r.copie&&r.copie[rk])l.push(r.copie[rk]);rnsRef(r).forEach(function(x){if(l.indexOf(x)<0)l.push(x);});
  var i=0;function prova(){if(i>=l.length)return Promise.resolve(null);var rn=l[i++];
    return papi(rn+'?personFields='+PF).catch(function(){return prova();});}
  return prova();}
// contatti appena cambiati/cancellati dall'app: Google li mostra nell'elenco solo dopo qualche minuto (27/11), quindi per
// 15 minuti il 🔄 usa la versione letta subito dopo la modifica (e salta quelli cancellati)
function ricordaFresco(p){SY.freschi=SY.freschi||{};SY.freschi[p.resourceName]={p:p,t:Date.now()};}
function ricordaEliminato(rn){SY.eliminati=SY.eliminati||{};SY.eliminati[rn]=Date.now();}
// rimette cliente un ex cliente: nome senza "Ex ", nota senza "Ex cliente dal …", gruppi clienti + zona, fuori dagli ex
function togliExDal(n){return (n||'').split('\n').map(function(r){if(r.indexOf('Altro:')!==0)return r;
    var pz=pezziAltro(r.slice(6)).filter(function(x){return !/^ex cliente dal /i.test(x);});return pz.length?'Altro: '+pz.join(' / '):null;})
  .filter(function(r){return r!==null;}).join('\n');}
function rimettiCliente(p,gs){
  var nome=(((p.names||[])[0]||{}).displayName||'').trim(),dm=cdato(p,'framezzino')||{},body={},campi=[];
  if(/^ex\s+/i.test(nome)){body.names=[{givenName:nome.replace(/^ex\s+/i,'')}];campi.push('names');}
  var n=notaDi(p),n2=togliExDal(n);if(n2.trim()!==n.trim()){body.biographies=n2?[{value:n2,contentType:'TEXT_PLAIN'}]:[];campi.push('biographies');}
  return (campi.length?contattoAggiorna(p,body,campi.join(',')):Promise.resolve(p)).then(function(np){
    return gruppiZona(np,dm.senzaMappa?null:(dm.zona||null),gs).then(function(){var g=gs.find(function(y){return y.name===EX_GRUPPO;});
      return g?papi(g.resourceName+'/members:modify','POST',{resourceNamesToRemove:[np.resourceName]}):null;})
      .then(function(){return papi(np.resourceName+'?personFields='+PF);}).then(function(f){ricordaFresco(f);return f;});});}
function ripristinaEx(c,btn){
  if(!window.confirm('«'+c.locale+'» torna cliente?\n\nTolgo «Ex » dal nome, lo tolgo dall\'etichetta «'+EX_GRUPPO+'» e lo rimetto in «Clienti Framezzino» e nella zona '+(c.zona||'')+'. Torna sulla mappa; all\'altra rubrica arriva con il giro del cloud, che parte subito.'))return;
  btn.disabled=true;btn.textContent='Salvo…';var fatti=0;
  googleToken().then(gruppiLista).then(function(gs){
    return (c.referenti||[]).reduce(function(pr,r){return pr.then(function(){return contattoMio(r).then(function(p){if(!p)return;fatti++;return rimettiCliente(p,gs);});});},Promise.resolve());
  }).then(function(){if(!fatti)throw new Error('Non trovo questo cliente nella tua rubrica Google: aggiorna con 🔄 e riprova.');
    closeOv();toast('«'+c.locale+'» è di nuovo cliente ✓ · sistemo la rubrica e la mappa');
    S.ex=S.ex.filter(function(x){return x!==c;});applyFilters();setTimeout(sistemaEAggiorna,600);},
    function(e){btn.disabled=false;btn.textContent='↩ Ripristina come cliente';toast(e.message,true);});}
// ELIMINA DEFINITIVAMENTE (27/11, Jacopo): con due conferme. I contatti della mia rubrica vanno nel cestino di Google
// Contatti (30 giorni); la copia nell'altra rubrica la toglie il giro del cloud (cancellazione propagata); la scheda
// sparisce subito dalla mappa. Per chi può tornare c'è "Non è più cliente".
function eliminaDefinitivo(c,lista,btn){
  if(!lista.length){toast('Nessun contatto di questo locale nella tua rubrica Google: lo elimina chi ce l\'ha.',true);return;}
  var nomi=lista.map(function(p){var n=(p.names||[])[0]||{};return '• '+(n.displayName||n.givenName||'(senza nome)');}).join('\n');
  if(!window.confirm('ELIMINARE DEFINITIVAMENTE «'+c.locale+'»?\n\n'+nomi+'\n\nVa nel cestino di Google Contatti (si recupera entro 30 giorni), sparisce dalla mappa e anche dalla rubrica dell\'altro (giro del cloud).'+(c._ex?'':'\n\nSe può tornare cliente usa invece «🚫 Non è più cliente».')))return;
  if(!window.confirm('Seconda conferma: elimino davvero '+(lista.length===1?'questo contatto':'questi '+lista.length+' contatti')+' di «'+c.locale+'»?'))return;
  var testo=btn.textContent;btn.disabled=true;btn.textContent='Elimino…';
  lista.reduce(function(pr,p){return pr.then(function(){return papi(p.resourceName+':deleteContact','DELETE').then(function(){ricordaEliminato(p.resourceName);});});},Promise.resolve())
    .then(function(){
      if(c._ex){var resto=S.ex.filter(function(x){return x!==c;});return scriviEx(resto).then(function(){S.ex=resto;});}
      return CCOL.doc(c._id).delete();})
    .then(function(){closeOv();toast('«'+c.locale+'» eliminato ✓ · lo tolgo anche dall\'altra rubrica');applyFilters();setTimeout(sistemaEAggiorna,600);},
      function(e){btn.disabled=false;btn.textContent=testo;toast(e.message,true);});}
function eliminaEx(c,btn){
  btn.disabled=true;
  googleToken().then(function(){return Promise.all((c.referenti||[]).map(contattoMio));})
    .then(function(l){btn.disabled=false;var visti={};eliminaDefinitivo(c,l.filter(function(p){if(!p||visti[p.resourceName])return false;visti[p.resourceName]=1;return true;}),btn);},
      function(e){btn.disabled=false;toast(e.message,true);});}
// salva la lista degli ex clienti (cifrata) nel documento network_meta/ex_clienti
function senzaInterni(c){var o={};Object.keys(c).forEach(function(k){if(k!=='_id'&&k!=='_ex')o[k]=c[k];});return o;}
function scriviEx(lista){var l=lista.map(senzaInterni);
  return enc({lista:l}).then(function(d){return EXDOC.set({d:d,v:1,aggiornato:new Date().toISOString(),da:S.user.email});}).then(function(){S.exSalvato=canonico(l);});}
// confronto "a chiavi ordinate": stesso contenuto = stesso testo (niente riscritture inutili)
function canonico(x){return JSON.stringify(x,function(k,v){if(v&&typeof v==='object'&&!Array.isArray(v)){var o={};Object.keys(v).sort().forEach(function(z){o[z]=v[z];});return o;}return v;});}

// ── FILTRI (pannello) ─────────────────────────────────────────────────────
function countBy(field){var o={};S.clients.forEach(function(c){(field==='zona'?[c.zona]:(c[field]||[])).forEach(function(v){o[v]=(o[v]||0)+1;});});return o;}
function chipGroup(title,k,field){var cnt=countBy(field);var keys=Object.keys(cnt).sort(function(a,b){return field==='zona'?a.localeCompare(b):cnt[b]-cnt[a];});
  return el('div',{cls:'fgroup'},[el('div',{cls:'sec',text:title}),el('div',{cls:'chips'},keys.map(function(v){
    var b=el('button',{cls:'chip'+(S.f[k][v]?' on':''),onclick:function(){S.f[k][v]=!S.f[k][v];b.classList.toggle('on');}},[field==='zona'?el('span',{cls:'zdot',style:'margin:0;width:10px;height:10px;background:'+(zoneColor[v]||'#999')}):null,v,el('span',{cls:'n',text:String(cnt[v])})]);return b;}))]);}
document.getElementById('fbtn').addEventListener('click',function(){
  openOv([el('div',{cls:'mhead'},[el('div',{cls:'mtitle',text:'Filtri'}),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},[chipGroup('Zona','zone','zona'),chipGroup('Prodotti','prod','prodotti'),chipGroup('Sigilli','sig','sigilli'),chipGroup('Pagamento','pag','pagamento'),
      el('div',{cls:'fbtns'},[el('button',{cls:'sbtn',style:'background:var(--surface2);border:1.5px solid var(--border)',text:'Azzera',onclick:function(){S.f={zone:{},prod:{},sig:{},pag:{}};applyFilters(true);closeOv();}}),
        el('button',{cls:'sbtn',style:'background:var(--orange);color:#fff',text:'Applica',onclick:function(){applyFilters(true);closeOv();}})])])]);
});

// ── STATISTICHE ───────────────────────────────────────────────────────────
function statBlock(title,field){var c=countBy(field);var keys=Object.keys(c).sort(function(a,b){return c[b]-c[a];});var max=Math.max.apply(null,keys.map(function(k){return c[k];}).concat([1]));
  return el('div',{},[el('div',{cls:'sec',text:title})].concat(keys.map(function(k){return el('div',{cls:'stat'},[el('span',{style:'min-width:130px',text:k}),el('div',{cls:'bar'},[el('i',{style:'width:'+(c[k]/max*100)+'%;background:'+(field==='zona'?(zoneColor[k]||'#f97316'):'#16a87a')})]),el('b',{text:String(c[k])})]);})));}
document.getElementById('stbtn').addEventListener('click',function(){
  var refs=S.clients.reduce(function(s,c){return s+(c.referenti||[]).length;},0);
  openOv([el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:'Statistiche'}),el('div',{cls:'msub',text:new Set(S.clients.map(function(c){return c.placeId||c.id;})).size+' locali · '+refs+' referenti'})]),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},[statBlock('Locali per zona','zona'),statBlock('Prodotti','prodotti'),statBlock('Sigilli','sigilli')])]);
});

// ── NUOVO CLIENTE: locale da Google Maps → contatto in rubrica Google + scheda cifrata sulla mappa ──
// Stesso formato degli script del PC: Nome "Tram Comune Locale", Cognome referente, P.IVA in Qualifica,
// SDI in Reparto, indirizzo di lavoro, link Maps, note a righe fisse, gruppi "Clienti Framezzino" + zona.
var PRODOTTI=['S','M','L','Magnum','XXL','Rettangolari','Panini','Toast','Tostoni','Maxi tostoni','Galaxy','Club','Veline','Sacchetti'];
var SIGILLI=['Personalizzati','Colorati','Smile','Produzione propria'];
var PAGAMENTI=['Bonifico','Contrassegno','PayPal','Spedizione'];
var PEOPLE='https://people.googleapis.com/v1/', gTok=null, gClient=null;
function fmtPhone(v){var d=(v||'').replace(/[^\d+]/g,'');if(d.indexOf('0039')===0)d='+39'+d.slice(4);
  if(/^3\d{9}$/.test(d))d='+39'+d;if(/^0\d{5,11}$/.test(d))d='+39'+d;
  var m=d.match(/^\+39(3\d{2})(\d{3})(\d{3,4})$/);if(m)return '+39 '+m[1]+' '+m[2]+' '+m[3];
  m=d.match(/^\+39(0\d{1,3})(\d{3,8})$/);if(m)return '+39 '+m[1]+' '+m[2];return (v||'').trim();}
function loadGis(){if(window.google&&google.accounts&&google.accounts.oauth2)return Promise.resolve();
  return new Promise(function(res,rej){var s=document.createElement('script');s.src='https://accounts.google.com/gsi/client';s.onload=res;s.onerror=function(){rej(new Error('Accesso Google non disponibile'));};document.head.appendChild(s);});}
function papi(path,method,body){return fetch(PEOPLE+path,{method:method||'GET',headers:{Authorization:'Bearer '+gTok.t,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined})
  .then(function(r){return r.json().catch(function(){return {};}).then(function(j){if(!r.ok)throw new Error('Rubrica Google: '+((j.error&&j.error.message)||r.status));return j;});});}
function comp(pl,t){var x=(pl.addressComponents||[]).find(function(c){return c.types.indexOf(t)>=0;});return x||{longText:'',shortText:''};}
// Zone (decise da Jacopo il 21/11): fuori Veneto ogni regione e' una zona; "Fuori zona" solo per l'estero; in Veneto
// la zona dei clienti vicini (entro 25 km), altrimenti "Veneto" provvisoria con il pallino rosso "zona da decidere".
var REGIONI=['Abruzzo','Basilicata','Calabria','Campania','Emilia-Romagna','Friuli-Venezia Giulia','Lazio','Liguria','Lombardia','Marche','Molise','Piemonte','Puglia','Sardegna','Sicilia','Toscana','Trentino-Alto Adige','Umbria',"Valle d'Aosta",'Veneto'];
var ZONA_PROVV='Veneto',MOTIVO_ZONA='zona da decidere: in Veneto ma lontano dai clienti delle altre zone (messo in "Veneto" per ora)';
function regioneDi(nome){var n=norm(nome).replace(/[^a-z0-9]+/g,' ').trim();
  var r=REGIONI.find(function(x){return n.indexOf(norm(x).replace(/[^a-z0-9]+/g,' ').trim())===0;});return r||(nome||'').trim();}
function zonaVeneta(z){return !!z&&z!=='Fuori zona'&&REGIONI.indexOf(z)<0;}
function zonaVicina(lat,lng){var best=null,bd=1e9;S.clients.forEach(function(c){if(c.lat==null||!zonaVeneta(c.zona))return;var d=dist({lat:lat,lng:lng},c);if(d<bd){bd=d;best=c.zona;}});return bd<=25?best:null;}
function zonaPer(pl){var paese=comp(pl,'country').shortText;if(paese&&paese!=='IT')return 'Fuori zona';
  var reg=regioneDi(comp(pl,'administrative_area_level_1').longText);if(reg&&reg!=='Veneto')return reg;
  return zonaVicina(pl.location.lat(),pl.location.lng())||(reg==='Veneto'?ZONA_PROVV:'Fuori zona');}
// zone per le tendine: prima quelle venete, poi le regioni, in fondo "Fuori zona"
function zoneOpzioni(extra){var zs={};Object.keys(countBy('zona')).concat(extra||[]).forEach(function(z){if(z)zs[z]=1;});
  var l=Object.keys(zs).filter(function(z){return z!=='Fuori zona';});
  return l.filter(zonaVeneta).sort().concat(l.filter(function(z){return !zonaVeneta(z);}).sort()).concat(['Fuori zona']);}
function zonaSelect(id,valore,extra){var s=el('select',{cls:'fi sm',id:id},zoneOpzioni([valore].concat(extra||[])).map(function(z){return el('option',{value:z,text:z+(z===ZONA_PROVV?' (provvisoria)':'')});}));if(valore)s.value=valore;return s;}
function zonaImposta(sel,z){if(![].some.call(sel.options,function(o){return o.value===z;}))sel.appendChild(el('option',{value:z,text:z}));sel.value=z;}

function openNewClient(){
  if(!window.GOOGLE_CLIENT_ID){toast('Manca l\'ID client Google in config.js',true);return;}
  loadGis().catch(function(){});
  var st={place:null,prod:{},sig:{},pag:{},omaggio:false,token:null,timer:null};
  function chipRow(list,obj){return el('div',{cls:'chips'},list.map(function(v){var b=el('button',{cls:'chip',type:'button',text:v,onclick:function(){obj[v]=!obj[v];b.classList.toggle('on',!!obj[v]);}});return b;}));}
  function field(id,ph,type){return el('input',{cls:'fi sm',id:id,placeholder:ph,type:type||'text',autocomplete:'off'});}
  var q=field('nc-q','Nome del locale e comune, es. Bar Roma Schio'),sugg=el('div',{}),box=el('div',{}),err=el('div',{cls:'ferr'});
  var zsel=zonaSelect('nc-zona','');
  var omg=el('button',{cls:'chip',type:'button',text:'🎁 Omaggio',onclick:function(){st.omaggio=!st.omaggio;omg.classList.toggle('on',st.omaggio);}});
  var bSenza=el('button',{cls:'chip',type:'button',text:'📦 Non ha un locale (spedizioni, indirizzo sconosciuto)',onclick:function(){st.senza=!st.senza;bSenza.classList.toggle('on',st.senza);
    q.disabled=st.senza;sugg.innerHTML='';box.innerHTML='';if(st.senza){st.place=null;q.value='';}}});
  var save=el('button',{cls:'sbtn',style:'background:var(--orange);color:#fff;width:100%;margin-top:16px',text:'Salva in rubrica e sulla mappa'});
  q.addEventListener('input',function(){clearTimeout(st.timer);var t=q.value.trim();if(t.length<3){sugg.innerHTML='';return;}st.timer=setTimeout(function(){cerca(t);},300);});
  function cerca(t){
    google.maps.importLibrary('places').then(function(P){
      if(!st.token)st.token=new P.AutocompleteSessionToken();
      return P.AutocompleteSuggestion.fetchAutocompleteSuggestions({input:t,sessionToken:st.token,language:'it',region:'it',
        locationBias:{center:{lat:45.55,lng:11.55},radius:50000}});
    }).then(function(r){sugg.innerHTML='';var list=(r.suggestions||[]).filter(function(s){return s.placePrediction;}).slice(0,6);
      if(!list.length){sugg.appendChild(el('div',{cls:'msub',style:'margin-top:6px',text:'Nessun locale trovato su Google Maps.'}));return;}
      sugg.appendChild(el('div',{cls:'sugg'},list.map(function(s){var p=s.placePrediction;
        return el('button',{type:'button',onclick:function(){scegli(p);}},[(p.mainText||p.text).text,el('small',{text:p.secondaryText?p.secondaryText.text:''})]);})));
    }).catch(function(e){sugg.innerHTML='';sugg.appendChild(el('div',{cls:'ferr',text:'Ricerca non riuscita: '+e.message+(/blocked|denied|not authorized/i.test(e.message)?'\n(la chiave Maps deve avere abilitata "Places API (New)")':'')}));});
  }
  function scegli(pred){
    var pl=pred.toPlace();st.token=null;
    pl.fetchFields({fields:['id','displayName','formattedAddress','location','addressComponents','nationalPhoneNumber','googleMapsURI','businessStatus']}).then(function(){
      st.place=pl;sugg.innerHTML='';q.value=pl.displayName||'';
      var city=comp(pl,'locality').longText||comp(pl,'administrative_area_level_3').longText||comp(pl,'postal_town').longText;
      document.getElementById('nc-comune').value=city;document.getElementById('nc-locale').value=pl.displayName||'';
      zonaImposta(zsel,zonaPer(pl));
      var gia=S.clients.filter(function(c){return (c.placeId||c.id)===pl.id;});
      box.innerHTML='';box.appendChild(el('div',{cls:'placebox'},[el('b',{text:pl.displayName}),el('div',{text:pl.formattedAddress}),
        pl.businessStatus&&pl.businessStatus!=='OPERATIONAL'?el('div',{style:'color:var(--red);font-weight:700',text:'⚠ Google lo indica come chiuso'}):null,
        gia.length?el('div',{style:'margin-top:4px;font-weight:700',text:'Già sulla mappa con: '+gia.map(function(c){return (c.referenti&&c.referenti[0]&&nomeRef(c.referenti[0],c))||c.locale;}).join(', ')+' — verrà aggiunto come referente in più.'}):null]));
    }).catch(function(e){err.textContent='Dettagli del locale non disponibili: '+e.message;});
  }
  openOv([el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:'Nuovo cliente'}),el('div',{cls:'msub',text:'Salvato già sistemato nella rubrica Google e sulla mappa'})]),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},[
      el('div',{cls:'flbl',style:'margin-top:0',text:'Locale su Google Maps *'}),q,sugg,box,el('div',{cls:'chips',style:'margin-top:6px'},[bSenza]),
      el('div',{cls:'flbl',text:'Comune *'}),field('nc-comune','Comune'),
      el('div',{cls:'flbl',text:'Nome del locale (come vuoi vederlo in rubrica) *'}),field('nc-locale','es. Bar Roma'),
      el('div',{cls:'flbl',text:'Referente'}),field('nc-ref','Nome della persona'),
      el('div',{cls:'flbl',text:'Telefono *'}),field('nc-tel','es. 333 123 4567','tel'),
      el('div',{cls:'flbl',text:'Prodotti'}),chipRow(PRODOTTI,st.prod),
      el('div',{cls:'flbl',text:'Sigilli (niente = neutri)'}),chipRow(SIGILLI,st.sig),el('div',{cls:'chips',style:'margin-top:6px'},[omg]),
      el('div',{cls:'flbl',text:'Pagamento'}),chipRow(PAGAMENTI,st.pag),
      el('div',{cls:'flbl',text:'Altro (note libere)'}),el('textarea',{cls:'fi sm',id:'nc-altro',rows:'2',placeholder:'es. vuole le veline 25x37'}),
      el('div',{cls:'flbl',text:'Ragione sociale · P.IVA · SDI (facoltativi)'}),field('nc-az','Ragione sociale'),
      el('div',{style:'display:flex;gap:8px;margin-top:6px'},[field('nc-piva','P.IVA'),field('nc-sdi','SDI')]),
      el('div',{cls:'flbl',text:'Zona'}),zsel,
      err,save])]);
  save.addEventListener('click',function(){
    var v=function(id){return document.getElementById(id).value.trim();};
    var comune=v('nc-comune'),locale=v('nc-locale'),ref=v('nc-ref'),tel=fmtPhone(v('nc-tel'));err.textContent='';
    var miss=[];if(!st.place&&!st.senza)miss.push('scegli il locale dai suggerimenti di Google Maps (o "Non ha un locale")');if(!comune&&!st.senza)miss.push('comune');if(!locale)miss.push(st.senza?'nome (come vuoi vederlo in rubrica)':'nome del locale');if(!tel)miss.push('telefono');
    if(miss.length){err.textContent='Manca: '+miss.join(', ');return;}
    var dati={comune:comune,locale:locale,ref:ref,tel:tel,az:v('nc-az'),piva:v('nc-piva').replace(/\s/g,''),sdi:v('nc-sdi').toUpperCase(),altro:v('nc-altro'),zona:zsel.value,
      prod:PRODOTTI.filter(function(x){return st.prod[x];}),sig:SIGILLI.filter(function(x){return st.sig[x];}).map(function(x){return x+(st.omaggio?' (omaggio)':'');}),
      pag:PAGAMENTI.filter(function(x){return st.pag[x];}),place:st.place,senza:!!st.senza};
    if(st.omaggio&&!dati.sig.length){err.textContent='Hai scelto Omaggio: scegli anche il tipo di sigillo.';return;}
    save.disabled=true;save.textContent='Accesso a Google…';
    function go(){
      // il numero c'e' gia' in rubrica? (non al nuovo tentativo dopo un errore: il contatto creato prima e' il suo)
      var controllo=st.creato?Promise.resolve(null):(save.textContent='Controllo il numero…',numeroGiaInRubrica(dati.tel));
      controllo.then(function(g){
        if(g&&!window.confirm(g.cliente?'Il numero '+dati.tel+' è già sulla mappa nel cliente «'+g.nome+'».\n\nOK = crea lo stesso un contatto nuovo\nAnnulla = apri quel cliente'
          :'Il numero '+dati.tel+' è già in rubrica: «'+g.nome+'».\n\nMeglio rinominare quel contatto «Tram Comune Locale Nome»: lo script lo sistema da solo.\n\nOK = crea lo stesso un contatto nuovo\nAnnulla = non salvo niente')){
          save.disabled=false;save.textContent='Salva in rubrica e sulla mappa';if(g.cliente){closeOv();setTimeout(function(){openDetail(g.doc,true);},300);}return;}
        save.textContent='Salvo…';
        return (dati.senza?salvaSenzaLocale(dati,st):salvaNuovo(dati,st)).then(function(c){closeOv();
          if(dati.senza){toast('Cliente senza locale salvato in rubrica ✓ (lo trovi in 🔄 → senza locale)');return;}
          toast('Cliente salvato in rubrica e sulla mappa ✓');setTimeout(function(){openDetail(c._doc||docId(c.id),true);},900);});
      }).catch(function(e){err.textContent=e.message;save.disabled=false;save.textContent='Salva in rubrica e sulla mappa';});}
    if(gTok&&gTok.exp>Date.now()+60000){go();return;}
    // la finestra di accesso Google deve partire dal tocco: niente attese prima di requestAccessToken
    if(!(window.google&&google.accounts&&google.accounts.oauth2)){err.textContent='Accesso Google non ancora caricato: riprova tra un secondo.';save.disabled=false;save.textContent='Salva in rubrica e sulla mappa';return;}
    gClient=google.accounts.oauth2.initTokenClient({client_id:window.GOOGLE_CLIENT_ID,scope:'https://www.googleapis.com/auth/contacts',
      callback:function(r){if(r.error){err.textContent='Accesso Google non riuscito ('+r.error+')';save.disabled=false;save.textContent='Salva in rubrica e sulla mappa';return;}
        gTok={t:r.access_token,exp:Date.now()+(r.expires_in||3600)*1000};go();},
      error_callback:function(e){err.textContent='Accesso Google annullato'+(e&&e.type==='popup_failed_to_open'?': consenti i popup per questo sito':'');save.disabled=false;save.textContent='Salva in rubrica e sulla mappa';}});
    gClient.requestAccessToken();
  });
}
function salvaNuovo(x,st){
  var pl=x.place,lat=pl.location.lat(),lng=pl.location.lng();
  var city=comp(pl,'locality').longText||comp(pl,'administrative_area_level_3').longText||comp(pl,'postal_town').longText;
  var via=comp(pl,'route').longText,num=comp(pl,'street_number').longText;
  var note=[];if(x.prod.length)note.push('Prodotti: '+x.prod.join(', '));if(x.sig.length)note.push('Sigilli: '+x.sig.join(', '));
  if(x.pag.length)note.push('Pagamento: '+x.pag.join(', '));if(x.altro)note.push('Altro: '+x.altro.replace(/\s*\n\s*/g,' / '));
  var given='Tram '+x.comune+' '+x.locale, full=(given+' '+x.ref).trim();
  // nome TUTTO su una riga nel campo Nome (regola di Jacopo 12/11): niente cognome
  var body={names:[{givenName:full}],phoneNumbers:[{value:x.tel,type:/^\+39 3/.test(x.tel)?'mobile':'work'}],
    addresses:[{streetAddress:(via+(num?', '+num:'')).trim(),city:city,region:comp(pl,'administrative_area_level_2').shortText,postalCode:comp(pl,'postal_code').longText,country:'Italia',type:'work'}],
    urls:pl.googleMapsURI?[{value:pl.googleMapsURI.replace(/&.*$/,''),type:'work'}]:[],biographies:note.length?[{value:note.join('\n'),contentType:'TEXT_PLAIN'}]:[]};
  if(x.az||x.piva||x.sdi)body.organizations=[{name:x.az,title:x.piva?'P.IVA '+x.piva:'',department:x.sdi?'SDI '+x.sdi:'',type:'work'}];
  // campo nascosto con i dati per la mappa (lo stesso che scrive lo script): la mappa si aggiorna dalla rubrica
  var dm={placeId:pl.id,locale:x.locale,nomeGoogle:pl.displayName||'',comune:city||x.comune,provincia:comp(pl,'administrative_area_level_2').shortText,
    indirizzo:pl.formattedAddress||'',lat:lat,lng:lng,maps:(pl.googleMapsURI||'').replace(/&.*$/,''),telefonoLocale:pl.nationalPhoneNumber||'',zona:x.zona};
  body.clientData=[{key:'framezzino',value:JSON.stringify(dm)}];
  if(x.zona===ZONA_PROVV)body.clientData.push({key:'framezzino_decidere',value:JSON.stringify({motivo:MOTIVO_ZONA,data:new Date().toISOString().slice(0,10)})});
  var person;
  // nuovo tentativo dopo un errore a meta': il contatto c'e' gia' (st.creato) -> si aggiorna quello, niente doppione
  var crea=st&&st.creato?papi(st.creato+'?personFields='+PF).then(function(f){
      body.organizations=body.organizations||[];
      body.clientData=(f.clientData||[]).filter(function(c){return c.key!=='framezzino'&&c.key!=='framezzino_decidere';}).map(function(c){return {key:c.key,value:c.value};}).concat(body.clientData);
      return contattoAggiorna(f,body,'names,phoneNumbers,addresses,urls,biographies,organizations,clientData');})
    :papi('people:createContact?personFields=names','POST',body).then(function(p){if(st)st.creato=p.resourceName;return p;});
  return crea.then(function(p){person=p;
    return papi('contactGroups?pageSize=1000&groupFields=name,groupType');
  }).then(function(r){
    var gs=(r.contactGroups||[]).filter(function(g){return g.groupType==='USER_CONTACT_GROUP';});
    var want=['Clienti Framezzino','Clienti Framezzino '+x.zona];
    return Promise.all(want.map(function(n){var g=gs.find(function(g){return g.name===n;});
      return g?g.resourceName:papi('contactGroups','POST',{contactGroup:{name:n}}).then(function(ng){return ng.resourceName;});}));
  }).then(function(ids){
    return Promise.all(ids.map(function(id){return papi(id+'/members:modify','POST',{resourceNamesToAdd:[person.resourceName]});}));
  }).then(function(){
    // un pallino per locale: se il locale e' gia' sulla mappa il cliente diventa un referente in piu' della sua scheda
    var ref={nome:x.ref,telefoni:[x.tel],contatto:full,resourceName:person.resourceName,rubrica:rubricaMia()||'',
      prodotti:x.prod,sigilli:x.sig,pagamento:x.pag,note:x.altro?[x.altro]:[],azienda:x.az,piva:x.piva,sdi:x.sdi};
    var gia=S.clients.find(function(c){return (c.placeId||c.id)===pl.id;});
    var c=gia?ricomponi(gia,(gia.referenti||[]).concat([ref]),null)
      :ricomponi({id:pl.id,placeId:pl.id,locale:x.locale,nomeGoogle:pl.displayName||'',comune:city||x.comune,
      provincia:comp(pl,'administrative_area_level_2').shortText,indirizzo:pl.formattedAddress||'',lat:lat,lng:lng,
      maps:pl.googleMapsURI||'',telefonoLocale:pl.nationalPhoneNumber||'',zona:x.zona},[ref],null);
    var docRef=gia?CCOL.doc(gia._id):CCOL.doc(docId(c.id));
    return enc(c).then(function(d){return docRef.set({d:d,v:1,aggiornato:new Date().toISOString(),da:S.user.email});})
      .then(function(){c._doc=docRef.id;return c;},function(e){throw new Error('Salvato in rubrica ma non sulla mappa: '+permMsg(e));});
  });
}
// "+ Nuovo": il numero c'e' gia'? Prima i clienti sulla mappa, poi tutta la rubrica Google (anche i personali)
function ultime9(v){var d=(v||'').replace(/\D/g,'');return d.length>=9?d.slice(-9):'';}
function numeroGiaInRubrica(tel){var k=ultime9(tel);if(!k)return Promise.resolve(null);
  var c=S.clients.find(function(x){return (x.referenti||[]).some(function(r){return (r.telefoni||[]).some(function(t){return ultime9(t)===k;});});});
  if(c)return Promise.resolve({nome:c.locale,cliente:true,doc:c._id});
  return leggiRubrica().then(function(r){var p=r[0].find(function(p){return (p.phoneNumbers||[]).some(function(t){return ultime9(t.value)===k;});});
    return p?{nome:((p.names||[])[0]||{}).displayName||'(senza nome)',cliente:false}:null;});}
// "+ Nuovo" di un cliente senza locale (spedizioni, indirizzo sconosciuto): in rubrica nel gruppo "Clienti Framezzino"
// (+ zona se scelta), niente pallino sulla mappa (campo nascosto senzaMappa, come "Cliente senza locale" dei Da decidere)
function salvaSenzaLocale(x,st){
  var note=[];if(x.prod.length)note.push('Prodotti: '+x.prod.join(', '));if(x.sig.length)note.push('Sigilli: '+x.sig.join(', '));
  if(x.pag.length)note.push('Pagamento: '+x.pag.join(', '));if(x.altro)note.push('Altro: '+x.altro.replace(/\s*\n\s*/g,' / '));
  var full=('Tram '+(x.comune?x.comune+' ':'')+x.locale+' '+x.ref).replace(/\s+/g,' ').trim();
  var body={names:[{givenName:full}],phoneNumbers:[{value:x.tel,type:/^\+39 3/.test(x.tel)?'mobile':'work'}],
    biographies:note.length?[{value:note.join('\n'),contentType:'TEXT_PLAIN'}]:[],clientData:[{key:'framezzino',value:JSON.stringify({senzaMappa:true})}]};
  if(x.az||x.piva||x.sdi)body.organizations=[{name:x.az,title:x.piva?'P.IVA '+x.piva:'',department:x.sdi?'SDI '+x.sdi:'',type:'work'}];
  var crea=st&&st.creato?papi(st.creato+'?personFields='+PF).then(function(f){body.organizations=body.organizations||[];
      return contattoAggiorna(f,body,'names,phoneNumbers,biographies,organizations,clientData');})
    :papi('people:createContact?personFields='+PF,'POST',body).then(function(p){if(st)st.creato=p.resourceName;return p;});
  return crea.then(function(p){return gruppiLista().then(function(gs){return gruppiZona(p,x.zona&&x.zona!==ZONA_PROVV?x.zona:null,gs);});})
    .then(function(){return null;});
}
document.getElementById('newbtn').addEventListener('click',function(e){e.stopPropagation();openNewClient();});

// ── RUBRICA → MAPPA (19/11): la mappa si aggiorna dalla rubrica Google di chi usa l'app ──────────────────
// Ogni cliente in rubrica ha un campo nascosto "framezzino" (scritto dallo script o da "+ Nuovo") con il locale Google.
// Un pallino per locale: la scheda tiene i referenti di tutte e due le rubriche; si aggiornano solo quelli della
// rubrica letta. I contatti che lo script non ha saputo sistemare hanno "framezzino_decidere": vanno in "Da decidere".
var SY={running:false,decidere:[],senza:0,quando:null,rubrica:null};
// l'accesso Google resta solo finche' l'app e' aperta (sessionStorage); il vecchio salvato nel telefono si cancella
try{localStorage.removeItem('fn_gtok');var _gt=JSON.parse(sessionStorage.getItem('fn_gtok')||'null');if(_gt&&_gt.exp>Date.now()+60000)gTok=_gt;}catch(e){}
function googleToken(){
  return new Promise(function(res,rej){
    if(gTok&&gTok.exp>Date.now()+60000)return res(gTok);
    if(!window.GOOGLE_CLIENT_ID)return rej(new Error('Manca l\'ID client Google in config.js'));
    if(!(window.google&&google.accounts&&google.accounts.oauth2)){loadGis().catch(function(){});return rej(new Error('Accesso Google non ancora caricato: riprova tra un secondo.'));}
    gClient=google.accounts.oauth2.initTokenClient({client_id:window.GOOGLE_CLIENT_ID,scope:'https://www.googleapis.com/auth/contacts',
      callback:function(r){if(r.error)return rej(new Error('Accesso Google non riuscito ('+r.error+')'));
        gTok={t:r.access_token,exp:Date.now()+(r.expires_in||3600)*1000};try{sessionStorage.setItem('fn_gtok',JSON.stringify(gTok));}catch(e){}res(gTok);},
      error_callback:function(e){rej(new Error('Accesso Google annullato'+(e&&e.type==='popup_failed_to_open'?': consenti i popup per questo sito':'')));}});
    gClient.requestAccessToken();
  });
}
function cdato(p,k){var x=(p.clientData||[]).find(function(c){return c.key===k;});if(!x)return null;try{return JSON.parse(x.value);}catch(e){return null;}}
function righeNota(note,k){var m=(note||'').match(new RegExp('^'+k+':[ \\t]*(.+)$','m'));return m?m[1].split(',').map(function(x){return x.trim();}).filter(Boolean):[];}
function altroNota(note){var m=(note||'').match(/^Altro:[ \t]*([\s\S]+)$/m);return m&&m[1].trim()?[m[1].trim()]:[];}
function rubricaMia(){return SY.rubrica;}
// nomi dei prodotti/sigilli/pagamenti come nei filtri, a prescindere da maiuscole ("Maxi Tostoni" = "Maxi tostoni");
// i nomi vecchi al singolare diventano plurali (Jacopo 22/11: "Tostone" -> "Tostoni", "Maxi tostone" -> "Maxi tostoni")
var ALIAS_PROD={'tostone':'Tostoni','maxi tostone':'Maxi tostoni','maxi tst':'Maxi tostoni','maxi tst.':'Maxi tostoni','xl':'Magnum'};
function canon(v,lista){if(lista===PRODOTTI&&ALIAS_PROD[(v||'').trim().toLowerCase()])return ALIAS_PROD[(v||'').trim().toLowerCase()];var b=(v||'').trim(),l=b.toLowerCase(),om=/\s*\(omaggio\)$/i.test(b)?' (omaggio)':'';var base=b.replace(/\s*\(omaggio\)$/i,'').toLowerCase();
  var x=lista.find(function(z){return z.toLowerCase()===l||z.toLowerCase()===base;});return x?(x.toLowerCase()===l?x:x+om):b;}
// RUBRICA UNICA (22/11): ogni cliente c'e' in tutte e due le rubriche; le due copie hanno lo stesso campo nascosto
// "framezzino_id" {id, jacopo: resourceName, marco: resourceName}. Sulla mappa il referente e' UNO: si riconosce
// dall'id e dai resourceName delle due copie (campo "copie" del referente).
function copieDi(p){var f=cdato(p,'framezzino_id'),o=[p.resourceName];if(f){if(f.jacopo)o.push(f.jacopo);if(f.marco)o.push(f.marco);}return o;}
function rnsRef(r){var o=[r.resourceName];if(r.copie)Object.keys(r.copie).forEach(function(k){o.push(r.copie[k]);});return o.filter(function(x,i){return x&&o.indexOf(x)===i;});}
function referenteDa(p,rubrica,vecchio){
  var n=(p.names||[])[0]||{},riga=(n.displayName||[n.givenName,n.middleName,n.familyName].filter(Boolean).join(' ')).trim();
  var note=(p.biographies||[]).map(function(b){return b.value||'';}).join('\n'),o=(p.organizations||[])[0]||{};
  var tel=(p.phoneNumbers||[]).map(function(t){return fmtPhone(t.value);}).filter(function(v,i,a){return v&&a.indexOf(v)===i;});
  var r={nome:(vecchio&&vecchio.nome)||'',telefoni:tel,contatto:riga,resourceName:(vecchio&&vecchio.resourceName)||p.resourceName,rubrica:(vecchio&&vecchio.rubrica)||rubrica,
    prodotti:righeNota(note,'Prodotti').map(function(v){return canon(v,PRODOTTI);}),sigilli:righeNota(note,'Sigilli').map(function(v){return canon(v,SIGILLI);}),
    pagamento:righeNota(note,'Pagamento').map(function(v){return canon(v,PAGAMENTI);}),note:altroNota(note),
    azienda:o.name||'',piva:(o.title||'').replace(/^P\.?\s*IVA\s*/i,''),sdi:(o.department||'').replace(/^SDI\s*/i,'')};
  var f=cdato(p,'framezzino_id');if(f&&f.id){r.id=f.id;r.copie={};if(f.jacopo)r.copie.jacopo=f.jacopo;if(f.marco)r.copie.marco=f.marco;}
  return r;
}
// scheda del locale ricomposta dai referenti: prodotti/sigilli/pagamento/note uniti; per i referenti "vecchi"
// (senza i loro prodotti) si tengono quelli che la scheda aveva gia'
// L'ordine resta quello che la scheda aveva gia' (referenti, prodotti, note...): i nuovi vanno in fondo. Prima (fino al
// 21/11) l'ordine dipendeva da quale rubrica si aggiornava per ultima, e ogni 🔄 alternato Jacopo/Marco riscriveva
// ~100 locali in comune senza cambiare niente ("96 locali aggiornati").
function nelVecchioOrdine(nuovi,vecchi,chiave){chiave=chiave||function(x){return x;};
  var pos={};(vecchi||[]).forEach(function(x,i){var k=chiave(x);if(!(k in pos))pos[k]=i;});
  return nuovi.map(function(x,i){var k=chiave(x);return {x:x,o:(k in pos)?pos[k]:1e6+i};}).sort(function(a,b){return a.o-b.o;}).map(function(z){return z.x;});}
function ricomponi(c,refs,dm){
  var n={};Object.keys(c).forEach(function(k){if(k!=='_id'&&k!=='_doc')n[k]=c[k];});
  refs=nelVecchioOrdine(refs,c.referenti,function(r){return r.resourceName;});
  ['prodotti','sigilli','pagamento','note'].forEach(function(k){
    var tutti=[];function add(v){if(v&&tutti.indexOf(v)<0)tutti.push(v);}
    if(refs.some(function(r){return !r[k];}))(c[k]||[]).forEach(add);
    refs.forEach(function(r){(r[k]||[]).forEach(add);});n[k]=nelVecchioOrdine(tutti,c[k]);});
  n.sigilli=n.sigilli.filter(function(s){return n.sigilli.indexOf(s+' (omaggio)')<0;});
  // "sì" (sigilli senza tipo) e' un doppione se il tipo c'e' gia' ("Personalizzati" + "sì")
  var tipi=n.sigilli.filter(function(s){return !/^s[iì](\s|$)/i.test(s);});
  if(tipi.length)n.sigilli=tipi;
  // se due referenti hanno valori diversi resta quello che la scheda aveva gia' (se uno dei referenti ce l'ha ancora)
  ['azienda','piva','sdi'].forEach(function(k){var r=refs.find(function(r){return r[k]&&r[k]===c[k];})||refs.find(function(r){return r[k];});if(r)n[k]=r[k];else if(n[k]==null)n[k]='';});
  if(dm&&!n.lat){['nomeGoogle','comune','provincia','indirizzo','lat','lng','maps','telefonoLocale','zona'].forEach(function(k){if(dm[k]!=null)n[k]=dm[k];});
    if(!n.locale)n.locale=dm.locale||dm.nomeGoogle;}
  n.referenti=refs;return n;
}
function chiaveScheda(c){var o={};Object.keys(c).sort().forEach(function(k){if(k!=='_id'&&k!=='_doc')o[k]=c[k];});return JSON.stringify(o);}
function leggiRubrica(){
  var all=[];
  function page(tok){return papi('people/me/connections?pageSize=1000&personFields=names,phoneNumbers,biographies,organizations,memberships,clientData,metadata'
    +(tok?'&pageToken='+encodeURIComponent(tok):'')).then(function(r){all=all.concat(r.connections||[]);return r.nextPageToken?page(r.nextPageToken):all;});}
  return page(null).then(function(cs){return papi('contactGroups?pageSize=1000&groupFields=name,groupType').then(function(g){return [cs,g.contactGroups||[]];});});
}
// Locale e zona cambiati DOPO (dall'app o da Claude): vince la modifica piu' recente. Il campo "agg" (data e ora)
// sta nella scheda e nel campo nascosto dei contatti. Se il contatto e' piu' recente la scheda prende il suo locale/zona;
// se la scheda e' piu' recente (cambiata dall'altra rubrica) il contatto si allinea: campo nascosto e gruppo della zona.
// "ex" nella scheda = locali Google di prima (locale cambiato dall'app): i contatti con il locale vecchio ci finiscono dentro.
var LOC=['placeId','nomeGoogle','comune','provincia','indirizzo','lat','lng','maps','telefonoLocale','zona'];
function aggiornaDaRubrica(daTocco){
  if(SY.running)return;
  // con la sola copia del telefono (senza rete o appena aperta) la mappa potrebbe essere vecchia: non si riscrive niente
  if(S.daCache||!navigator.onLine){if(daTocco)toast('Aspetto di essere collegato a internet per aggiornare la mappa: riprova tra poco.',true);return;}SY.running=true;segnaSync();
  var gruppi=[];
  googleToken().then(leggiRubrica).then(function(r){
    var contacts=r[0];gruppi=r[1]||[];var gid=(gruppi.find(function(g){return g.name==='Clienti Framezzino';})||{}).resourceName;
    // contatti cambiati o cancellati dall'app negli ultimi 15 minuti: l'elenco di Google li mostra in ritardo (27/11),
    // quindi si usa la versione letta subito dopo la modifica e si saltano quelli appena cancellati
    var ora=Date.now(),fr=SY.freschi||{},elim=SY.eliminati||{};
    contacts=contacts.filter(function(p){var e=elim[p.resourceName];return !(e&&ora-e<9e5);})
      .map(function(p){var f=fr[p.resourceName];  // la versione letta dopo la modifica, se l'elenco ne ha una piu' vecchia
        return f&&ora-f.t<9e5&&aggiornatoIl(f.p)>aggiornatoIl(p)?f.p:p;});
    if(!gid)throw new Error('In questa rubrica non c\'è il gruppo "Clienti Framezzino": hai scelto l\'account Google giusto?');
    // di chi e' questa rubrica: dei referenti gia' sulla mappa (Jacopo / Marco), altrimenti dell'utente dell'app
    var rns={},conta={};contacts.forEach(function(p){rns[p.resourceName]=1;});
    S.clients.forEach(function(s){(s.referenti||[]).forEach(function(x){if(rns[x.resourceName]&&x.rubrica)conta[x.rubrica]=(conta[x.rubrica]||0)+1;});});
    var rubrica=Object.keys(conta).sort(function(a,b){return conta[b]-conta[a];})[0]||(S.user&&S.user.email)||'rubrica';
    SY.rubrica=rubrica;
    var rk=String(rubrica).toLowerCase();  // sui referenti "Jacopo"/"Marco", nelle copie "jacopo"/"marco"
    var exDi={};S.clients.forEach(function(c){(c.ex||[]).forEach(function(o){exDi[o]=c;});});
    var mio={};contacts.forEach(function(p){copieDi(p).forEach(function(x){mio[x]=p;});});  // rn (mio o della copia gemella) -> mio contatto
    var miei={},decidere=[],senza=0,senzaLista=[],exLista=[],exMiei={},exGid=(gruppi.find(function(g){return g.name===EX_GRUPPO;})||{}).resourceName;
    contacts.forEach(function(p){
      var nm=(((p.names||[])[0]||{}).displayName)||'',dd=cdato(p,'framezzino_decidere');
      if(dd)decidere.push({nome:nm,motivo:dd.motivo||'',data:dd.data||'',rn:p.resourceName});
      var inEx=!!exGid&&(p.memberships||[]).some(function(m){return m.contactGroupMembership&&m.contactGroupMembership.contactGroupResourceName===exGid;});
      if(inEx)exLista.push({nome:nm,rn:p.resourceName});
      var inGr=(p.memberships||[]).some(function(m){return m.contactGroupMembership&&m.contactGroupMembership.contactGroupResourceName===gid;});
      if(!inGr){  // ex cliente con il locale: va nella lista degli ex (pallini grigi a richiesta)
        if(inEx){var dx=cdato(p,'framezzino');if(dx&&dx.placeId&&!dx.senzaMappa)(exMiei[dx.placeId]=exMiei[dx.placeId]||{dm:dx,refs:[]}).refs.push(p);}
        return;}
      var dm=cdato(p,'framezzino');
      if(!dm||dm.senzaMappa||!dm.placeId){senza++;senzaLista.push({nome:nm,rn:p.resourceName,tel:(p.phoneNumbers||[]).map(function(t){return fmtPhone(t.value);}).filter(function(v,i,a){return v&&a.indexOf(v)===i;})});return;}
      var pid=dm.placeId,t=exDi[pid];
      if(t&&(dm.agg||'')<=(t.agg||''))pid=t.placeId||t.id;  // locale cambiato dall'app: va nella scheda nuova
      p._dm=dm;
      (miei[pid]=miei[pid]||{dm:dm,refs:[]}).refs.push(p);
    });
    var scrivi=[],togli=[],allinea=[];
    function controlla(n,pid,ps){  // contatti di questa rubrica con locale/zona piu' vecchi della scheda -> da allineare
      ps.forEach(function(p){var d=p._dm;if((n.agg||'')>(d.agg||'')&&(d.placeId!==pid||d.zona!==n.zona)){
        var nd=Object.assign({},d);LOC.forEach(function(k){if(n[k]!=null)nd[k]=n[k];});nd.placeId=pid;nd.agg=n.agg;
        allinea.push({p:p,dm:nd,zona:n.zona});}});}
    // referenti gia' noti (schede dei clienti e degli ex): un cliente che torna o che diventa ex tiene il nome del referente
    var refVecchi={};S.clients.concat(S.ex||[]).forEach(function(c){(c.referenti||[]).forEach(function(x){rnsRef(x).forEach(function(k){if(!refVecchi[k])refVecchi[k]=x;});});});
    function vecchioDi(p){var v=null;copieDi(p).some(function(k){v=refVecchi[k];return !!v;});return v;}
    S.clients.forEach(function(c){
      var pid=c.placeId||c.id,vecchi={};(c.referenti||[]).forEach(function(x){rnsRef(x).forEach(function(k){if(!vecchi[k])vecchi[k]=x;});});
      var m=miei[pid],nuoviRn={};(m?m.refs:[]).forEach(function(p){copieDi(p).forEach(function(k){nuoviRn[k]=1;});});
      // referenti dell'altra rubrica ancora da tenere: non sono miei (ne' la mia copia), e non cancellati dalla mia rubrica
      var altri=(c.referenti||[]).filter(function(x){return x.rubrica!==rubrica&&!rnsRef(x).some(function(k){return nuoviRn[k]||mio[k];})
        &&!(x.copie&&x.copie[rk]&&!rns[x.copie[rk]]);});
      var refs=altri.concat((m?m.refs:[]).map(function(p){var v=null;copieDi(p).some(function(k){v=vecchi[k];return !!v;});return referenteDa(p,rubrica,v);}));
      delete miei[pid];
      if(!refs.length){togli.push(c);return;}
      var n=ricomponi(c,refs,null);
      var nuovo=null;(m?m.refs:[]).forEach(function(p){if((p._dm.agg||'')>((nuovo&&nuovo.agg)||c.agg||''))nuovo=p._dm;});
      if(nuovo){LOC.forEach(function(k){if(k!=='placeId'&&nuovo[k]!=null)n[k]=nuovo[k];});n.agg=nuovo.agg;}
      controlla(n,pid,m?m.refs:[]);
      if(chiaveScheda(n)!==chiaveScheda(c))scrivi.push({doc:c._id,c:n});
    });
    Object.keys(miei).forEach(function(pid){var m=miei[pid],dm=m.dm;
      m.refs.forEach(function(p){if((p._dm.agg||'')>(dm.agg||''))dm=p._dm;});
      var n=ricomponi({id:pid,placeId:pid,locale:dm.locale||dm.nomeGoogle||'',zona:dm.zona||'Fuori zona'},m.refs.map(function(p){return referenteDa(p,rubrica,vecchioDi(p));}),dm);
      if(dm.agg)n.agg=dm.agg;
      controlla(n,pid,m.refs);
      scrivi.push({doc:docId(pid),c:n});});
    // EX CLIENTI (27/11): una scheda per locale dai contatti dell'etichetta "Ex clienti Framezzino" (non piu' nei clienti),
    // uguale qualunque rubrica la calcoli (le due rubriche hanno gli stessi ex clienti). Un locale che ha ancora un
    // cliente attivo non compare tra gli ex.
    var attivi={};S.clients.forEach(function(c){if(togli.indexOf(c)<0)attivi[c.placeId||c.id]=1;});scrivi.forEach(function(x){attivi[x.c.placeId||x.c.id]=1;});
    var exCards=Object.keys(exMiei).filter(function(pid){return !attivi[pid];}).sort().map(function(pid){var m=exMiei[pid],dm=m.dm;
      var refs=m.refs.map(function(p){var x=referenteDa(p,'',vecchioDi(p));delete x.rubrica;if(x.copie)x.resourceName=x.copie.jacopo||x.copie.marco||x.resourceName;return x;})
        .sort(function(a,b){return String(a.id||a.resourceName).localeCompare(String(b.id||b.resourceName));});
      var n=ricomponi({id:pid,placeId:pid,locale:dm.locale||dm.nomeGoogle||'',zona:dm.zona||'Fuori zona'},refs,dm);
      m.refs.forEach(function(p){var x=/Ex cliente dal (\d{1,2}\/\d{1,2}\/\d{2,4})/i.exec(notaDi(p));if(x&&!n.exDal)n.exDal=x[1];});
      return n;});
    // confronto con quello che e' davvero salvato (non con quello che si vede: dopo "Ripristina" l'ex sparisce subito)
    var exCambiati=!S.exLeggibile||S.exSalvato!==canonico(exCards);
    SY.decidere=decidere;SY.senza=senza;SY.senzaLista=senzaLista;SY.exLista=exLista;SY.quando=new Date();
    // freni di sicurezza: se qualcosa non torna non si tocca la mappa
    var conCampo=contacts.filter(function(p){return cdato(p,'framezzino');}).length,mie=S.clients.filter(function(c){return (c.referenti||[]).some(function(x){return x.rubrica===rubrica;});}).length;
    if(!conCampo)throw new Error('In questa rubrica nessun cliente ha ancora i dati per la mappa: la mappa non è stata toccata. (Avvisa Claude)');
    if(togli.length>Math.max(10,mie*0.05))throw new Error('Aggiornando dalla rubrica verrebbero tolti '+togli.length+' locali dalla mappa: troppi, mi fermo e non tocco niente. (Avvisa Claude)');
    if(/[?&]prova\b/.test(location.search)){  // prova: calcola e mostra, non scrive niente
      window.FN_PROVA={rubrica:rubrica,scrivi:scrivi,togli:togli,allinea:allinea,decidere:decidere,senza:senza,ex:exCards,exCambiati:exCambiati};
      toast('PROVA: '+scrivi.length+' locali da aggiornare, '+togli.length+' da togliere, '+allinea.length+' contatti da allineare, '+exCards.length+' ex clienti'+(exCambiati?' (da salvare)':'')+' · niente scritto');return [0,0,0];}
    var fatto=!scrivi.length&&!togli.length?Promise.resolve():Promise.all(scrivi.map(function(x){return enc(x.c).then(function(d){return {ref:CCOL.doc(x.doc),d:d};});})).then(function(rows){
      var ops=rows.map(function(x){return {set:x};}).concat(togli.map(function(c){return {del:CCOL.doc(c._id)};}));
      var now=new Date().toISOString(),chunks=[];for(var i=0;i<ops.length;i+=400)chunks.push(ops.slice(i,i+400));
      return chunks.reduce(function(pr,ch){return pr.then(function(){var b=db.batch();
        ch.forEach(function(o){if(o.set)b.set(o.set.ref,{d:o.set.d,v:1,aggiornato:now,da:S.user.email});else b.delete(o.del);});return b.commit();});},Promise.resolve());
    });
    return fatto.then(function(){
      if(!exCambiati)return;
      return scriviEx(exCards).then(function(){S.ex=exCards.map(function(c){c._id='ex:'+(c.placeId||c.id);c._ex=true;return c;});S.exLeggibile=true;});
    }).then(function(){
      if(!allinea.length)return 0;
      if(allinea.length>40){toast(allinea.length+' contatti da allineare in rubrica: troppi, non li tocco. (Avvisa Claude)',true);return 0;}
      return allineaRubrica(allinea,gruppi);
    }).then(function(k){return [scrivi.length,togli.length,k,exCambiati?1:0];});
  }).then(function(n){
    try{localStorage.setItem('fn_sync_'+(SY.rubrica||''),String(Date.now()));localStorage.setItem('fn_rubrica',SY.rubrica||'');localStorage.setItem('fn_dd_n',String(SY.decidere.length));}catch(e){}
    if(!/[?&]prova\b/.test(location.search))db.collection('network_meta').doc('aggiornamento').set({quando:new Date().toISOString(),chi:SY.rubrica||''}).catch(function(){});
    SY.running=false;segnaSync();
    if(daTocco||n[0]||n[1]||n[2]||n[3])toast('Mappa aggiornata dalla rubrica ✓'+(n[0]?' · '+n[0]+' locali aggiornati':'')+(n[1]?' · '+n[1]+' tolti':'')+(n[2]?' · '+n[2]+' contatti allineati':'')+(n[3]?' · ex clienti aggiornati':'')+(!n[0]&&!n[1]&&!n[2]&&!n[3]?' · niente da cambiare':''));
    applyFilters();
    if(SY.decidere.length&&!daTocco)toast(SY.decidere.length+(SY.decidere.length===1?' contatto da decidere':' contatti da decidere')+': tocca 🔄');
  }).catch(function(e){SY.running=false;segnaSync();if(daTocco||!/Accesso Google non ancora/.test(e.message))toast(e.message,true);});
}
// contatti di questa rubrica da allineare alla scheda (locale/zona cambiati dall'altra rubrica): campo nascosto + gruppo zona
function allineaRubrica(lista,gruppi){var k=0;
  return lista.reduce(function(pr,x){return pr.then(function(){
    return contattoAggiorna(x.p,{clientData:conDati(x.p,x.dm,decidereDopo(x.p,x.zona))},'clientData')
      .then(function(np){return gruppiZona(np,x.zona,gruppi);}).then(function(){k++;},function(e){console.warn('allinea',x.p.resourceName,e);});});},Promise.resolve())
    .then(function(){return k;});}
// pallino sul 🔄: numero dei "Da decidere" (rosso; prima del primo 🔄 quello dell'ultima volta), arancione = non ancora aggiornata
function segnaSync(){var d=document.getElementById('sydot'),b=document.getElementById('sybtn');if(!d)return;
  var n=SY.quando?SY.decidere.length:(parseInt((function(){try{return localStorage.getItem('fn_dd_n');}catch(e){return '';}})(),10)||0);
  var ko=!!(SY.cloud&&SY.cloud.ok===false);
  d.classList.toggle('on',!!n||ko||!SY.quando);d.classList.toggle('num',!!n||ko);d.textContent=n?String(n):(ko?'!':'');d.style.background=n||ko?'var(--red)':'var(--orange)';
  b.classList.toggle('spin',SY.running);}
// ── SCRIPT NEL CLOUD (GitHub, repository privato) avviato dal 🔄: sistema la rubrica di chi usa l'app, poi la mappa ──
// La chiave GitHub (solo "Actions" sul repository framezzino-sync) e' salvata CIFRATA con la password della mappa.
var GH={repo:'Jacuziaaa/framezzino-sync',wf:'rubriche.yml',tok:null},GHDOC=db.collection('network_meta').doc('github');
function ghToken(){if(GH.tok!==null)return Promise.resolve(GH.tok);
  return GHDOC.get().then(function(s){if(!s.exists||!s.data().d){GH.tok='';return '';}
    return decD(s.data()).then(function(o){if(o&&o.__dn)finisciRekey([GHDOC]);GH.tok=(o&&o.t)||'';return GH.tok;}).catch(function(){GH.tok='';return '';});}).catch(function(){GH.tok='';return '';});}
function salvaGhToken(t){return enc({t:t}).then(function(d){return GHDOC.set({d:d,aggiornato:new Date().toISOString(),da:S.user.email});}).then(function(){GH.tok=t;});}
function ghApi(path,method,body){return fetch('https://api.github.com/repos/'+GH.repo+path,{method:method||'GET',
    headers:{Authorization:'Bearer '+GH.tok,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'},body:body?JSON.stringify(body):undefined})
  .then(function(r){if(r.status===204)return {};return r.json().catch(function(){return {};}).then(function(j){
    if(!r.ok)throw new Error(r.status===401||r.status===403||r.status===404?'La chiave GitHub non è valida o è scaduta: incollane una nuova (🔄 → Chiave GitHub).':'GitHub: '+(j.message||r.status));return j;});});}
function lanciaScript(account,senzaFreno){
  var t0=Date.now()-15000,giri=0;
  function attesa(ms){return new Promise(function(r){setTimeout(r,ms);});}
  function poll(){giri++;return attesa(giri<3?4000:6000).then(function(){return ghApi('/actions/workflows/'+GH.wf+'/runs?event=workflow_dispatch&per_page=5');})
    .then(function(j){var run=(j.workflow_runs||[]).find(function(x){return new Date(x.created_at).getTime()>=t0;});
      if(!run){if(giri>12)throw new Error('Lo script nel cloud non è partito: riprova tra poco.');return poll();}
      if(run.status!=='completed'){if(giri>60)throw new Error('Lo script nel cloud ci sta mettendo troppo: la mappa si aggiorna al prossimo 🔄.');return poll();}
      if(run.conclusion==='cancelled')throw new Error('Lo script nel cloud è stato sostituito da un altro giro partito subito dopo (dell\'altro telefono o delle 13): aggiorno lo stesso la mappa, riprova 🔄 tra qualche minuto.');
      if(run.conclusion!=='success')return motiviGiro(run).then(function(m){SY.cloud={ok:false,quando:run.updated_at,motivi:m};segnaSync();
        throw new Error('Lo script nel cloud si è fermato'+(m.length?': '+m.map(function(x){return x.titolo;}).join(', '):'')+'. Spiegazione e sblocco: 🔄. Aggiorno lo stesso la mappa.');});
      SY.cloud={ok:true,quando:run.updated_at};segnaSync();
      return run;});}
  var inputs={account:account};if(senzaFreno)inputs.senza_freno='true';
  return ghApi('/actions/workflows/'+GH.wf+'/dispatches','POST',{ref:'main',inputs:inputs}).then(poll);
}
// 🔄 dal pannello: accesso Google (finestra dal tocco), script nel cloud per la MIA rubrica, poi mappa dalla rubrica
function sistemaEAggiorna(){
  if(SY.running)return;
  var mia=(SY.rubrica||(function(){try{return localStorage.getItem('fn_rubrica')||'';}catch(e){return '';}})()).toLowerCase();
  var account=mia==='jacopo'||mia==='marco'?mia:'entrambi';
  googleToken().then(ghToken).then(function(t){
    if(!t){toast('Script nel cloud non collegato: aggiorno solo la mappa (🔄 → Chiave GitHub per collegarlo).',true);return;}
    SY.running=true;SY.fase='script';segnaSync();
    toast('Sistemo la rubrica'+(account==='entrambi'?'':' di '+account.charAt(0).toUpperCase()+account.slice(1))+' nel cloud… (circa 1 minuto)');
    return lanciaScript(account).catch(function(e){toast(e.message,true);}).then(function(){SY.running=false;SY.fase='';});
  }).then(function(){aggiornaDaRubrica(true);}).catch(function(e){SY.running=false;SY.fase='';segnaSync();toast(e.message,true);});
}
function openGhKey(){
  var inp=el('input',{cls:'fi',type:'password',placeholder:'github_pat_…',autocomplete:'off'}),err=el('div',{cls:'ferr'});
  var b=el('button',{cls:'sbtn',style:'background:var(--orange);color:#fff;width:100%;margin-top:12px',text:'Salva la chiave (cifrata)',onclick:function(){
    var t=inp.value.trim();err.textContent='';if(!/^github_pat_[A-Za-z0-9_]{20,}$/.test(t)){err.textContent=/^ghp_/.test(t)?'Questa è una chiave GitHub "classica" (ghp_), con troppi permessi: crea una chiave "fine-grained" (inizia con github_pat_).':'Non sembra una chiave GitHub (inizia con github_pat_).';return;}
    b.disabled=true;b.textContent='Controllo la chiave…';var vecchia=GH.tok;GH.tok=t;
    ghApi('/actions/workflows/'+GH.wf).then(function(){return salvaGhToken(t);}).then(function(){closeOv();toast('Script nel cloud collegato ✓');})
      .catch(function(e){GH.tok=vecchia;err.textContent=e.message;b.disabled=false;b.textContent='Salva la chiave (cifrata)';});}});
  openOv([el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:'Chiave GitHub'}),el('div',{cls:'msub',text:'Serve al 🔄 per avviare lo script che sistema la rubrica'})]),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},[el('p',{cls:'msub',style:'margin-top:0',text:'Incolla la chiave creata su GitHub (solo permesso "Actions" sul repository framezzino-sync). Viene salvata cifrata con la password della mappa: vale anche sul telefono di Marco.'}),inp,err,b])]);
}
function openSync(){
  var lista=SY.decidere.map(function(x){var m=x.motivo||'',azioni;
    if(/^possibile doppione/.test(m))azioni=[el('button',{cls:'act main',type:'button',text:'🗑️ È un doppione: elimina',onclick:function(){eliminaDoppione(x);}}),
      el('button',{cls:'act',type:'button',text:'✓ Sono diversi',onclick:function(){togliDecidere(x,'Tenuti tutti e due ✓');}})];
    // doppione visto dallo script dei contatti nuovi: il contatto non e' ancora sistemato, quindi "sono diversi" = sistemalo
    // (scegli il locale: diventa un referente in piu' di quella scheda); togliere solo l'avviso lo farebbe tornare al giro dopo
    else if(/^sembra un doppione/.test(m))azioni=[el('button',{cls:'act main',type:'button',text:'🗑️ È un doppione: elimina',onclick:function(){eliminaDoppione(x);}}),
      el('button',{cls:'act',type:'button',text:'📍 Sono diversi: sistemalo',onclick:function(){openRisolvi(x);}})];
    else if(/^zona da decidere/.test(m))azioni=[el('button',{cls:'act main',type:'button',text:'🗺️ Scegli la zona',onclick:function(){openRisolvi(x);}})];
    else if(/^(ricreato in rubrica|modificato da Jacopo e da Marco)/.test(m))azioni=[el('button',{cls:'act main',type:'button',text:'✓ Va bene così',onclick:function(){togliDecidere(x,'Fatto ✓');}})];
    else azioni=[el('button',{cls:'act main',type:'button',text:'📍 Sistema qui',onclick:function(){openRisolvi(x);}})];
    azioni.push(el('a',{cls:'act',href:'https://contacts.google.com/person/'+x.rn.split('/').pop(),target:'_blank',rel:'noopener',text:'✏️ Apri in Google Contatti'}));
    return el('div',{cls:'ref'},[el('div',{cls:'refn',text:x.nome||'(senza nome)'}),el('div',{cls:'refc',text:m+(x.data?' · '+x.data:'')}),el('div',{cls:'acts'},azioni)]);});
  var btn=el('button',{cls:'sbtn',style:'background:var(--orange);color:#fff;width:100%',
    text:SY.running?(SY.fase==='script'?'Sistemo la rubrica nel cloud…':'Aggiornamento in corso…'):'🔄 Sistema la rubrica e aggiorna la mappa',
    onclick:function(){closeOv();sistemaEAggiorna();}});
  var chiave=el('button',{cls:'act',style:'justify-content:flex-start;margin-top:8px;width:100%',text:'🔑 Chiave GitHub per lo script nel cloud…',onclick:function(){closeOv();openGhKey();}});
  ghToken().then(function(t){chiave.textContent=t?'🔑 Script nel cloud collegato ✓ (cambia chiave)':'🔑 Collega lo script nel cloud (chiave GitHub)';});
  openOv([el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:'Rubrica e mappa'}),
      el('div',{cls:'msub',text:SY.quando?('Ultimo aggiornamento: '+SY.quando.toLocaleTimeString('it-IT',{hour:'2-digit',minute:'2-digit'})+(SY.rubrica?' · rubrica di '+SY.rubrica:'')):'Non ancora aggiornata in questa sessione'})]),
      el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},[btn,chiave,boxCloud(),
      el('div',{cls:'sec',style:'margin-top:16px',text:'Da decidere'+(SY.decidere.length?' ('+SY.decidere.length+')':'')}),
      SY.quando?(lista.length?el('div',{},lista):el('div',{cls:'msub',text:'Niente da decidere ✓'})):el('div',{cls:'msub',text:'Aggiorna dalla rubrica per vedere i contatti da decidere.'}),
      lista.length?el('p',{cls:'msub',style:'margin-top:10px',text:'Sono clienti che lo script non ha saputo sistemare da solo (locale non trovato su Google, possibile doppione, zona da scegliere…). Con "📍 Sistema qui" scegli il locale (o "senza locale") e la zona: va in rubrica e sulla mappa. Possibile doppione: "elimina" se è lo stesso cliente, "sono diversi" se sono due clienti diversi. Oppure correggi il contatto in Google Contatti: al prossimo giro lo script lo riprova. Questi avvisi li vedete tutti e due.'}):null,
      SY.senza?el('button',{cls:'act',type:'button',style:'justify-content:flex-start;margin-top:12px;width:100%',text:'📦 '+SY.senza+(SY.senza===1?' cliente':' clienti')+' senza locale sulla mappa ›',onclick:function(){closeOv();openSenzaLocale();}}):null,
      (SY.exLista||[]).length?el('button',{cls:'act',type:'button',style:'justify-content:flex-start;margin-top:8px;width:100%',text:'🗂️ Ex clienti ('+SY.exLista.length+') ›',onclick:function(){closeOv();openExClienti();}}):null])]);
}
// ── MODIFICHE DALL'APP (21/11): scheda del locale e "Da decidere" → rubrica Google di chi usa l'app + mappa ──────
// Si scrive solo nei contatti della PROPRIA rubrica (Google non permette altro). Locale e zona valgono per tutta la
// scheda: i contatti dell'altra rubrica si allineano da soli al suo 🔄 (vedi aggiornaDaRubrica, campo "agg").
var PF='names,phoneNumbers,biographies,organizations,memberships,clientData,addresses,urls,metadata';
// ora dell'ultima modifica di un contatto secondo Google (per scegliere la versione piu' recente, 27/11)
function aggiornatoIl(p){return ((p&&p.metadata&&p.metadata.sources)||[]).reduce(function(m,s){return s.updateTime&&s.updateTime>m?s.updateTime:m;},'');}
function oraIso(){return new Date().toISOString();}
function contattoAggiorna(p,body,campi){body.etag=p.etag;
  return papi(p.resourceName+':updateContact?updatePersonFields='+campi+'&personFields='+PF,'PATCH',body);}
function gruppiLista(){return papi('contactGroups?pageSize=1000&groupFields=name,groupType').then(function(r){return (r.contactGroups||[]).filter(function(g){return g.groupType==='USER_CONTACT_GROUP';});});}
// campi nascosti: tiene quelli di altri, rimette "framezzino" (dati mappa) e, se serve, "framezzino_decidere"
function conDati(p,dm,dec){var cd=(p.clientData||[]).filter(function(c){return c.key!=='framezzino'&&c.key!=='framezzino_decidere';}).map(function(c){return {key:c.key,value:c.value};});
  if(dm)cd.push({key:'framezzino',value:JSON.stringify(dm)});
  if(dec)cd.push({key:'framezzino_decidere',value:JSON.stringify({motivo:dec.motivo,data:dec.data||oraIso().slice(0,10)})});return cd;}
// "Da decidere" dopo un cambio di zona: zona provvisoria "Veneto" -> resta/diventa da decidere; altrimenti si toglie
// il motivo "zona da decidere" (gli altri motivi restano)
function decidereDopo(p,zona){var d=cdato(p,'framezzino_decidere');if(zona===ZONA_PROVV)return d&&/^zona da decidere/.test(d.motivo||'')?d:{motivo:MOTIVO_ZONA};
  return d&&!/^zona da decidere/.test(d.motivo||'')?d:null;}
// gruppi: "Clienti Framezzino" + "Clienti Framezzino <zona>" (creato se manca); tolto dagli altri gruppi di zona
function gruppiZona(p,zona,gs){
  var perNome={},perId={};gs.forEach(function(g){perNome[g.name]=g.resourceName;perId[g.resourceName]=g.name;});
  var ha=(p.memberships||[]).map(function(m){return m.contactGroupMembership&&m.contactGroupMembership.contactGroupResourceName;}).filter(Boolean);
  var voglio=['Clienti Framezzino'].concat(zona?['Clienti Framezzino '+zona]:[]);
  var via=ha.filter(function(id){var n=perId[id]||'';return (n.indexOf('Clienti Framezzino ')===0&&voglio.indexOf(n)<0)||n==='Personali';});  // un cliente esce da Personali
  return voglio.reduce(function(pr,n){return pr.then(function(){
    if(perNome[n]&&ha.indexOf(perNome[n])>=0)return;
    return (perNome[n]?Promise.resolve(perNome[n]):papi('contactGroups','POST',{contactGroup:{name:n}}).then(function(g){gs.push({name:n,resourceName:g.resourceName,groupType:'USER_CONTACT_GROUP'});perNome[n]=g.resourceName;return g.resourceName;}))
      .then(function(id){return papi(id+'/members:modify','POST',{resourceNamesToAdd:[p.resourceName]});});});},Promise.resolve())
    .then(function(){return Promise.all(via.map(function(id){return papi(id+'/members:modify','POST',{resourceNamesToRemove:[p.resourceName]});}));});}
function notaDi(p){return (p.biographies||[]).map(function(b){return b.value||'';}).join('\n');}
// valori di TUTTE le righe "Prodotti:" (o Sigilli/Pagamento) della nota, non solo della prima
function tutteRighe(note,k){var out=[];(note||'').split('\n').forEach(function(r){if(r.indexOf(k+':')!==0)return;r.slice(k.length+1).split(',').forEach(function(x){x=x.trim();if(x)out.push(x);});});return out;}
// note a righe fisse (come lo script): Prodotti / Sigilli / Pagamento / righe libere di prima / Altro
function notaNuova(vecchia,v){var libere=[],inAltro=false;
  (vecchia||'').split('\n').forEach(function(r){if(/^Altro:/.test(r)){inAltro=true;return;}if(inAltro||/^(Prodotti|Sigilli|Pagamento):/.test(r))return;if(r.trim())libere.push(r.trim());});
  var out=[];if(v.prodotti.length)out.push('Prodotti: '+v.prodotti.join(', '));if(v.sigilli.length)out.push('Sigilli: '+v.sigilli.join(', '));
  if(v.pagamento.length)out.push('Pagamento: '+v.pagamento.join(', '));out=out.concat(libere);
  if(v.altro)out.push('Altro: '+v.altro.replace(/\s*\n\s*/g,' / '));return out.join('\n');}
function comuneDi(pl){return comp(pl,'locality').longText||comp(pl,'administrative_area_level_3').longText||comp(pl,'postal_town').longText;}
function dmDaPlace(pl,locale,zona){return {placeId:pl.id,locale:locale||pl.displayName||'',nomeGoogle:pl.displayName||'',comune:comuneDi(pl),
  provincia:comp(pl,'administrative_area_level_2').shortText,indirizzo:pl.formattedAddress||'',lat:pl.location.lat(),lng:pl.location.lng(),
  maps:(pl.googleMapsURI||'').replace(/&.*$/,''),telefonoLocale:pl.nationalPhoneNumber||'',zona:zona};}
// indirizzo di lavoro e link Maps del contatto col locale nuovo (gli altri indirizzi e link restano)
var RX_MAPS=/maps\.google|google\.[a-z.]+\/maps|goo\.gl\/maps|maps\.app\.goo\.gl/i;
function indirizzoLink(p,pl){
  var nuovo={streetAddress:(comp(pl,'route').longText+(comp(pl,'street_number').longText?', '+comp(pl,'street_number').longText:'')).trim(),city:comuneDi(pl),
    region:comp(pl,'administrative_area_level_2').shortText,postalCode:comp(pl,'postal_code').longText,country:comp(pl,'country').longText||'Italia',type:'work'};
  var ad=(p.addresses||[]).map(function(a){var o={};['streetAddress','extendedAddress','poBox','city','region','postalCode','country','type'].forEach(function(k){if(a[k])o[k]=a[k];});return o;});
  var i=ad.findIndex(function(a){return a.type==='work';});if(i<0)i=ad.length?0:-1;if(i>=0)ad[i]=nuovo;else ad.push(nuovo);
  var ur=(p.urls||[]).filter(function(u){return !RX_MAPS.test(u.value||'');}).map(function(u){var o={value:u.value};if(u.type)o.type=u.type;return o;});
  if(pl.googleMapsURI)ur.push({value:pl.googleMapsURI.replace(/&.*$/,''),type:'work'});
  return {addresses:ad,urls:ur};}
function salvaScheda(id,c){var n={};Object.keys(c).forEach(function(k){if(k!=='_id'&&k!=='_doc')n[k]=c[k];});
  return enc(n).then(function(d){return CCOL.doc(id).set({d:d,v:1,aggiornato:oraIso(),da:S.user.email});});}
function testata(t,sub){return el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:t}),sub?el('div',{cls:'msub',text:sub}):null]),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]);}
function attesaOv(t){openOv([testata(t,'Leggo la tua rubrica Google…'),el('div',{cls:'mbody'},[el('div',{cls:'msub',text:'Un attimo…'})])]);}
// ricerca di un locale su Google Maps (come in "+ Nuovo"): onPick(place) con i dettagli
function cercaLocale(testo,onPick){
  var st={token:null,timer:null},q=el('input',{cls:'fi sm',placeholder:'Nome del locale e comune',autocomplete:'off'}),sugg=el('div',{});
  q.value=testo||'';
  function cerca(t){google.maps.importLibrary('places').then(function(P){if(!st.token)st.token=new P.AutocompleteSessionToken();
      return P.AutocompleteSuggestion.fetchAutocompleteSuggestions({input:t,sessionToken:st.token,language:'it',region:'it',locationBias:{center:{lat:45.55,lng:11.55},radius:50000}});})
    .then(function(r){sugg.innerHTML='';var list=(r.suggestions||[]).filter(function(s){return s.placePrediction;}).slice(0,6);
      if(!list.length){sugg.appendChild(el('div',{cls:'msub',style:'margin-top:6px',text:'Nessun locale trovato su Google Maps.'}));return;}
      sugg.appendChild(el('div',{cls:'sugg'},list.map(function(s){var p=s.placePrediction;
        return el('button',{type:'button',onclick:function(){var pl=p.toPlace();st.token=null;
          pl.fetchFields({fields:['id','displayName','formattedAddress','location','addressComponents','nationalPhoneNumber','googleMapsURI','businessStatus']})
            .then(function(){sugg.innerHTML='';onPick(pl);}).catch(function(e){sugg.innerHTML='';sugg.appendChild(el('div',{cls:'ferr',text:'Dettagli del locale non disponibili: '+e.message}));});}},
          [(p.mainText||p.text).text,el('small',{text:p.secondaryText?p.secondaryText.text:''})]);})));})
    .catch(function(e){sugg.innerHTML='';sugg.appendChild(el('div',{cls:'ferr',text:'Ricerca non riuscita: '+e.message}));});}
  q.addEventListener('input',function(){clearTimeout(st.timer);var t=q.value.trim();if(t.length<3){sugg.innerHTML='';return;}st.timer=setTimeout(function(){cerca(t);},300);});
  return el('div',{},[q,sugg]);}
function scatolaLocale(pl,nota){return el('div',{cls:'placebox'},[el('b',{text:pl.displayName}),el('div',{text:pl.formattedAddress}),
  pl.businessStatus&&pl.businessStatus!=='OPERATIONAL'?el('div',{style:'color:var(--red);font-weight:700',text:'⚠ Google lo indica come chiuso'}):null,
  nota?el('div',{style:'margin-top:4px;font-weight:700',text:nota}):null]);}

// Modifica con piu' referenti dello stesso locale: ognuno tiene i suoi prodotti/sigilli/note, si applicano solo
// le differenze scelte nel modulo (aggiunto / tolto / omaggio cambiato / pezzi di "Altro" aggiunti o tolti)
function pezziAltro(s){return (s||'').split(/\s+\/\s+|\n/).map(function(x){return x.trim();}).filter(Boolean);}
function modificheScelte(v,v0,altroPrima,altroOra){
  function d(a,b){return {piu:Object.keys(a).filter(function(x){return a[x]&&!b[x];}),meno:Object.keys(b).filter(function(x){return b[x]&&!a[x];})};}
  var pp=pezziAltro(altroPrima),po=pezziAltro(altroOra),r={prod:d(v.prod,v0.prod),sig:d(v.sig,v0.sig),pag:d(v.pag,v0.pag),
    omaggio:v.omaggio!==v0.omaggio?v.omaggio:null,omaggioOra:v.omaggio,altroCambiato:altroPrima!==altroOra,altroOra:altroOra,
    altroPiu:po.filter(function(x){return pp.indexOf(x)<0;}),altroMeno:pp.filter(function(x){return po.indexOf(x)<0;})};
  r.nota=r.altroCambiato||r.omaggio!==null||['prod','sig','pag'].some(function(k){return r[k].piu.length||r[k].meno.length;});
  return r;}
function valPer(p,dif){var n=notaDi(p);
  function applica(lista,dd){var out=lista.filter(function(x,i){return dd.meno.indexOf(x)<0&&lista.indexOf(x)===i;});
    dd.piu.forEach(function(x){if(out.indexOf(x)<0)out.push(x);});return out;}
  var om=/\s*\(omaggio\)$/i,sig=[],basi=[];
  tutteRighe(n,'Sigilli').forEach(function(x){x=canon(x,SIGILLI);var o=om.test(x),b=x.replace(om,'');
    if(dif.sig.meno.indexOf(b)>=0||basi.indexOf(b)>=0)return;if(dif.omaggio!==null)o=dif.omaggio;basi.push(b);sig.push(b+(o?' (omaggio)':''));});
  dif.sig.piu.forEach(function(b){if(basi.indexOf(b)<0){basi.push(b);sig.push(b+(dif.omaggioOra?' (omaggio)':''));}});
  var altro=altroNota(n)[0]||'';
  if(dif.altroCambiato){if(dif.unico)altro=dif.altroOra;else{var pz=pezziAltro(altro).filter(function(x){return dif.altroMeno.indexOf(x)<0;});
    dif.altroPiu.forEach(function(x){if(pz.indexOf(x)<0)pz.push(x);});altro=pz.join(' / ');}}
  return {prodotti:applica(tutteRighe(n,'Prodotti').map(function(x){return canon(x,PRODOTTI);}),dif.prod),
    pagamento:applica(tutteRighe(n,'Pagamento').map(function(x){return canon(x,PAGAMENTI);}),dif.pag),sigilli:sig,altro:altro};}
// dati fiscali confrontati "puliti" (spazi, P.I./P.IVA, SDI minuscolo): niente scritture se non sono cambiati davvero
function orgNorm(o){return {az:(o.az||'').trim().replace(/\s+/g,' '),
  piva:(o.piva||'').replace(/^\s*(P\.?\s*IVA|P\.?\s*I\.?|Partita\s*IVA)\s*:?\s*/i,'').replace(/\s/g,''),
  sdi:(o.sdi||'').replace(/^\s*SDI\s*:?\s*/i,'').trim().toUpperCase()};}
// la ditta nuova va solo nei referenti che avevano la stessa ditta (o nessuna), non in quelli con una ditta diversa
function orgCompatibile(p,prima){var o=(p.organizations||[])[0]||{},m=orgNorm({az:o.name,piva:/\d{6,}/.test(o.title||'')?o.title:'',sdi:o.department});
  return ['az','piva','sdi'].every(function(k){return !m[k]||!prima[k]||m[k].toLowerCase()===prima[k].toLowerCase();});}
// ✏️ Modifica della scheda: prodotti, sigilli, pagamento, note, dati fiscali (dei MIEI referenti), nome, locale, zona
function openModifica(c){
  attesaOv('Modifica · '+c.locale);
  googleToken().then(function(){
    var tutti=[];(c.referenti||[]).forEach(function(r){rnsRef(r).forEach(function(k){if(tutti.indexOf(k)<0)tutti.push(k);});});
    return Promise.all([Promise.all(tutti.map(function(k){return papi(k+'?personFields='+PF).catch(function(){return null;});})),gruppiLista()]);
  }).then(function(z){var visti={};formModifica(c,z[0].filter(function(p){if(!p||visti[p.resourceName])return false;visti[p.resourceName]=1;return true;}),z[1]);})
    .catch(function(e){closeOv();toast(e.message,true);});
}
function formModifica(c,miei,gs){
  var mieiRn={};miei.forEach(function(p){mieiRn[p.resourceName]=p;});
  var altri=(c.referenti||[]).filter(function(r){return !rnsRef(r).some(function(k){return mieiRn[k];});});
  var v={prod:{},sig:{},pag:{},omaggio:false},altro=[],org={az:'',piva:'',sdi:''};
  miei.forEach(function(p){var n=notaDi(p);
    tutteRighe(n,'Prodotti').forEach(function(x){v.prod[canon(x,PRODOTTI)]=1;});
    tutteRighe(n,'Sigilli').forEach(function(x){x=canon(x,SIGILLI);if(/\s*\(omaggio\)$/i.test(x)){v.omaggio=true;x=x.replace(/\s*\(omaggio\)$/i,'');}v.sig[x]=1;});
    tutteRighe(n,'Pagamento').forEach(function(x){v.pag[canon(x,PAGAMENTI)]=1;});
    altroNota(n).forEach(function(x){if(altro.indexOf(x)<0)altro.push(x);});
    var o=(p.organizations||[])[0]||{};if(!org.az&&o.name)org.az=o.name;
    var pv=(o.title||'').replace(/^P\.?\s*IVA\s*/i,'');if(!org.piva&&/\d{6,}/.test(pv))org.piva=pv;
    var sd=(o.department||'').replace(/^SDI\s*/i,'');if(!org.sdi&&sd)org.sdi=sd;});
  // com'era all'apertura: al salvataggio si scrive in ogni referente SOLO quello che e' stato cambiato
  var v0={prod:Object.assign({},v.prod),sig:Object.assign({},v.sig),pag:Object.assign({},v.pag),omaggio:v.omaggio},altro0=altro.join(' / ');
  function righe(lista,obj){var tutte=lista.concat(Object.keys(obj).filter(function(x){return lista.indexOf(x)<0;}));
    return el('div',{cls:'chips'},tutte.map(function(x){var b=el('button',{cls:'chip'+(obj[x]?' on':''),type:'button',text:x,onclick:function(){obj[x]=!obj[x];b.classList.toggle('on',!!obj[x]);}});return b;}));}
  function campo(ph,val){var i=el('input',{cls:'fi sm',placeholder:ph,autocomplete:'off'});i.value=val||'';return i;}
  var st={place:null};
  var fLocale=campo('Nome del locale',c.locale),zsel=zonaSelect('md-zona',c.zona),box=el('div',{}),err=el('div',{cls:'ferr'});
  var omg=el('button',{cls:'chip'+(v.omaggio?' on':''),type:'button',text:'🎁 Omaggio',onclick:function(){v.omaggio=!v.omaggio;omg.classList.toggle('on',v.omaggio);}});
  var fAltro=el('textarea',{cls:'fi sm',rows:'2',placeholder:'note libere'});fAltro.value=altro.join(' / ');
  var fAz=campo('Ragione sociale',org.az),fPiva=campo('P.IVA',org.piva),fSdi=campo('SDI',org.sdi);
  var cerca=cercaLocale('',function(pl){st.place=pl;zonaImposta(zsel,zonaPer(pl));
    var gia=S.clients.find(function(x){return x._id!==c._id&&(x.placeId||x.id)===pl.id;});
    box.innerHTML='';box.appendChild(scatolaLocale(pl,gia?'Già sulla mappa come "'+gia.locale+'": i referenti verranno uniti in quella scheda.':''));});
  var save=el('button',{cls:'sbtn',style:'background:var(--orange);color:#fff;width:100%;margin-top:16px',text:'Salva in rubrica e sulla mappa'});
  var info=[];
  if(!miei.length)info.push('Nessun referente di questo locale è nella tua rubrica Google: puoi cambiare nome, locale e zona; prodotti e note li cambia chi ha il contatto.');
  else if(altri.length)info.push('Referenti nell\'altra rubrica: '+altri.map(function(r){return nomeRef(r,c)||r.contatto;}).join(', ')+'. I loro prodotti e note li cambia chi ha quella rubrica; nome, locale e zona si allineano da soli al suo 🔄.');
  openOv([testata('Modifica · '+c.locale,miei.length?'Nella tua rubrica: '+miei.map(function(p){return ((p.names||[])[0]||{}).displayName||'';}).join(', '):'Solo mappa'),
    el('div',{cls:'mbody'},[
      info.length?el('p',{cls:'msub',style:'margin-top:0',text:info.join(' ')}):null,
      miei.length?el('div',{},[
        el('div',{cls:'flbl',style:'margin-top:0',text:'Prodotti'}),righe(PRODOTTI,v.prod),
        el('div',{cls:'flbl',text:'Sigilli (niente = neutri)'}),righe(SIGILLI,v.sig),el('div',{cls:'chips',style:'margin-top:6px'},[omg]),
        el('div',{cls:'flbl',text:'Pagamento'}),righe(PAGAMENTI,v.pag),
        el('div',{cls:'flbl',text:'Altro (note libere)'}),fAltro,
        el('div',{cls:'flbl',text:'Ragione sociale · P.IVA · SDI'}),fAz,el('div',{style:'display:flex;gap:8px;margin-top:6px'},[fPiva,fSdi])]):null,
      el('div',{cls:'flbl',text:'Nome del locale (titolo della scheda)'}),fLocale,
      el('div',{cls:'flbl',text:'Locale su Google Maps — ora: '+(c.nomeGoogle||c.locale)+', '+(c.indirizzo||'')}),
      el('div',{cls:'msub',style:'margin:0 0 6px',text:'Solo se l\'indirizzo è sbagliato: cerca il locale giusto.'}),cerca,box,
      el('div',{cls:'flbl',text:'Zona'}),zsel,
      err,save,miei.length?el('button',{cls:'act',type:'button',style:'width:100%;justify-content:center;margin-top:14px;color:var(--red)',text:'🚫 Non è più cliente',onclick:function(e){exCliente(c,miei,gs,e.currentTarget);}}):null,
      miei.length?el('button',{cls:'act',type:'button',style:'width:100%;justify-content:center;margin-top:8px;color:var(--red)',text:'🗑️ Elimina definitivamente',onclick:function(e){eliminaDefinitivo(c,miei,e.currentTarget);}}):null])]);
  save.addEventListener('click',function(){
    err.textContent='';var ora=oraIso(),pid=c.placeId||c.id,locale=fLocale.value.trim()||c.locale,zona=zsel.value,pl=st.place;
    var cambiaLoc=!!pl&&pl.id!==pid,cambiaZona=zona!==c.zona,cambiaNome=locale!==c.locale;
    if(v.omaggio&&!Object.keys(v.sig).some(function(x){return v.sig[x];})){err.textContent='Hai scelto Omaggio: scegli anche il tipo di sigillo.';return;}
    var dif=modificheScelte(v,v0,altro0,fAltro.value.trim());dif.unico=miei.length===1;
    var orgNuova=orgNorm({az:fAz.value,piva:fPiva.value,sdi:fSdi.value}),orgPrima=orgNorm(org),cambiaOrg=JSON.stringify(orgNuova)!==JSON.stringify(orgPrima);
    var dmNuovo=cambiaLoc?dmDaPlace(pl,locale,zona):null;
    save.disabled=true;save.textContent='Salvo…';
    miei.reduce(function(pr,p){return pr.then(function(fatti){
      var body={},campi=[];
      var nn=dif.nota?notaNuova(notaDi(p),valPer(p,dif)):notaDi(p);if(nn.trim()!==notaDi(p).trim()){body.biographies=nn?[{value:nn,contentType:'TEXT_PLAIN'}]:[];campi.push('biographies');}
      if(cambiaOrg&&orgCompatibile(p,orgPrima)){var o=(p.organizations||[])[0]||{},resto=(p.organizations||[]).slice(1).map(function(x){var y={};['name','title','department','type'].forEach(function(k){if(x[k])y[k]=x[k];});return y;});
        var tit=orgNuova.piva?'P.IVA '+orgNuova.piva:((o.title||'')&&!/\d{6,}/.test(o.title)?o.title:'');
        var nuovaO={name:orgNuova.az,title:tit,department:orgNuova.sdi?'SDI '+orgNuova.sdi:'',type:o.type||'work'};
        body.organizations=(nuovaO.name||nuovaO.title||nuovaO.department?[nuovaO]:[]).concat(resto);campi.push('organizations');}
      if(cambiaLoc||cambiaZona||cambiaNome){var vecchio=cdato(p,'framezzino')||{};
        var d=Object.assign({placeId:pid},vecchio.senzaMappa?{}:vecchio);LOC.forEach(function(k){if(d[k]==null&&c[k]!=null)d[k]=c[k];});
        if(dmNuovo)Object.assign(d,dmNuovo);d.zona=zona;d.locale=locale;if(cambiaLoc||cambiaZona)d.agg=ora;
        body.clientData=conDati(p,d,cambiaZona?decidereDopo(p,zona):cdato(p,'framezzino_decidere'));campi.push('clientData');}
      if(cambiaLoc){var il=indirizzoLink(p,pl);body.addresses=il.addresses;body.urls=il.urls;campi.push('addresses','urls');}
      var passo=campi.length?contattoAggiorna(p,body,campi.join(',')):Promise.resolve(p);
      return passo.then(function(np){return (cambiaZona?gruppiZona(np,zona,gs):Promise.resolve()).then(function(){fatti[np.resourceName]=np;return fatti;});});
    });},Promise.resolve({})).then(function(fatti){
      var refs=(c.referenti||[]).map(function(r){var np=null;rnsRef(r).some(function(k){np=fatti[k];return !!np;});return np?referenteDa(np,r.rubrica||rubricaMia()||'',r):r;});
      var n=ricomponi(c,refs,null),dest=c._id;n.locale=locale;n.zona=zona;
      if(dmNuovo){LOC.forEach(function(k){if(k!=='zona')n[k]=dmNuovo[k];});n.id=dmNuovo.placeId;n.maps=pl.googleMapsURI||dmNuovo.maps;}
      if(cambiaLoc||cambiaZona)n.agg=ora;
      if(cambiaLoc){var ex=[pid].concat(c.ex||[]);n.ex=ex.filter(function(x,i){return x!==n.placeId&&ex.indexOf(x)===i;});
        var t=S.clients.find(function(x){return x._id!==c._id&&(x.placeId||x.id)===n.placeId;});
        if(t){var m=ricomponi(t,(t.referenti||[]).concat(n.referenti),null),ex2=(t.ex||[]).concat(n.ex);
          m.ex=ex2.filter(function(x,i){return x!==m.placeId&&ex2.indexOf(x)===i;});m.zona=zona;m.agg=ora;n=m;dest=t._id;}
        else dest=docId(n.placeId);}
      return salvaScheda(dest,n).then(function(){if(dest!==c._id)return CCOL.doc(c._id).delete();}).then(function(){return dest;},
        function(e){throw new Error('Salvato in rubrica ma non sulla mappa: '+permMsg(e));});
    }).then(function(dest){closeOv();toast(miei.length?'Salvato in rubrica e sulla mappa ✓':'Salvato sulla mappa ✓');setTimeout(function(){openDetail(dest,true);},900);})
      .catch(function(e){err.textContent=e.message;save.disabled=false;save.textContent='Salva in rubrica e sulla mappa';});
  });
}

// 📍 Sistemare dall'app un contatto "Da decidere": scegliere il locale (o "senza locale"), oppure solo la zona
function openRisolvi(x){
  attesaOv(x.nome||'Da decidere');
  googleToken().then(function(){return Promise.all([papi(x.rn+'?personFields='+PF),gruppiLista()]);})
    .then(function(z){formRisolvi(x,z[0],z[1]);}).catch(function(e){closeOv();toast(e.message,true);});
}
function formRisolvi(x,p,gs){
  var soloZona=/^zona da decidere/.test(x.motivo||''),dm=cdato(p,'framezzino')||{},err=el('div',{cls:'ferr'}),st={place:null};
  var nome=((p.names||[])[0]||{}).displayName||x.nome||'';
  function fine(msg){closeOv();toast(msg);SY.decidere=SY.decidere.filter(function(d){return d.rn!==x.rn;});segnaSync();setTimeout(function(){aggiornaDaRubrica(true);},600);}
  function errore(b,t){return function(e){err.textContent=e.message;b.disabled=false;b.textContent=t;};}
  var link=el('a',{cls:'act',href:'https://contacts.google.com/person/'+x.rn.split('/').pop(),target:'_blank',rel:'noopener',text:'✏️ Apri in Google Contatti'});
  if(soloZona){
    var zs=zonaSelect('rs-zona',dm.zona||ZONA_PROVV);
    var b=el('button',{cls:'sbtn',style:'background:var(--orange);color:#fff;width:100%;margin-top:16px',text:'Salva la zona',onclick:function(){
      var z=zs.value;if(z===ZONA_PROVV&&!window.confirm('Lasciare la zona provvisoria "Veneto"? Il contatto resta in "Da decidere".'))return;
      b.disabled=true;b.textContent='Salvo…';
      contattoAggiorna(p,{clientData:conDati(p,Object.assign({},dm,{zona:z,agg:oraIso()}),decidereDopo(p,z))},'clientData')
        .then(function(np){return gruppiZona(np,z,gs);}).then(function(){fine('Zona salvata in rubrica ✓ · aggiorno la mappa');},errore(b,'Salva la zona'));}});
    openOv([testata(nome,x.motivo),el('div',{cls:'mbody'},[
      el('div',{cls:'addr',text:(dm.nomeGoogle||'')+(dm.indirizzo?' · '+dm.indirizzo:'')}),
      el('div',{cls:'flbl',text:'Zona'}),zs,err,b,el('div',{cls:'acts',style:'margin-top:10px'},[link])])]);
    return;
  }
  var fNome=el('input',{cls:'fi sm',autocomplete:'off'});fNome.value=nome;
  var fLocale=el('input',{cls:'fi sm',placeholder:'es. Bar Roma',autocomplete:'off'}),zsel=zonaSelect('rs-zona',''),box=el('div',{});
  var cerca=cercaLocale(nome.replace(/^\s*(tram|tam)\s+/i,''),function(pl){st.place=pl;fLocale.value=fLocale.value||pl.displayName||'';zonaImposta(zsel,zonaPer(pl));
    var gia=S.clients.filter(function(c){return (c.placeId||c.id)===pl.id;});
    box.innerHTML='';box.appendChild(scatolaLocale(pl,gia.length?'Già sulla mappa come "'+gia[0].locale+'": diventa un referente in più.':''));});
  var b=el('button',{cls:'sbtn',style:'background:var(--orange);color:#fff;width:100%;margin-top:16px',text:'Salva in rubrica e sulla mappa'});
  var bSenza=el('button',{cls:'act',type:'button',style:'width:100%;justify-content:center;margin-top:10px',text:'Cliente senza locale (spedizioni, indirizzo sconosciuto)'});
  b.addEventListener('click',function(){err.textContent='';var pl=st.place,z=zsel.value,nm=fNome.value.trim().replace(/\s+/g,' ');
    if(!pl){err.textContent='Scegli il locale dai suggerimenti di Google Maps (o "Cliente senza locale").';return;}
    var d=dmDaPlace(pl,fLocale.value.trim()||pl.displayName,z);d.agg=oraIso();
    var il=indirizzoLink(p,pl),body={clientData:conDati(p,d,z===ZONA_PROVV?{motivo:MOTIVO_ZONA}:null),addresses:il.addresses,urls:il.urls},campi='clientData,addresses,urls';
    if(nm&&nm!==nome){body.names=[{givenName:nm}];campi+=',names';}  // nome tutto su una riga (regola di Jacopo 12/11)
    b.disabled=true;b.textContent='Salvo…';
    contattoAggiorna(p,body,campi).then(function(np){return gruppiZona(np,z,gs);})
      .then(function(){fine('Salvato in rubrica ✓ · aggiorno la mappa');},errore(b,'Salva in rubrica e sulla mappa'));});
  bSenza.addEventListener('click',function(){if(!window.confirm('Segnare "'+nome+'" come cliente senza locale? Resta nel gruppo Clienti Framezzino ma non va sulla mappa.'))return;
    bSenza.disabled=true;
    contattoAggiorna(p,{clientData:conDati(p,{senzaMappa:true},null)},'clientData').then(function(np){return gruppiZona(np,null,gs);})
      .then(function(){fine('Segnato come cliente senza locale ✓');},errore(bSenza,'Cliente senza locale (spedizioni, indirizzo sconosciuto)'));});
  openOv([testata(nome,x.motivo),el('div',{cls:'mbody'},[
    el('div',{cls:'flbl',style:'margin-top:0',text:'Nome in rubrica (tutto su una riga)'}),fNome,
    el('div',{cls:'flbl',text:'Locale su Google Maps *'}),cerca,box,
    el('div',{cls:'flbl',text:'Nome del locale (come vuoi vederlo sulla mappa)'}),fLocale,
    el('div',{cls:'flbl',text:'Zona'}),zsel,err,b,bSenza,el('div',{cls:'acts',style:'margin-top:10px'},[link])])]);
}
// "Da decidere" risolto senza cambiare il contatto (doppione tenuto, copia ricreata giusta...): si toglie solo il motivo;
// al prossimo giro del cloud si toglie anche dalla copia nell'altra rubrica
function togliDecidere(x,msg){
  closeOv();attesaOv(x.nome||'Da decidere');
  googleToken().then(function(){return papi(x.rn+'?personFields='+PF);})
    .then(function(p){return contattoAggiorna(p,{clientData:conDati(p,cdato(p,'framezzino'),null)},'clientData');})
    .then(function(){closeOv();toast(msg+' · aggiorno la mappa');SY.decidere=SY.decidere.filter(function(d){return d.rn!==x.rn;});segnaSync();setTimeout(function(){aggiornaDaRubrica(true);},600);})
    .catch(function(e){closeOv();toast(e.message,true);});
}
// possibile doppione: il contatto nuovo si elimina (cestino di Google Contatti, 30 giorni); al prossimo giro del cloud
// sparisce anche la sua copia nell'altra rubrica. Il cliente che c'era gia' resta com'e'.
function eliminaDoppione(x){
  if(!window.confirm('Eliminare "'+(x.nome||'questo contatto')+'" dalla tua rubrica?\n\n'+(x.motivo||'')+'\n\nResta il cliente che c\'era già. Se questo contatto ha qualcosa in più (altro numero, note…), aggiungilo prima all\'altro con "Apri in Google Contatti". Va nel cestino di Google Contatti (30 giorni) e sparisce anche dall\'altra rubrica al prossimo giro.'))return;
  closeOv();attesaOv(x.nome||'Elimino…');
  googleToken().then(function(){return papi(x.rn+':deleteContact','DELETE');})
    .then(function(){closeOv();toast('Doppione eliminato ✓ · aggiorno la mappa');SY.decidere=SY.decidere.filter(function(d){return d.rn!==x.rn;});segnaSync();setTimeout(function(){aggiornaDaRubrica(true);},600);})
    .catch(function(e){closeOv();toast(e.message,true);});
}
// ── EX CLIENTI (Jacopo 22/11): "non è più cliente" NON cancella (potrebbe tornare). Ogni mio referente del locale diventa
// "Ex Tram …", esce dai gruppi "Clienti Framezzino…", va nell'etichetta "Ex clienti Framezzino" con "Ex cliente dal …" nelle
// note, ed esce dalla mappa. L'altra rubrica si allinea al giro del cloud. "↩ Torna cliente" (🔄 → Ex clienti) fa il contrario;
// anche togliere "Ex " dal nome sul telefono basta: lo script del cloud lo rimette tra i clienti.
var EX_GRUPPO='Ex clienti Framezzino';
function conAltro(nota,testo){var r=(nota||'').split('\n').filter(function(x){return x.trim();}),i=-1;
  r.forEach(function(x,k){if(i<0&&x.indexOf('Altro:')===0)i=k;});
  if(i<0)r.push('Altro: '+testo);else r[i]=r[i].replace(/\s+$/,'')+' / '+testo;return r.join('\n');}
function gruppoEx(gs){var g=gs.find(function(x){return x.name===EX_GRUPPO;});if(g)return Promise.resolve(g.resourceName);
  return papi('contactGroups','POST',{contactGroup:{name:EX_GRUPPO}}).then(function(n){gs.push({name:EX_GRUPPO,resourceName:n.resourceName,groupType:'USER_CONTACT_GROUP'});return n.resourceName;});}
function exCliente(c,miei,gs,btn){
  if(!window.confirm('«'+c.locale+'» non è più cliente?\n\nNon si cancella niente: resta in rubrica (tua e, al prossimo giro del cloud, dell\'altro) come «Ex Tram …», con l\'etichetta «'+EX_GRUPPO+'» e «Ex cliente dal …» nelle note, ed esce dalla mappa.\n\nSe torna cliente: tasto «🗂️ Ex clienti» sulla mappa → toccalo → «↩ Ripristina come cliente».'))return;
  btn.disabled=true;btn.textContent='Salvo…';
  var oggi=new Date().toLocaleDateString('it-IT'),perId={};gs.forEach(function(g){perId[g.resourceName]=g.name;});
  gruppoEx(gs).then(function(gid){
    return miei.reduce(function(pr,p){return pr.then(function(){
      var nome=(((p.names||[])[0]||{}).displayName||'').trim(),body={},campi=[],n=notaDi(p);
      // "Tram Ex Tram …" (rimasto a meta' il 27/11) torna "Ex Tram …": mai "Ex Tram Ex Tram"
      var exNome=/^(tram|tam)\s+ex\s+/i.test(nome)?nome.replace(/^(tram|tam)\s+/i,''):(/^ex\s/i.test(nome)?nome:('Ex '+nome).trim());
      if(exNome!==nome){body.names=[{givenName:exNome}];campi.push('names');}
      if(n.indexOf('Ex cliente dal')<0){body.biographies=[{value:conAltro(n,'Ex cliente dal '+oggi),contentType:'TEXT_PLAIN'}];campi.push('biographies');}
      return (campi.length?contattoAggiorna(p,body,campi.join(',')):Promise.resolve(p)).then(function(np){
        var ha=(np.memberships||[]).map(function(m){return m.contactGroupMembership&&m.contactGroupMembership.contactGroupResourceName;}).filter(Boolean);
        var via=ha.filter(function(id){var g=perId[id]||'';return g.indexOf('Clienti Framezzino')===0||g==='Personali';});
        return (ha.indexOf(gid)<0?papi(gid+'/members:modify','POST',{resourceNamesToAdd:[np.resourceName]}):Promise.resolve())
          .then(function(){return Promise.all(via.map(function(id){return papi(id+'/members:modify','POST',{resourceNamesToRemove:[np.resourceName]});}));})
          .then(function(){return papi(np.resourceName+'?personFields='+PF).then(ricordaFresco,function(){});});
      });});},Promise.resolve());
  }).then(function(){closeOv();toast('«'+c.locale+'» segnato come ex cliente ✓ · lo tolgo dalla mappa');setTimeout(sistemaEAggiorna,600);},
    function(e){btn.disabled=false;btn.textContent='🚫 Non è più cliente';toast(e.message,true);});
}
function openExClienti(){
  var l=(SY.exLista||[]).slice().sort(function(a,b){return (a.nome||'').localeCompare(b.nome||'');});
  openOv([el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:'Ex clienti'}),el('div',{cls:'msub',text:l.length+' nella tua rubrica · etichetta «'+EX_GRUPPO+'»'})]),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},l.length?l.map(function(x){var b=el('button',{cls:'act main',type:'button',text:'↩ Torna cliente',onclick:function(){tornaCliente(x,b);}});
      return el('div',{cls:'ref'},[el('div',{cls:'refn',text:x.nome||'(senza nome)'}),el('div',{cls:'acts'},[b,
        el('a',{cls:'act',href:'https://contacts.google.com/person/'+x.rn.split('/').pop(),target:'_blank',rel:'noopener',text:'✏️ Apri in Google Contatti'})])]);})
      :[el('div',{cls:'msub',text:'Nessuno'})])]);
}
function tornaCliente(x,btn){
  if(!window.confirm('«'+(x.nome||'')+'» torna cliente?\n\nTolgo «Ex » dal nome, lo rimetto nei gruppi dei clienti e torna sulla mappa (anche per l\'altro, al prossimo giro del cloud).'))return;
  btn.disabled=true;btn.textContent='Salvo…';
  googleToken().then(function(){return Promise.all([papi(x.rn+'?personFields='+PF),gruppiLista()]);}).then(function(z){
    return rimettiCliente(z[0],z[1]);  // stessa cosa di "Ripristina come cliente" dalla mappa
  }).then(function(){closeOv();toast('«'+(x.nome||'').replace(/^ex\s+/i,'')+'» è di nuovo cliente ✓ · lo rimetto sulla mappa');
    SY.exLista=(SY.exLista||[]).filter(function(y){return y.rn!==x.rn;});setTimeout(sistemaEAggiorna,600);},
    function(e){btn.disabled=false;btn.textContent='↩ Torna cliente';toast(e.message,true);});
}
// 📦 clienti della rubrica senza locale sulla mappa (spedizioni, indirizzo sconosciuto): telefono, WhatsApp, "Metti sulla mappa"
function openSenzaLocale(){
  var l=(SY.senzaLista||[]).slice().sort(function(a,b){return (a.nome||'').localeCompare(b.nome||'');});
  var righe=l.map(function(x){var acts=[];
    (x.tel||[]).forEach(function(t){acts.push(el('a',{cls:'act',href:'tel:'+t.replace(/\s/g,''),text:'📞 '+t}));var w=waLink(t);if(w)acts.push(el('a',{cls:'act',href:w,target:'_blank',rel:'noopener',text:'💬 WhatsApp'}));});
    acts.push(el('button',{cls:'act',type:'button',text:'📍 Metti sulla mappa',onclick:function(){openRisolvi({nome:x.nome,rn:x.rn,motivo:''});}}));
    return el('div',{cls:'ref'},[el('div',{cls:'refn',text:x.nome||'(senza nome)'}),el('div',{cls:'acts'},acts)]);});
  openOv([el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:'Clienti senza locale'}),el('div',{cls:'msub',text:l.length+' nella tua rubrica · spedizioni o indirizzo sconosciuto'})]),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},l.length?righe:[el('div',{cls:'msub',text:'Nessuno ✓'})])]);
}
// "aggiornata oggi alle 18:05 · Marco" sotto il numero dei locali
function testoAggiornata(){var u=S.ultimo;if(!u||!u.quando)return '';var d=new Date(u.quando);if(isNaN(d))return '';
  var ieri=new Date(Date.now()-864e5),hm=d.toLocaleTimeString('it-IT',{hour:'2-digit',minute:'2-digit'});
  var g=d.toDateString()===new Date().toDateString()?'oggi':d.toDateString()===ieri.toDateString()?'ieri':d.toLocaleDateString('it-IT',{day:'numeric',month:'short'});
  return 'aggiornata '+g+' alle '+hm+(u.chi?' · '+u.chi:'');}
function mostraAggiornata(){var s=document.getElementById('scount');if(!s)return;var x=s.querySelector('.sagg');if(x)x.remove();
  var t=testoAggiornata();if(t)s.appendChild(el('span',{cls:'sagg',text:t}));}
// ── ❓ COME SI USA: la scheda rapida della guida (niente dati di clienti: questo file e' pubblico) ──
var GUIDA=[
  ['Salvare un cliente nuovo',[
    'Dall\'app (consigliato): ＋ Nuovo → scegli il locale tra i suggerimenti di Google Maps, scrivi telefono e prodotti → Salva. Va in rubrica e sulla mappa, e passa anche all\'altro. Se il numero è già in rubrica l\'app te lo dice.',
    'Senza locale (spedizioni, ufficio, indirizzo sconosciuto): in ＋ Nuovo tocca «📦 Non ha un locale». Resta cliente, senza pallino sulla mappa.',
    'Dal telefono: «Salva in» = il tuo account Google (mai «Telefono»). Nome tutto su una riga: Tram + comune + nome del locale + referente, es. «Tram Schio Bar Roma Luca». Cognome vuoto. Indirizzo e gruppi non servono: li mette lo script. Poi 🔄 → «Sistema la rubrica e aggiorna la mappa».',
    'Senza «Tram» davanti il contatto resta personale: niente mappa, non passa all\'altro, nessun avviso.']],
  ['Le note: una riga per tipo',[
    'Prodotti: S, M, L, Magnum, XXL, Rettangolari, Panini, Toast, Tostoni, Maxi tostoni, Galaxy, Club, Veline, Sacchetti',
    'Sigilli: Personalizzati, Colorati, Smile, Produzione propria. «(omaggio)» solo se sono regalati. Neutri = niente riga.',
    'Pagamento: Bonifico, Contrassegno, PayPal, Spedizione',
    'Altro: tutto il resto (prezzi, orari, «ex …», altre persone). Esempio: «Prodotti: L, Maxi tostoni» poi a capo «Sigilli: Personalizzati (omaggio)».',
    'Mai i prodotti nel nome. «Tostoni» e «Maxi tostoni» sono due prodotti diversi.']],
  ['Il 🔄 e i «Da decidere»',[
    'Il 🔄 legge la tua rubrica e aggiorna la mappa. Il numero rosso sul 🔄 = contatti da decidere; il pallino arancione = mappa non ancora aggiornata da quando hai aperto l\'app.',
    '«Sistema la rubrica e aggiorna la mappa» avvia lo script nel cloud (circa un minuto). Lo script gira anche da solo alle 6:37 e alle 13:23.',
    'Da decidere: 📍 Sistema qui (scegli il locale, o «Cliente senza locale»), 🗺️ Scegli la zona, possibile doppione → «È un doppione: elimina» oppure «Sono diversi», ✓ Va bene così. Li vedete tutti e due: basta che lo sistemi uno.',
    'Sotto il numero dei locali c\'è quando è stata aggiornata la mappa l\'ultima volta e da chi.']],
  ['Modificare, ex clienti, cancellare',[
    'Scheda del locale → ✏️ Modifica: prodotti, sigilli, pagamento, note, ditta, nome, locale e zona. Va in rubrica e sulla mappa; all\'altro arriva al giro del cloud (o subito con «Sistema la rubrica»).',
    'Non è più cliente: Modifica → 🚫 Non è più cliente. Non si cancella: resta in rubrica come «Ex Tram …» (etichetta «Ex clienti Framezzino») ed esce dalla mappa. Passa anche all\'altro.',
    'Vedere gli ex clienti: tasto «🗂️ Ex clienti» sulla mappa → nascosti, insieme ai clienti (pallini grigi «ex») o solo loro. Tocca un ex cliente → «↩ Ripristina come cliente» (torna nei clienti e nella sua zona, anche per l\'altro). Anche da 🔄 → Ex clienti.',
    'Eliminare davvero: Modifica (o la scheda dell\'ex cliente) → 🗑️ Elimina definitivamente, con due conferme. Sparisce anche all\'altro e dalla mappa; resta 30 giorni nel cestino di Google Contatti.',
    'Clienti senza locale: 🔄 → «📦 … senza locale»: telefono, WhatsApp e «📍 Metti sulla mappa».']],
  ['Attenzione',[
    'Mai importare file .vcf sul telefono: sostituisce la rubrica.',
    'Dopo un aggiornamento dell\'app la novità arriva entro una decina di minuti: chiudi l\'app dalle app recenti e riaprila.',
    'Su un telefono nuovo serve la password della mappa (quella di cifratura).']]
];
function openGuida(){
  var corpo=[];GUIDA.forEach(function(s){corpo.push(el('div',{cls:'sec',style:'margin-top:14px',text:s[0]}));
    s[1].forEach(function(r){corpo.push(el('p',{cls:'msub',style:'margin:6px 0;font-size:13px;line-height:1.45;color:var(--text)',text:'• '+r}));});});
  openOv([el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:'Come si usa'}),el('div',{cls:'msub',text:'La scheda rapida della guida'})]),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},corpo)]);
}
// ── AVVISI DEL CLOUD (22/11): l'ultimo giro dello script (6:37, 13:23 o dal 🔄) è andato bene? Se no, perché.
// Il giro nel cloud chiude con passi dal nome chiaro ("FRENO: rubrica di Marco", "ERRORE: allineamento"...): la chiave
// GitHub (solo Actions) basta per leggerli. Il freno si sblocca da qui dopo la conferma (input "senza_freno").
var SPIEGA={
  'FRENO rubrica':'Il freno di sicurezza si è attivato: in un giro solo c\'erano più di 30 contatti nuovi o più di 50 modificati in questa rubrica, e lo script non ha toccato niente. Succede se si salvano o si importano tanti contatti insieme, oppure se un telefono ha riscritto la rubrica.',
  'FRENO allineamento':'Il freno di sicurezza dell\'allineamento si è attivato: tra le due rubriche c\'erano più di 10 clienti da cancellare, 60 nuovi o 40 modifiche da copiare in un giro solo, e non è stato toccato niente. Se qualcuno ha cancellato tanti clienti per sbaglio, sbloccando le cancellazioni arrivano anche all\'altro (restano 30 giorni nel cestino di Google Contatti).',
  'ERRORE rubrica':'Lo script si è fermato con un errore. Spesso è l\'accesso Google della rubrica scaduto (va rifatto dal PC con Claude) oppure Google che non rispondeva: riprova con «Sistema la rubrica»; se si ripete, avvisa Claude.',
  'ERRORE allineamento':'Alcuni clienti non sono stati copiati nell\'altra rubrica (errore di rete o contatto cambiato proprio in quel momento): si riprova da solo al giro dopo. Se si ripete, avvisa Claude.'};
function motiviGiro(run){return ghApi('/actions/runs/'+run.id+'/jobs').then(function(j){var out=[];
  ((j.jobs||[])[0]||{steps:[]}).steps.forEach(function(s){var m=/^(FRENO|ERRORE): (.+)$/.exec(s.name||'');if(!m||s.conclusion!=='failure')return;
    var acc=/Jacopo/.test(m[2])?'jacopo':/Marco/.test(m[2])?'marco':'';
    out.push({tipo:m[1],titolo:m[1]==='FRENO'?'freno di sicurezza ('+m[2]+')':'errore ('+m[2]+')',account:acc,spiega:SPIEGA[m[1]+' '+(acc?'rubrica':'allineamento')]});});
  return out;}).catch(function(){return [];});}
function statoCloud(){return ghToken().then(function(tok){if(!tok)return null;
  return ghApi('/actions/workflows/'+GH.wf+'/runs?per_page=6').then(function(j){
    var run=(j.workflow_runs||[]).find(function(x){return x.status==='completed'&&x.conclusion!=='cancelled'&&x.conclusion!=='skipped';});
    if(!run)return null;if(run.conclusion==='success')return {ok:true,quando:run.updated_at};
    return motiviGiro(run).then(function(m){return {ok:false,quando:run.updated_at,motivi:m};});});}).catch(function(){return null;});}
function controllaCloud(avvisa){return statoCloud().then(function(c){if(!c)return;var prima=SY.cloud;SY.cloud=c;segnaSync();
  if(avvisa&&!c.ok&&!(prima&&prima.ok===false))toast('⚠ Lo script nel cloud si è fermato'+(c.motivi.length?': '+c.motivi.map(function(x){return x.titolo;}).join(', '):'')+'. Tocca 🔄 per sapere cosa fare.',true);});}
function quandoBreve(iso){var d=new Date(iso);if(isNaN(d))return '';var ieri=new Date(Date.now()-864e5),hm=d.toLocaleTimeString('it-IT',{hour:'2-digit',minute:'2-digit'});
  return (d.toDateString()===new Date().toDateString()?'oggi':d.toDateString()===ieri.toDateString()?'ieri':d.toLocaleDateString('it-IT',{day:'numeric',month:'short'}))+' alle '+hm;}
function boxCloud(){var box=el('div',{style:'margin-top:10px'});
  function disegna(c){box.innerHTML='';if(!c)return;
    if(c.ok){box.appendChild(el('div',{cls:'msub',text:'Script nel cloud: ultimo giro '+quandoBreve(c.quando)+' ✓'}));return;}
    var frena=(c.motivi||[]).filter(function(m){return m.tipo==='FRENO';});
    var righe=[el('div',{style:'font-weight:800;color:var(--red)',text:'⚠ Lo script nel cloud si è fermato ('+quandoBreve(c.quando)+')'})];
    (c.motivi||[]).forEach(function(m){righe.push(el('div',{style:'margin-top:6px;font-weight:700',text:'• '+m.titolo}));if(m.spiega)righe.push(el('div',{cls:'msub',style:'margin-top:2px',text:m.spiega}));});
    if(!(c.motivi||[]).length)righe.push(el('div',{cls:'msub',style:'margin-top:4px',text:'Motivo non chiaro: riprova con «Sistema la rubrica»; se si ripete, avvisa Claude.'}));
    if(frena.length){var acc=frena.every(function(m){return m.account==='jacopo';})?'jacopo':frena.every(function(m){return m.account==='marco';})?'marco':'entrambi';
      var b=el('button',{cls:'act main',type:'button',style:'margin-top:10px;width:100%;justify-content:center',text:'🔓 Sblocca il freno e rifai il giro',onclick:function(){
        if(!window.confirm('Sbloccare il freno di sicurezza?\n\nLo script farà TUTTE le modifiche che aveva fermato. Fallo solo se sai perché ci sono tanti contatti nuovi, modificati o cancellati (per esempio li hai appena salvati tu). Se non lo sai, annulla e avvisa Claude.'))return;
        closeOv();googleToken().then(ghToken).then(function(){SY.running=true;SY.fase='script';segnaSync();toast('Sblocco il freno e rifaccio il giro nel cloud… (circa 1 minuto)');
          return lanciaScript(acc,true).catch(function(e){toast(e.message,true);});}).then(function(){SY.running=false;SY.fase='';aggiornaDaRubrica(true);},
          function(e){SY.running=false;SY.fase='';segnaSync();toast(e.message,true);});}});
      righe.push(b);}
    box.appendChild(el('div',{style:'border:1px solid var(--red);border-radius:10px;padding:10px;background:#fff5f5'},righe));}
  disegna(SY.cloud);statoCloud().then(function(c){if(c){SY.cloud=c;segnaSync();}disegna(c);});
  return box;}
// link da DeliverySync (22/11): #cliente=<scheda> apre la scheda (per correggerla), #nuovo apre "+ Nuovo"
function apriDaLink(){var h=location.hash||'';if(!h||!S.clients.length)return;var m=/^#cliente=(.+)$/.exec(h);
  try{history.replaceState(null,'',location.pathname+location.search);}catch(e){}
  if(m){var id=decodeURIComponent(m[1]);if(S.clients.some(function(c){return c._id===id;}))openDetail(id,true);else toast('Cliente non trovato sulla mappa',true);}
  else if(h==='#nuovo')openNewClient();}
window.addEventListener('hashchange',apriDaLink);
document.getElementById('sybtn').addEventListener('click',openSync);

// ── MENU ──────────────────────────────────────────────────────────────────
document.getElementById('mbtn').addEventListener('click',function(){
  openOv([el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:'Menu'}),el('div',{cls:'msub',text:'Accesso: '+(S.user?S.user.email:'')})]),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},[
      el('button',{cls:'act',style:'justify-content:flex-start',text:'📥 Importa / aggiorna clienti da file',onclick:function(){document.getElementById('fileimp').click();}}),
      el('button',{cls:'act',style:'justify-content:flex-start',text:'❓ Come si usa',onclick:function(){closeOv();openGuida();}}),
      el('button',{cls:'act',style:'justify-content:flex-start',text:'🗺️ Mostra tutti sulla mappa',onclick:function(){S.f={zone:{},prod:{},sig:{},pag:{}};S.q='';document.getElementById('search').value='';applyFilters(true);closeOv();}}),
      el('button',{cls:'act',style:'justify-content:flex-start',text:'🔑 Cambia password di cifratura',onclick:openRekey}),
      el('button',{cls:'act',style:'justify-content:flex-start;color:var(--red)',text:'↩ Esci',onclick:function(){if(!window.confirm('Vuoi uscire? La chiave di cifratura verrà rimossa da questo dispositivo.'))return;
        if(unsub)unsub();if(unsubMeta)unsubMeta();if(unsubEx)unsubEx();S.key=null;S.clients=[];S.ex=[];gTok=null;try{localStorage.removeItem('fn_gtok');sessionStorage.removeItem('fn_gtok');localStorage.removeItem('fn_dd_n');}catch(e){}
        dropKey().then(function(){auth.signOut();closeOv();});}})])]);
});

// ── CAMBIO PASSWORD DI CIFRATURA: decifra tutto con la vecchia e ricifra con la nuova ──
function openRekey(){
  function inp(id,ph){return el('div',{cls:'pw',style:'margin-bottom:10px'},[el('input',{cls:'fi',id:id,type:'password',placeholder:ph,autocomplete:'new-password'})]);}
  var err=el('div',{cls:'err',style:'color:var(--red);font-size:13px;min-height:18px;margin:6px 0'});
  var btn=el('button',{cls:'pbtn',text:'Cambia password',onclick:function(){doRekey(btn,err);}});
  openOv([el('div',{cls:'mhead'},[el('div',{},[el('div',{cls:'mtitle',text:'Cambia password di cifratura'}),el('div',{cls:'msub',text:'Tutti i clienti vengono ricifrati con la nuova password'})]),el('button',{cls:'mclose',text:'✕',onclick:closeOv})]),
    el('div',{cls:'mbody'},[inp('rkold','Password attuale'),inp('rknew','Nuova password (min. 12 caratteri)'),inp('rknew2','Ripeti la nuova password'),
      el('p',{style:'font-size:13px;color:var(--muted,#64748b);margin:4px 0 8px',text:'Dopo il cambio, sugli altri dispositivi (e per gli altri utenti) l\'app chiederà la nuova password: comunicala a chi deve usarla.'}),err,btn])]);
}
function doRekey(btn,err){
  var oldPw=document.getElementById('rkold').value,nw=document.getElementById('rknew').value,nw2=document.getElementById('rknew2').value;err.textContent='';
  if(nw.length<12){err.textContent='La nuova password deve avere almeno 12 caratteri.';return;}
  if(nw!==nw2){err.textContent='Le due nuove password non coincidono.';return;}
  if(nw===oldPw){err.textContent='La nuova password è uguale a quella attuale.';return;}
  btn.disabled=true;btn.textContent='Ricifratura in corso…';
  var oldK,newK;
  deriveKey(oldPw).then(function(k){oldK=k;return verifyKey(k);}).then(function(ok){if(!ok)throw new Error('wrong');return deriveKey(nw);})
  .then(function(k){newK=k;return CCOL.get();})
  .then(function(snap){
    return Promise.all(snap.docs.map(function(d){return dec(d.data().d,oldK).then(function(c){delete c._id;return enc(c,newK).then(function(x){return {ref:d.ref,d:x};});});}))
    .then(function(rows){return enc(CHECK,newK).then(function(chk){return {rows:rows,chk:chk};});})
    .then(function(r){  // anche la chiave GitHub dello script nel cloud va ricifrata con la nuova password
      return GHDOC.get().then(function(s){if(!s.exists||!s.data().d)return r;
        return dec(s.data().d,oldK).then(function(o){return enc(o,newK);}).then(function(x){r.rows.push({ref:GHDOC,d:x,gh:true});return r;},function(){return r;});});
    })
    .then(function(r){  // e la lista degli ex clienti (27/11); se non si decifra si rifa' da sola al 🔄
      return EXDOC.get().then(function(s){if(!s.exists||!s.data().d)return r;
        return dec(s.data().d,oldK).then(function(o){return enc(o,newK);}).then(function(x){r.rows.push({ref:EXDOC,d:x,gh:true});return r;},function(){return r;});});
    });
  })
  .then(function(r){
    // Firestore scrive al massimo 500 documenti per volta: si lavora a blocchi, in tre fasi sicure.
    // 1) accanto a ogni scheda si scrive la copia con la password nuova (campo "dn"): la vecchia "d" resta,
    //    se qualcosa si interrompe qui non e' cambiato niente (la password valida resta la vecchia);
    // 2) un solo salvataggio rende valida la password nuova;
    // 3) "dn" diventa "d". Se si interrompe qui, l'app legge "dn" e completa da sola (finisciRekey).
    S.rekeying=true;
    var now=new Date().toISOString(),FV=firebase.firestore.FieldValue;
    return aBlocchi(r.rows,function(b,x){b.set(x.ref,{dn:x.d},{merge:true});})
    .then(function(){return META.set({check:r.chk,creato:now,da:S.user.email,cambiata:true});})
    .then(function(){S.key=newK;saveKey(newK);
      return aBlocchi(r.rows,function(b,x){b.update(x.ref,{d:x.d,dn:FV.delete(),v:1,aggiornato:now,da:S.user.email});});})
    .then(function(){return r.rows.filter(function(x){return !x.gh;}).length;});
  })
  .then(function(n){S.rekeying=false;closeOv();startApp();toast('Password cambiata · '+n+' clienti ricifrati ✓');})
  .catch(function(e){S.rekeying=false;btn.disabled=false;btn.textContent='Cambia password';
    if(S.key===newK){closeOv();startApp();toast('Password cambiata: alcune schede si completano alla prossima apertura.',true);return;}
    err.textContent=e.message==='wrong'?'La password attuale non è corretta.':(e.name==='OperationError'?'Alcuni dati non si decifrano con la password attuale: nulla è stato cambiato.':permMsg(e)+' · Nulla è stato cambiato: la password resta quella attuale.');});
}
// scrive una lista a blocchi da 400 (limite Firestore: 500 per volta)
function aBlocchi(lista,fn){var p=Promise.resolve();
  for(var i=0;i<lista.length;i+=400)(function(ch){p=p.then(function(){var b=db.batch();ch.forEach(function(x){fn(b,x);});return b.commit();});})(lista.slice(i,i+400));
  return p;}
// legge una scheda: se e' a meta' di un cambio password, la copia buona e' in "dn"
function decD(data){return dec(data.d).catch(function(e){if(!data.dn)throw e;return dec(data.dn).then(function(c){if(c&&typeof c==='object')c.__dn=true;return c;});});}
function finisciRekey(refs){  // ripetibile senza danni: riscrive solo dove c'e' ancora "dn"
  var now=new Date().toISOString(),FV=firebase.firestore.FieldValue;
  Promise.all(refs.map(function(ref){return ref.get().then(function(s){return s.data()&&s.data().dn?{ref:ref,dn:s.data().dn}:null;});}))
  .then(function(l){return aBlocchi(l.filter(Boolean),function(b,x){b.update(x.ref,{d:x.dn,dn:FV.delete(),aggiornato:now,da:S.user.email});});})
  .catch(function(){});}
document.getElementById('exbtn').addEventListener('click',function(e){e.stopPropagation();openExMode();});
