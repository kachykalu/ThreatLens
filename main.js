
function applyFontToAllSheets(){
  var root = DriveApp.getFoldersByName("ThreatLens WAF Logs").next();
  var years = root.getFolders();

  while(years.hasNext()){
    var yearFolder = years.next();
    var files = yearFolder.getFiles();

    while(files.hasNext()){
      var f = files.next();
      if(f.getMimeType() === MimeType.GOOGLE_SHEETS){
        var ss = SpreadsheetApp.open(f);
        ss.getSheets().forEach(function(sh){
          sh.getRange(1,1,sh.getMaxRows(),sh.getMaxColumns())
            .setFontFamily("Instrument Sans");
        });
      }
    }
  }
}
const CONFIG = {
  SAFELINE_HOST: "YOUR_URL",
  API_TOKEN: "YOUR_API_KEY",
  ROOT_FOLDER_NAME: "ThreatLens WAF Logs",
  DASHBOARD_FILE_NAME: "ThreatLens WAF Dashboard",
  PAGE_SIZE: 100, MAX_PAGES: 200, TRIGGER_INTERVAL_MINUTES: 30,
};

// ── ENUMS ────────────────────────────────────────────────────────────────────
var ATK_MAP={0:"Unknown",1:"SQL Injection",2:"XSS",3:"Command Injection",4:"CRLF Injection",5:"LDAP Injection",6:"XPath Injection",7:"RCE",8:"XXE",9:"SSRF",10:"Path Traversal",11:"Backdoor",12:"Brute Force",13:"HTTP Flood",14:"Bot Abuse",15:"Code Injection",16:"File Upload",17:"Scanner",18:"Sensitive Data",19:"JSON Injection",20:"XML Injection","-1":"Custom Rule","-2":"Blacklist","-3":"Blacklist"};
var ACT_MAP={0:"Pass",1:"Deny",2:"Challenge",3:"Log Only"};
var PROTO_MAP={0:"Unknown",1:"HTTP",2:"HTTPS"};
var RISK_MAP={0:"None",1:"Low",2:"Medium",3:"High",4:"Critical"};
function mE_(m,v){if(v===null||v===undefined||v==="")return"";return m[String(v)]||("Code:"+v);}

// ── TAB CONFIG ───────────────────────────────────────────────────────────────
var H_ATK=["ID","Timestamp","Source IP","Socket IP","Dest IP","Host","Src Port","Dst Port","URL Path","Query String","Method","Attack Type","Action","Risk Level","Module","Reason","Payload","Rule ID","Policy Name","Country","Province","City","Lat","Lng","Protocol","Status Code","JA4 Fingerprint","Event ID","Website"];
var H_RULE=H_ATK.slice();
var H_RL=["ID","Timestamp","Source IP","Action","Reason","Status","Denied Count","Count","Block Minutes","Period","Site Title","Site Server Names","Country","Province","City","Query Key","Result","Updated At"];
var H_BOT=["ID","Timestamp","Source IP","Site Title","Site Server Names","Trigger Count","Pass Count","Duration (sec)","Started At","Ended At","Event ID","Rule ID","Country","Province","City","Updated At"];
var H_AUTH=["ID","Timestamp","Source IP","Username","Deny Count","Pass Count","Trigger Count","Duration (sec)","Site Title","Site Server Names","Started At","Ended At","Event ID","Rule ID","Country","Province","City","Updated At"];
var H_AUTHV2=["ID","Timestamp","Source IP","Username","Result","Source Type","Policy ID","Auth Source ID","Site Title","Site Server Names","Site ID","Country","Province","City","UUID","Third ID","User ID","Updated At"];
var H_EV=["ID","Source IP","Host","Dest Port","Protocol","Country","Province","City","Deny Count","Pass Count","Started At","Ended At","Finished"];

var T_ATK="Attack Records",T_RULE="Rule Block Records",T_RL="Rate Limit Logs",T_BOT="Anti-Bot Challenge",T_AUTH="Auth Challenge",T_AUTHV2="Auth Challenge v2",T_EV="Attack Events";
var MONTHS=["January","February","March","April","May","June","July","August","September","October","November","December"];

var ALL_TABS=[
  {name:T_ATK,endpoint:"/api/open/records",headers:H_ATK,parser:"pAtk_"},
  {name:T_RULE,endpoint:"/api/open/records/rule",headers:H_RULE,parser:"pRule_"},
  {name:T_RL,endpoint:"/api/open/records/acl",headers:H_RL,parser:"pRL_"},
  {name:T_BOT,endpoint:"/api/open/records/challenge",headers:H_BOT,parser:"pBot_"},
  {name:T_AUTH,endpoint:"/api/open/records/auth_defense",headers:H_AUTH,parser:"pAuth_"},
  {name:T_AUTHV2,endpoint:"/api/open/v2/records/auth_defense",headers:H_AUTHV2,parser:"pAuthV2_"},
  {name:T_EV,endpoint:"/api/open/events",headers:H_EV,parser:"pEv_"},
];

// ── TRANSLATION ──────────────────────────────────────────────────────────────
var tC_={};
function bTr_(texts){
  if(!texts||!texts.length)return[];
  var r=[],tt=[],ix=[];
  texts.forEach(function(t,i){
    if(!t||typeof t!=="string"||/^[\x00-\x7F]*$/.test(t)){r[i]=t||"";}
    else if(tC_[t]){r[i]=tC_[t];}
    else{tt.push(t);ix.push(i);r[i]=null;}
  });
  if(tt.length>0){
    for(var c=0;c<tt.length;c+=50){
      var ch=tt.slice(c,c+50),d=" ||| ";
      try{var tr=LanguageApp.translate(ch.join(d),"","en").split(d);
        for(var j=0;j<ch.length;j++){var e=(tr[j]||ch[j]).trim();tC_[ch[j]]=e;r[ix[c+j]]=e;}}
      catch(er){for(var j=0;j<ch.length;j++){tC_[ch[j]]=ch[j];r[ix[c+j]]=ch[j];}}
      Utilities.sleep(100);
    }
  }return r;
}

// ── FOLDER/FILE MGMT ─────────────────────────────────────────────────────────
function gRoot_(){var f=DriveApp.getFoldersByName(CONFIG.ROOT_FOLDER_NAME);return f.hasNext()?f.next():DriveApp.createFolder(CONFIG.ROOT_FOLDER_NAME);}
function gYear_(y){var r=gRoot_(),s=String(y),f=r.getFoldersByName(s);return f.hasNext()?f.next():r.createFolder(s);}
function gMonth_(y,m){
  var fo=gYear_(y),nm="SafeLine - "+MONTHS[m]+" "+y,fi=fo.getFilesByName(nm);
  if(fi.hasNext())return SpreadsheetApp.open(fi.next());

  var ss=SpreadsheetApp.create(nm);
  DriveApp.getFileById(ss.getId()).moveTo(fo);

  ALL_TABS.forEach(function(cfg,i){
    var sh=i===0?ss.getSheets()[0]:ss.insertSheet(cfg.name);
    if(i===0)sh.setName(cfg.name);
    sh.getRange(1,1,1,cfg.headers.length).setValues([cfg.headers]);
    sh.getRange(1,1,1,cfg.headers.length).setBackground("#1a73e8").setFontColor("#fff").setFontWeight("bold").setHorizontalAlignment("center");
    sh.setFrozenRows(1);
    sh.getRange(1,1,1,cfg.headers.length).createFilter();
  });

  setDefaultFont_(ss);
  return ss;
}

function setDefaultFont_(ss){
  ss.getSheets().forEach(function(sh){
    sh.getRange(1,1,sh.getMaxRows(),sh.getMaxColumns())
      .setFontFamily("Instrument Sans");
  });
}
function gDash_(){
  var r=gRoot_(),fi=r.getFilesByName(CONFIG.DASHBOARD_FILE_NAME);
  if(fi.hasNext())return SpreadsheetApp.open(fi.next());

  var ss=SpreadsheetApp.create(CONFIG.DASHBOARD_FILE_NAME);
  DriveApp.getFileById(ss.getId()).moveTo(r);
  ss.getSheets()[0].setName("Consolidated");

  setDefaultFont_(ss);
  return ss;
}

// ── SETUP ────────────────────────────────────────────────────────────────────
function initialSetup(){
  var r=gRoot_(),now=new Date(),ss=gMonth_(now.getFullYear(),now.getMonth()),d=gDash_();
  ScriptApp.getProjectTriggers().forEach(function(t){if(t.getHandlerFunction()==="pullAllData")ScriptApp.deleteTrigger(t);});
  ScriptApp.newTrigger("pullAllData").timeBased().everyMinutes(CONFIG.TRIGGER_INTERVAL_MINUTES).create();
  pullAllData();
  SpreadsheetApp.getUi().alert("Setup Complete!\n\n📁 "+r.getUrl()+"\n📊 Monthly: "+ss.getUrl()+"\n📊 Dashboard: "+d.getUrl()+"\n\n✓ All 7 block type tabs\n✓ Auto-pull every "+CONFIG.TRIGGER_INTERVAL_MINUTES+" min");
}

// ── MAIN PULL ────────────────────────────────────────────────────────────────
function pullAllData(){
  Logger.log("=== Pull started ===");
  var allData={};
  ALL_TABS.forEach(function(cfg){allData[cfg.name]=fetchAll_(cfg.endpoint);});
  var all=[];ALL_TABS.forEach(function(cfg){all=all.concat(allData[cfg.name]);});
  var p=[],c=[],re=[],mo=[];
  all.forEach(function(r){p.push(r.province||"");c.push(r.city||"");re.push(r.reason||"");mo.push(r.module||"");});
  var tP=bTr_(p),tCi=bTr_(c),tR=bTr_(re),tM=bTr_(mo);
  var i=0;all.forEach(function(r){r._p=tP[i]||"";r._c=tCi[i]||"";r._r=tR[i]||"";r._m=tM[i]||"";i++;});
  var parsers={pAtk_:pAtk_,pRule_:pRule_,pRL_:pRL_,pBot_:pBot_,pAuth_:pAuth_,pAuthV2_:pAuthV2_,pEv_:pEv_};
  ALL_TABS.forEach(function(cfg){
    var n=writeByMonth_(allData[cfg.name],cfg.name,cfg.headers,parsers[cfg.parser]);
    Logger.log(cfg.name+": "+n);
  });
  updateDashboard_();
  Logger.log("=== Pull complete ===");
}

function fetchAll_(ep){
  var pg=1,all=[],more=true;
  while(more){
    var d=apiGet_(ep,{page:pg,page_size:CONFIG.PAGE_SIZE});if(!d)break;
    var it=exIt_(d);if(!it||!it.length){more=false;break;}
    it.forEach(function(r){all.push(r);});pg++;
    if(it.length<CONFIG.PAGE_SIZE)more=false;
    if(pg>CONFIG.MAX_PAGES)more=false;
    Utilities.sleep(300);
  }
  Logger.log("Fetched "+all.length+" from "+ep);return all;
}

function writeByMonth_(items,tab,hdr,fn){
  if(!items||!items.length)return 0;
  var gr={};
  items.forEach(function(r){
    var ts=r.timestamp||r.created_at||r.start_at||r.started_at||"";
    var d=tsD_(ts)||new Date();
    var k=d.getFullYear()+"-"+d.getMonth();
    if(!gr[k])gr[k]=[];gr[k].push(r);
  });
  var tot=0;
  Object.keys(gr).forEach(function(k){
    var p=k.split("-"),y=parseInt(p[0]),m=parseInt(p[1]);
    var ss=gMonth_(y,m),sh=ss.getSheetByName(tab);
    if(!sh){sh=ss.insertSheet(tab);sh.getRange(1,1,1,hdr.length).setValues([hdr]);sh.getRange(1,1,1,hdr.length).setBackground("#1a73e8").setFontColor("#fff").setFontWeight("bold").setHorizontalAlignment("center");sh.setFrozenRows(1);}
    var ex={},lr=sh.getLastRow();
    if(lr>1)sh.getRange(2,1,lr-1,1).getValues().forEach(function(r){if(r[0])ex[String(r[0])]=true;});
    var nr=[];
    gr[k].forEach(function(r){var row=fn(r);var id=String(row[0]);if(!ex[id]&&id!==""){nr.push(row);ex[id]=true;}});
    if(nr.length>0){var wr=sh.getLastRow()+1;for(var i=0;i<nr.length;i+=500){var b=nr.slice(i,i+500);sh.getRange(wr,1,b.length,hdr.length).setValues(b);wr+=b.length;}tot+=nr.length;}
  });
  return tot;
}

// ── PARSERS ──────────────────────────────────────────────────────────────────
function pAtk_(r){var ts=r.timestamp||r.created_at||"",id=r.id||(ts+"_"+(r.src_ip||"")+"_"+(r.url_path||""));return[id,fTs_(ts),r.src_ip||"",r.socket_ip||"",r.dst_ip||"",r.host||"",r.src_port||"",r.dst_port||"",r.url_path||"",r.query_string||"",r.method||"",mE_(ATK_MAP,r.attack_type),mE_(ACT_MAP,r.action),mE_(RISK_MAP,r.risk_level),r._m||"",r._r||"",r.payload||"",r.rule_id||"",r.policy_name||"",r.country||"",r._p||"",r._c||"",r.lat||"",r.lng||"",mE_(PROTO_MAP,r.protocol),r.status_code||"",r.ja4_fingerprint||"",r.event_id||r.EventId||"",r.website||""];}
function pRule_(r){return pAtk_(r);}
function pRL_(r){var ts=r.created_at||r.timestamp||"",id=r.id||(ts+"|rl|"+(r.ip||""));return[id,fTs_(ts),r.ip||"",r.action||"",r._r||r.reason||"",r.status||"",r.denied_count||0,r.count||0,r.block_min||0,r.period||0,r.site_title||"",(r.site_server_names||[]).join(", "),r.country||"",r._p||"",r._c||"",r.query_key||"",r.result||"",fTs_(r.updated_at||"")];}
function pBot_(r){var ts=r.created_at||r.started_at||"",id=r.id||(ts+"|bot|"+(r.ip||""));return[id,fTs_(ts),r.ip||"",r.site_title||"",(r.site_server_names||[]).join(", "),r.trigger_count||0,r.pass_count||0,r.dur_sec||0,fTs_(r.started_at||""),fTs_(r.ended_at||""),r.event_id||"",r.rule_id||"",r.country||"",r._p||"",r._c||"",fTs_(r.updated_at||"")];}
function pAuth_(r){var ts=r.created_at||r.started_at||"",id=r.id||(ts+"|auth|"+(r.ip||"")+(r.username||""));return[id,fTs_(ts),r.ip||"",r.username||"",r.deny_count||0,r.pass_count||0,r.trigger_count||0,r.dur_sec||0,r.site_title||"",(r.site_server_names||[]).join(", "),fTs_(r.started_at||""),fTs_(r.ended_at||""),r.event_id||"",r.rule_id||"",r.country||"",r._p||"",r._c||"",fTs_(r.updated_at||"")];}
function pAuthV2_(r){var ts=r.created_at||"",id=r.id||(ts+"|av2|"+(r.ip||"")+(r.username||""));return[id,fTs_(ts),r.ip||"",r.username||"",r.result===true?"Pass":r.result===false?"Deny":String(r.result||""),r.source_type||"",r.policy_id||"",r.auth_source_id||"",r.site_title||"",(r.site_server_names||[]).join(", "),r.site_id||"",r.country||"",r._p||"",r._c||"",r.uuid||"",r.third_id||"",r.user_id||"",fTs_(r.updated_at||"")];}
function pEv_(r){var ts=r.start_at||r.started_at||"";return[String(r.id||""),r.ip||r.src_ip||"",r.host||"",r.dst_port||r.port||"",mE_(PROTO_MAP,r.protocol),r.country||"",r._p||"",r._c||"",r.deny_count||0,r.pass_count||0,fTs_(r.start_at||r.started_at||""),fTs_(r.end_at||r.ended_at||""),r.finished||false];}

// ── DASHBOARD ────────────────────────────────────────────────────────────────
function updateDashboard_(){
  Logger.log("Updating dashboard...");
  var dSS=gDash_(),root=gRoot_();
  var mFiles=[];
  var yfs=root.getFolders();
  while(yfs.hasNext()){var yf=yfs.next();if(!/^\d{4}$/.test(yf.getName()))continue;var fs=yf.getFiles();while(fs.hasNext()){var f=fs.next();if(f.getName().indexOf("SafeLine - ")===0)mFiles.push({name:f.getName(),id:f.getId()});}}
  mFiles.sort(function(a,b){return a.name.localeCompare(b.name);});

  var con=newStats_();con.monthly={};

  mFiles.forEach(function(mf){
    var ss;try{ss=SpreadsheetApp.openById(mf.id);}catch(e){return;}
    var label=mf.name.replace("SafeLine - ","");
    var st=analyzeFile_(ss);
    var tab=dSS.getSheetByName(label);if(!tab)tab=dSS.insertSheet(label);
    writeMonthDash_(tab,label,st);
    mergeInto_(con,st,label);
  });

  var ct=dSS.getSheetByName("Consolidated");if(!ct)ct=dSS.insertSheet("Consolidated");
  writeConDash_(ct,con);
  Logger.log("Dashboard updated");
}

function newStats_(){
  return{attacks:0,blacklist:0,rateLimit:0,antiBot:0,authChallenge:0,authV2:0,events:0,
    rlDenied:0,botTriggers:0,authDenies:0,evDenies:0,evPasses:0,
    ips:{},countries:{},attackTypes:{},policies:{},apps:{},riskLevels:{},
    urlPaths:{},methods:{},protocols:{},hourly:{},
  };
}

function analyzeFile_(ss){
  var s=newStats_();

  // Attack Records: IP=2,Host=5,AttackType=11,Action=12,RiskLevel=13,Module=14,Policy=18,Country=19,URLPath=8,Method=10,Protocol=24
  tFE_(ss,T_ATK,H_ATK,function(r){
    s.attacks++;
    aTo_(s.ips,r[2]);aTo_(s.apps,r[5]);aTo_(s.attackTypes,r[11]);
    aTo_(s.riskLevels,r[13]);aTo_(s.policies,r[18]);aTo_(s.countries,r[19]);
    aTo_(s.urlPaths,r[8]);aTo_(s.methods,r[10]);aTo_(s.protocols,r[24]);
    trackHour_(s,r[1]);
  });

  // Rule Blocks
  tFE_(ss,T_RULE,H_RULE,function(r){
    s.blacklist++;
    aTo_(s.ips,r[2]);aTo_(s.apps,r[5]);aTo_(s.attackTypes,r[11]);
    aTo_(s.riskLevels,r[13]);aTo_(s.policies,r[18]);aTo_(s.countries,r[19]);
    aTo_(s.urlPaths,r[8]);aTo_(s.methods,r[10]);
    trackHour_(s,r[1]);
  });

  // Rate Limits: IP=2,DeniedCount=6,SiteTitle=11,Country=12
  tFE_(ss,T_RL,H_RL,function(r){
    s.rateLimit++;
    var w=parseInt(r[6])||1;s.rlDenied+=parseInt(r[6])||0;
    aTo_(s.ips,r[2],w);aTo_(s.apps,r[11],w);aTo_(s.countries,r[12],w);
    aTo_(s.policies,"Rate Limiting",w);
    trackHour_(s,r[1]);
  });

  // Anti-Bot: IP=2,SiteTitle=3,TriggerCount=5,Country=12
  tFE_(ss,T_BOT,H_BOT,function(r){
    s.antiBot++;
    var w=parseInt(r[5])||1;s.botTriggers+=parseInt(r[5])||0;
    aTo_(s.ips,r[2],w);aTo_(s.apps,r[4],w);aTo_(s.countries,r[12],w);
    aTo_(s.policies,"Anti-Bot Challenge",w);
    trackHour_(s,r[1]);
  });

  // Auth v1: IP=2,DenyCount=4,PassCount=5,SiteTitle=9,Country=14
  tFE_(ss,T_AUTH,H_AUTH,function(r){
    s.authChallenge++;
    var d=parseInt(r[4])||0,p=parseInt(r[5])||0,w=d+p||1;
    s.authDenies+=d;
    aTo_(s.ips,r[2],w);aTo_(s.apps,r[9],w);aTo_(s.countries,r[14],w);
    aTo_(s.policies,"Auth Challenge",w);
    trackHour_(s,r[1]);
  });

  // Auth v2: IP=2,Result=4,SiteTitle=9,Country=11
  tFE_(ss,T_AUTHV2,H_AUTHV2,function(r){
    s.authV2++;
    aTo_(s.ips,r[2]);aTo_(s.apps,r[9]);aTo_(s.countries,r[11]);
    aTo_(s.policies,"Auth Challenge v2");
    trackHour_(s,r[1]);
  });

  // Events: IP=1,Host=2,Country=5,DenyCount=8,PassCount=9
  tFE_(ss,T_EV,H_EV,function(r){
    s.events++;
    var d=parseInt(r[8])||0,p=parseInt(r[9])||0;
    s.evDenies+=d;s.evPasses+=p;
    var w=d+p||1;
    aTo_(s.ips,r[1],w);aTo_(s.apps,r[2],w);aTo_(s.countries,r[5],w);
    trackHour_(s,r[10]);
  });

  return s;
}

function trackHour_(s,tsStr){
  if(!tsStr)return;
  try{var d=new Date(tsStr);if(!isNaN(d.getTime())){var h=d.getHours();aTo_(s.hourly,String(h).padStart(2,"0")+":00");}}catch(e){}
}

function tFE_(ss,tab,hdr,fn){var sh=ss.getSheetByName(tab);if(!sh||sh.getLastRow()<=1)return;sh.getRange(2,1,sh.getLastRow()-1,hdr.length).getValues().forEach(fn);}
function aTo_(o,k,w){if(!k||k==="None"||k==="Unknown"||k==="")return;o[k]=(o[k]||0)+(w||1);}

function mergeInto_(con,s,label){
  con.attacks+=s.attacks;con.blacklist+=s.blacklist;con.rateLimit+=s.rateLimit;
  con.antiBot+=s.antiBot;con.authChallenge+=s.authChallenge;con.authV2+=s.authV2;
  con.events+=s.events;con.rlDenied+=s.rlDenied;con.botTriggers+=s.botTriggers;
  con.authDenies+=s.authDenies;con.evDenies+=s.evDenies;con.evPasses+=s.evPasses;
  var totalBlocked=s.attacks+s.blacklist+s.rlDenied+s.botTriggers+s.authDenies+s.authV2+s.evDenies;
  con.monthly[label]=totalBlocked;
  ["ips","countries","attackTypes","policies","apps","riskLevels","urlPaths","methods","protocols","hourly"].forEach(function(f){
    Object.keys(s[f]).forEach(function(k){con[f][k]=(con[f][k]||0)+s[f][k];});
  });
}

// ── WRITE MONTH DASHBOARD ────────────────────────────────────────────────────
function writeMonthDash_(sh,label,s){
  sh.clear();
  var totalBlocked=s.attacks+s.blacklist+s.rlDenied+s.botTriggers+s.authDenies+s.authV2+s.evDenies;

  // ── SECTION 1: Title & Key Metrics ──
  sh.getRange("A1").setValue("ThreatLens WAF — "+label).setFontSize(18).setFontWeight("bold");
  sh.getRange("A2").setValue("Monthly Security Report").setFontSize(11).setFontColor("#666");

  var row=4;
  sh.getRange(row,1,1,3).setValues([["KEY METRICS","",""]]).setBackground("#0d47a1").setFontColor("#fff").setFontWeight("bold").setFontSize(12);
  var km=[
    ["Total Blocked Traffic",totalBlocked,"Sum of all denied/blocked requests across all protection layers"],
    ["Total Attacks (System Rules)",s.attacks,"Blocked by semantic analysis engine (SQLi, XSS, RCE, etc.)"],
    ["Total Blacklist (Custom Rules)",s.blacklist,"Blocked by custom rules: country blocks, IP blacklists, etc."],
    ["Total Rate Limiting",s.rlDenied,"Requests denied by rate limit policies"],
    ["Total Anti-Bot Challenge",s.botTriggers,"Bot challenges triggered"],
    ["Total Auth Challenge",s.authDenies+s.authV2,"Auth defense denials (v1 + v2)"],
    ["Total Attack Events",s.events,"Aggregated event count"],
    ["Event Deny Attempts",s.evDenies,""],
    ["Event Pass Attempts",s.evPasses,""],
  ];
  sh.getRange(row+1,1,km.length,3).setValues(km);
  sh.getRange(row+1,1,1,3).setBackground("#e3f2fd").setFontWeight("bold");
  sh.setColumnWidth(1,280);sh.setColumnWidth(2,150);sh.setColumnWidth(3,400);

  // ── SECTION 2: Policies & Attempts ──
  var row2=row+km.length+2;
  sh.getRange(row2,1).setValue(" ALL POLICIES & ATTEMPTS").setFontSize(13).setFontWeight("bold");
  sh.getRange(row2+1,1,1,2).setValues([["Policy / Rule","Total Attempts"]]).setBackground("#4a148c").setFontColor("#fff").setFontWeight("bold");
  var polSorted=Object.entries(s.policies).sort(function(a,b){return b[1]-a[1];});
  if(polSorted.length>0) sh.getRange(row2+2,1,polSorted.length,2).setValues(polSorted);

  // ── SECTION 3: Most Attacked Apps ──
  var row3=row2;
  sh.getRange(row3,4).setValue("MOST ATTACKED APPS").setFontSize(13).setFontWeight("bold");
  sh.getRange(row3+1,4,1,2).setValues([["Application / Host","Total Attempts"]]).setBackground("#b71c1c").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,s.apps,row3+2,4,15);

  // ── SECTION 4: Strategic Metrics ──
  var row4=Math.max(row2+polSorted.length+4, row3+18);
  sh.getRange(row4,1).setValue(" STRATEGIC INSIGHTS").setFontSize(14).setFontWeight("bold").setBackground("#fff3e0");
  sh.getRange(row4,1,1,11).setBackground("#fff3e0");

  var r=row4+2;
  // Attack Types
  sh.getRange(r,1).setValue("Attack Types").setFontSize(11).setFontWeight("bold");
  sh.getRange(r+1,1,1,2).setValues([["Type","Count"]]).setBackground("#d32f2f").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,s.attackTypes,r+2,1,15);

  // Top IPs
  sh.getRange(r,4).setValue("Top Attacker IPs").setFontSize(11).setFontWeight("bold");
  sh.getRange(r+1,4,1,2).setValues([["IP","Attempts"]]).setBackground("#e65100").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,s.ips,r+2,4,15);

  // Top Countries
  sh.getRange(r,7).setValue("Top Source Countries").setFontSize(11).setFontWeight("bold");
  sh.getRange(r+1,7,1,2).setValues([["Country","Attempts"]]).setBackground("#2e7d32").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,s.countries,r+2,7,15);

  // Risk Levels
  sh.getRange(r,10).setValue("Risk Level Distribution").setFontSize(11).setFontWeight("bold");
  sh.getRange(r+1,10,1,2).setValues([["Level","Count"]]).setBackground("#bf360c").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,s.riskLevels,r+2,10,6);

  // Row 2 of strategic
  var r2=r+19;
  // Top URL Paths
  sh.getRange(r2,1).setValue("Most Targeted URL Paths").setFontSize(11).setFontWeight("bold");
  sh.getRange(r2+1,1,1,2).setValues([["URL Path","Hits"]]).setBackground("#1565c0").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,s.urlPaths,r2+2,1,10);

  // HTTP Methods
  sh.getRange(r2,4).setValue("HTTP Methods").setFontSize(11).setFontWeight("bold");
  sh.getRange(r2+1,4,1,2).setValues([["Method","Count"]]).setBackground("#00695c").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,s.methods,r2+2,4,8);

  // Peak Hours
  sh.getRange(r2,7).setValue("Attack Peak Hours (UTC)").setFontSize(11).setFontWeight("bold");
  sh.getRange(r2+1,7,1,2).setValues([["Hour","Attacks"]]).setBackground("#4e342e").setFontColor("#fff").setFontWeight("bold");
  var hSorted=Object.entries(s.hourly).sort(function(a,b){return b[1]-a[1];}).slice(0,12);
  if(hSorted.length>0)sh.getRange(r2+2,7,hSorted.length,2).setValues(hSorted);

  // Protocols
  sh.getRange(r2,10).setValue("Protocols").setFontSize(11).setFontWeight("bold");
  sh.getRange(r2+1,10,1,2).setValues([["Protocol","Count"]]).setBackground("#263238").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,s.protocols,r2+2,10,5);

  // Column widths
  [4,7,10].forEach(function(c){sh.setColumnWidth(c,200);});
  [5,8,11].forEach(function(c){sh.setColumnWidth(c,120);});
}

// ── WRITE CONSOLIDATED DASHBOARD ─────────────────────────────────────────────
function writeConDash_(sh,c){
  sh.clear();
  var totalBlocked=c.attacks+c.blacklist+c.rlDenied+c.botTriggers+c.authDenies+c.authV2+c.evDenies;

  sh.getRange("A1").setValue("Consolidated Security Dashboard").setFontSize(18).setFontWeight("bold");
  sh.getRange("A2").setValue("All-time aggregated view | Updated: "+new Date().toISOString()).setFontSize(10).setFontColor("#666");

  // ── SECTION 1: Key Metrics ──
  var row=4;
  sh.getRange(row,1,1,3).setValues([["KEY METRICS (ALL TIME)","",""]]).setBackground("#0d47a1").setFontColor("#fff").setFontWeight("bold").setFontSize(12);
  var km=[
    ["Total Blocked Traffic (All Time)",totalBlocked," Sum of all denied/blocked across all months"],
    ["Total Attacks (System Rules)",c.attacks," Semantic engine blocks (SQLi, XSS, RCE, etc.)"],
    ["Total Blacklist (Custom Rules)",c.blacklist," Country blocks, IP blacklists, custom rules"],
    ["Total Rate Limiting Denials",c.rlDenied," Rate limit denied requests"],
    ["Total Anti-Bot Triggers",c.botTriggers," Bot challenge triggers"],
    ["Total Auth Challenge Denials",c.authDenies+c.authV2," Auth defense blocks"],
    ["Total Event Denies",c.evDenies,""],
    ["Total Event Passes",c.evPasses,""],
    ["","",""],
    ["Unique Attacker IPs",Object.keys(c.ips).length," Distinct source IPs across all time"],
    ["Unique Targeted Apps",Object.keys(c.apps).length," Distinct hosts/apps targeted"],
    ["Unique Source Countries",Object.keys(c.countries).length," Geographic diversity of attacks"],
    ["Unique Attack Types",Object.keys(c.attackTypes).length," Variety of attack vectors observed"],
  ];
  sh.getRange(row+1,1,km.length,3).setValues(km);
  sh.getRange(row+1,1,1,3).setBackground("#e3f2fd").setFontWeight("bold");
  sh.setColumnWidth(1,300);sh.setColumnWidth(2,160);sh.setColumnWidth(3,400);

  // ── SECTION 2: Monthly Trend ──
  var row2=row+km.length+2;
  sh.getRange(row2,1).setValue("MONTHLY TREND (Total Blocked per Month)").setFontSize(13).setFontWeight("bold");
  sh.getRange(row2+1,1,1,2).setValues([["Month","Total Blocked"]]).setBackground("#1565c0").setFontColor("#fff").setFontWeight("bold");
  var mSorted=Object.entries(c.monthly).sort(function(a,b){return a[0].localeCompare(b[0]);});
  if(mSorted.length>0)sh.getRange(row2+2,1,mSorted.length,2).setValues(mSorted);

  // ── Avg per month ──
  if(mSorted.length>0){
    var avg=Math.round(totalBlocked/mSorted.length);
    sh.getRange(row2+mSorted.length+3,1,1,2).setValues([["Average Blocked / Month",avg]]).setFontWeight("bold").setBackground("#e8eaf6");
  }

  // ── SECTION 3: All Policies ──
  var row3=row2;
  sh.getRange(row3,4).setValue("ALL POLICIES & ATTEMPTS").setFontSize(13).setFontWeight("bold");
  sh.getRange(row3+1,4,1,2).setValues([["Policy / Rule","Total Attempts"]]).setBackground("#4a148c").setFontColor("#fff").setFontWeight("bold");
  var polSorted=Object.entries(c.policies).sort(function(a,b){return b[1]-a[1];});
  if(polSorted.length>0)sh.getRange(row3+2,4,polSorted.length,2).setValues(polSorted);

  // ── SECTION 4: Most Attacked Apps ──
  sh.getRange(row3,7).setValue("MOST ATTACKED APPS (All Time)").setFontSize(13).setFontWeight("bold");
  sh.getRange(row3+1,7,1,2).setValues([["Application / Host","Total Attempts"]]).setBackground("#b71c1c").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,c.apps,row3+2,7,15);

  // ── SECTION 5: Strategic Metrics ──
  var row5=Math.max(row2+mSorted.length+6,row3+Math.max(polSorted.length,15)+4);
  sh.getRange(row5,1).setValue("STRATEGIC INSIGHTS (ALL TIME)").setFontSize(14).setFontWeight("bold").setBackground("#fff3e0");
  sh.getRange(row5,1,1,11).setBackground("#fff3e0");

  var r=row5+2;
  sh.getRange(r,1).setValue("Attack Types").setFontSize(11).setFontWeight("bold");
  sh.getRange(r+1,1,1,2).setValues([["Type","Attempts"]]).setBackground("#d32f2f").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,c.attackTypes,r+2,1,15);

  sh.getRange(r,4).setValue("Top Attacker IPs").setFontSize(11).setFontWeight("bold");
  sh.getRange(r+1,4,1,2).setValues([["IP","Attempts"]]).setBackground("#e65100").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,c.ips,r+2,4,15);

  sh.getRange(r,7).setValue("Top Source Countries").setFontSize(11).setFontWeight("bold");
  sh.getRange(r+1,7,1,2).setValues([["Country","Attempts"]]).setBackground("#2e7d32").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,c.countries,r+2,7,15);

  sh.getRange(r,10).setValue("Risk Level Distribution").setFontSize(11).setFontWeight("bold");
  sh.getRange(r+1,10,1,2).setValues([["Level","Count"]]).setBackground("#bf360c").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,c.riskLevels,r+2,10,6);

  var r2=r+19;
  sh.getRange(r2,1).setValue("Most Targeted URL Paths").setFontSize(11).setFontWeight("bold");
  sh.getRange(r2+1,1,1,2).setValues([["URL Path","Hits"]]).setBackground("#1565c0").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,c.urlPaths,r2+2,1,10);

  sh.getRange(r2,4).setValue("HTTP Methods").setFontSize(11).setFontWeight("bold");
  sh.getRange(r2+1,4,1,2).setValues([["Method","Count"]]).setBackground("#00695c").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,c.methods,r2+2,4,8);

  sh.getRange(r2,7).setValue("Attack Peak Hours (UTC)").setFontSize(11).setFontWeight("bold");
  sh.getRange(r2+1,7,1,2).setValues([["Hour","Attacks"]]).setBackground("#4e342e").setFontColor("#fff").setFontWeight("bold");
  var hS=Object.entries(c.hourly).sort(function(a,b){return b[1]-a[1];}).slice(0,24);
  if(hS.length>0)sh.getRange(r2+2,7,hS.length,2).setValues(hS);

  sh.getRange(r2,10).setValue("Protocols").setFontSize(11).setFontWeight("bold");
  sh.getRange(r2+1,10,1,2).setValues([["Protocol","Count"]]).setBackground("#263238").setFontColor("#fff").setFontWeight("bold");
  wTop_(sh,c.protocols,r2+2,10,5);

  [4,7,10].forEach(function(c){sh.setColumnWidth(c,220);});
  [5,8,11].forEach(function(c){sh.setColumnWidth(c,130);});
}

function wTop_(sh,obj,startRow,startCol,n){
  var sorted=Object.entries(obj).sort(function(a,b){return b[1]-a[1];}).slice(0,n);
  sh.getRange(startRow,startCol,n+2,2).clearContent();
  if(sorted.length>0)sh.getRange(startRow,startCol,sorted.length,2).setValues(sorted);
}

// ── API ──────────────────────────────────────────────────────────────────────
function apiGet_(ep,params){
  var url=CONFIG.SAFELINE_HOST+ep;
  if(params){var qs=Object.keys(params).filter(function(k){return params[k]!==""&&params[k]!==null&&params[k]!==undefined;}).map(function(k){return encodeURIComponent(k)+"="+encodeURIComponent(params[k]);}).join("&");if(qs)url+="?"+qs;}
  Logger.log("REQ: "+url);
  try{var r=UrlFetchApp.fetch(url,{method:"get",headers:{"X-SLCE-API-TOKEN":CONFIG.API_TOKEN,"Content-Type":"application/json"},muteHttpExceptions:true,validateHttpsCertificates:false});
    var code=r.getResponseCode(),body=r.getContentText();Logger.log("HTTP "+code+" | "+body.substring(0,200));
    if(code!==200)return null;var p=JSON.parse(body);if(p.msg==="invalid-permission")return null;return p;
  }catch(e){Logger.log("ERR: "+e.message);return null;}
}
function exIt_(d){if(!d)return[];if(d.data){var x=d.data;if(x.nodes&&Array.isArray(x.nodes))return x.nodes;if(x.data&&Array.isArray(x.data))return x.data;if(Array.isArray(x))return x;}return[];}
function fTs_(ts){
  if(!ts)return"";
  if(typeof ts==="number"){
    var d=new Date(ts*1000);
    if(!isNaN(d.getTime())&&d.getFullYear()>=2020&&d.getFullYear()<=2030) return d.toISOString();
    d=new Date(ts);
    if(!isNaN(d.getTime())&&d.getFullYear()>=2020&&d.getFullYear()<=2030) return d.toISOString();
  }
  return ts.toString();
}
function tsD_(ts){
  if(!ts)return null;
  var d;
  if(typeof ts==="number"){
    // Current epoch seconds ~1.7e9, milliseconds ~1.7e12
    // If number is > 1e11 (year 5000+ in seconds), it COULD be ms
    // But we validate by checking resulting year
    d=new Date(ts*1000); // try as seconds first
    if(!isNaN(d.getTime())&&d.getFullYear()>=2020&&d.getFullYear()<=2030) return d;
    d=new Date(ts); // try as milliseconds
    if(!isNaN(d.getTime())&&d.getFullYear()>=2020&&d.getFullYear()<=2030) return d;
    return null;
  }else{
    d=new Date(ts);
  }
  if(isNaN(d.getTime()))return null;
  if(d.getFullYear()<2020||d.getFullYear()>2030)return null;
  return d;
}

// ── MENU ─────────────────────────────────────────────────────────────────────
function resetAndRePull(){var n=new Date(),ss=gMonth_(n.getFullYear(),n.getMonth());ALL_TABS.forEach(function(c){var s=ss.getSheetByName(c.name);if(s&&s.getLastRow()>1)s.deleteRows(2,s.getLastRow()-1);});pullAllData();SpreadsheetApp.getUi().alert("Reset complete for "+MONTHS[n.getMonth()]+" "+n.getFullYear());}
function removeTrigger(){ScriptApp.getProjectTriggers().forEach(function(t){if(t.getHandlerFunction()==="pullAllData")ScriptApp.deleteTrigger(t);});SpreadsheetApp.getUi().alert("Auto-pull removed.");}
function onOpen(){SpreadsheetApp.getUi().createMenu("SafeLine WAF").addItem("Pull Now","pullAllData").addItem("Initial Setup","initialSetup").addSeparator().addItem("Reset Current Month","resetAndRePull").addItem("Update Dashboard Only","updateDashboard_").addItem("Remove Auto-Pull","removeTrigger").addToUi();}

function translateExistingSheets() {
  var root = gRoot_();
  var yfs = root.getFolders();
  
  while (yfs.hasNext()) {
    var yf = yfs.next();
    if (!/^\d{4}$/.test(yf.getName())) continue;
    var fs = yf.getFiles();
    
    while (fs.hasNext()) {
      var f = fs.next();
      if (f.getName().indexOf("SafeLine - ") !== 0) continue;
      
      var ss = SpreadsheetApp.open(f);
      Logger.log("Processing: " + f.getName());
      
      // Translate Attack Records & Rule Block Records columns:
      // N=Module(14), O=Reason(15), T=Province(21), U=City(22)
      [T_ATK, T_RULE].forEach(function(tab) {
        var sh = ss.getSheetByName(tab);
        if (!sh || sh.getLastRow() <= 1) return;
        translateColumn_(sh, 14); // Module
        translateColumn_(sh, 15); // Reason
        translateColumn_(sh, 21); // Province
        translateColumn_(sh, 22); // City
      });
      
      // Rate Limit: Province=14, City=15
      var shRL = ss.getSheetByName(T_RL);
      if (shRL && shRL.getLastRow() > 1) {
        translateColumn_(shRL, 14); // Province
        translateColumn_(shRL, 15); // City
      }
      
      // Anti-Bot: Province=14, City=15
      var shBot = ss.getSheetByName(T_BOT);
      if (shBot && shBot.getLastRow() > 1) {
        translateColumn_(shBot, 14); // Province
        translateColumn_(shBot, 15); // City
      }
      
      // Auth Challenge: Province=16, City=17
      var shAuth = ss.getSheetByName(T_AUTH);
      if (shAuth && shAuth.getLastRow() > 1) {
        translateColumn_(shAuth, 16); // Province
        translateColumn_(shAuth, 17); // City
      }
      
      // Auth v2: Province=13, City=14
      var shAv2 = ss.getSheetByName(T_AUTHV2);
      if (shAv2 && shAv2.getLastRow() > 1) {
        translateColumn_(shAv2, 13); // Province
        translateColumn_(shAv2, 14); // City
      }
      
      // Events: Province=7, City=8
      var shEv = ss.getSheetByName(T_EV);
      if (shEv && shEv.getLastRow() > 1) {
        translateColumn_(shEv, 7); // Province
        translateColumn_(shEv, 8); // City
      }
    }
  }
  Logger.log("Translation complete!");
}

function translateColumn_(sh, colNum) {
  var lr = sh.getLastRow();
  if (lr <= 1) return;
  var range = sh.getRange(2, colNum, lr - 1, 1);
  var vals = range.getValues();
  var texts = vals.map(function(r) { return r[0] ? String(r[0]) : ""; });
  var translated = bTr_(texts);
  var newVals = translated.map(function(t) { return [t]; });
  range.setValues(newVals);
}
