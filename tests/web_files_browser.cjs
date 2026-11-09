// Atlas UI regressions with an isolated, simulated backend. Real TPM proofs,
// cookie isolation and server authorization are covered by the Rust suites.
// NODE_PATH=/path/to/node_modules node tests/web_files_browser.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {chromium, firefox} = require("playwright");
const origin = "https://sync.example.test";
const root = path.join(__dirname, "../web");
const csp = fs.readFileSync(path.join(__dirname, "../src/server/web_status.rs"), "utf8").match(/const CSP: &str = "([^"]+)"/)[1];
const pdfCsp = fs.readFileSync(path.join(__dirname, "../src/server/web_status.rs"), "utf8").match(/const PDF_CSP: &str = "([^"]+)"/)[1];
const id = "a".repeat(64);
const screenshotDir = process.env.MYSYNC_SCREENSHOTS;
const content = Buffer.from("A verified file.\n");
const digest = crypto.createHash("sha256").update(content).digest("hex");
const pdfContent = (() => {
  let data = "%PDF-1.4\n";
  const offsets = [0];
  for (const [index, object] of [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << >> >>",
  ].entries()) {
    offsets.push(Buffer.byteLength(data));
    data += `${index + 1} 0 obj\n${object}\nendobj\n`;
  }
  const xref = Buffer.byteLength(data);
  data += `xref\n0 4\n0000000000 65535 f \n${offsets.slice(1).map(offset=>String(offset).padStart(10,"0")+" 00000 n \n").join("")}trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(data);
})();
const fixtureTime = Date.parse("2026-10-01T10:00:00Z")/1000;
const file = (name, size = content.length, revision = 1) => ({kind:"file", path:name, size, revision, sha256:digest, updated_at:fixtureTime+revision*60});
const fixtures = [
  file("Configurations/client.example.json",2048,6), file("Configurations/server.example.toml",2048,5), file("Documentation/configuration-du-client.pdf",612*1024,8),
  file("Projets/AgentSync/config.rs",7168,14), file("Versions/release.txt"),
  file("CHANGELOG.md",14*1024,12), file("Cargo.lock",86*1024,9), file("Cargo.toml",2048,16), file("LICENSE",35*1024),
  file("README.md",9216,24), file("architecture-technique.pdf",824*1024,18), file("configuration.example.toml",3072,7), file("notes-de-version.txt",6144,11),
];
function listing(entries, query) {
  const search=query.get("search") || "", directory=query.get("directory") || "", after=query.get("after") || "";
  const prefix=directory ? directory+"/" : "";
  const result=new Map();
  for (const entry of entries) {
    if (search) { if(entry.path.toLowerCase().includes(search.toLowerCase())) result.set(entry.path, entry); continue; }
    if (!entry.path.startsWith(prefix)) continue;
    const suffix=entry.path.slice(prefix.length), separator=suffix.indexOf("/");
    if(separator>=0) { const folder=prefix+suffix.slice(0,separator); result.set(folder,{kind:"directory",path:folder,size:(result.get(folder)?.size || 0)+entry.size,revision:null,sha256:null,updated_at:Math.max(result.get(folder)?.updated_at || 0,entry.updated_at || 0)}); }
    else result.set(entry.path,entry);
  }
  const key=e=>e.kind+":"+e.path;
  const sorted=[...result.values()].sort((a,b)=>key(a)<key(b)?-1:1).filter(e=>key(e)>after);
  return {entries:sorted.slice(0,200), next:sorted.length>200?key(sorted[199]):null};
}
async function run(type,name) {
  const executablePath=name==="chromium"?process.env.MYSYNC_CHROMIUM:process.env.MYSYNC_FIREFOX;
  // The PDF regressions need Chromium's built-in viewer, which is absent from
  // Playwright's default headless shell. This channel uses full Chromium headless.
  const browser=await type.launch({headless:true,...(name==="chromium"?{channel:"chromium"}:{firefoxUserPrefs:{"pdfjs.disabled":false}}),...(executablePath?{executablePath}:{})});
  console.log(`${name} ${browser.version()}`);
  let counter=0;
  async function setup(options={}) {
    const context=await browser.newContext({viewport:options.viewport || (options.mobile?{width:390,height:844}:{width:1240,height:823}), acceptDownloads:true, timezoneId:"Europe/Paris"});
    const page=await context.newPage();
    if(options.manual)await page.addInitScript(()=>localStorage.setItem("mysync-auto-access","off"));
    if(options.clock)await page.clock.install();
    const errors=[]; const violations=[];
    let navigations=0;
    page.on("framenavigated",frame=>{if(frame===page.mainFrame())navigations++;});
    const pendingListings=[];
    const releaseListings=()=>pendingListings.splice(0).forEach(resolve=>resolve());
    page.on("pageerror", e=>errors.push(e.message));
    page.on("console", msg=>{if(msg.type()==="error" && /Content Security Policy|Refused to|violates/.test(msg.text()))violations.push(msg.text());});
    let clockOffset=0;
    const now=()=>Math.floor((Date.now()+clockOffset)/1000);
    let authorized=options.authorized!==false, entries=options.entries || fixtures, expires=now()+1800;
    let writeExpires=expires, manageExpires=expires;
    const proofs=[];
    const completed=new Set();
    let mode=options.mode || "normal", calls=0, chunks=0, loggedOut=false, pdfs=0, sessionReads=0;
    let writeAuthorized=false, uploadChunks=0;
    let manageAuthorized=false;
    const mutations=[];
    const uploads=new Map(), uploaded=[], cancelled=[], pendingUploads=[];
    const releaseUploads=()=>pendingUploads.splice(0).forEach(resolve=>resolve());
    if(name==="chromium") await context.grantPermissions(["local-network-access"],{origin}).catch(()=>{});
    await context.route("http://127.0.0.1:47831/**",async route=>{
      const headers={"Access-Control-Allow-Origin":origin,"Access-Control-Allow-Headers":"X-MySync-Bridge, X-MySync-Challenge","Access-Control-Allow-Private-Network":"true"};
      if(route.request().method()==="OPTIONS") {await route.fulfill({status:204,headers});return;}
      if(mode==="denied" || mode==="offline") {await route.abort();return;}
      if(mode==="waiting") {await new Promise(resolve=>setTimeout(resolve,4500));await route.fulfill({status:401,headers,json:{error:"challenge_required"}}).catch(()=>{});return;}
      if(!route.request().headers()["x-mysync-challenge"]) {await route.fulfill({status:401,headers,json:{error:"challenge_required"}});return;}
      proofs.push(route.request().headers()["x-mysync-challenge"]);
      if(route.request().headers()["x-mysync-challenge"]==="upload-ticket") {
        if(mode==="write_disabled") {await route.fulfill({status:403,headers,json:{error:"files_write_disabled"}});return;}
        if(mode==="write_impostor") {await route.fulfill({headers,json:{challenge_id:id}});return;}
        writeAuthorized=true;writeExpires=expires;completed.add("upload-ticket");
        if(mode==="write_lost_ack") {await route.abort();return;}
        await route.fulfill({headers,json:{}});return;
      }
      if(route.request().headers()["x-mysync-challenge"]==="manage-ticket") {
        if(mode==="manage_disabled") {await route.fulfill({status:403,headers,json:{error:"files_manage_disabled"}});return;}
        if(mode==="manage_impostor") {await route.fulfill({headers,json:{}});return;}
        manageAuthorized=true;manageExpires=expires;completed.add("manage-ticket");
        if(mode==="manage_lost_ack") {await route.abort();return;}
        await route.fulfill({headers,json:{}});return;
      }
      if(mode==="disabled") {await route.fulfill({status:403,headers,json:{error:"files_read_disabled"}});return;}
      if(mode==="rejected" || mode==="misleading_rejection") {
        if(mode==="misleading_rejection") {authorized=true;completed.add("fixture-ticket");}
        await route.fulfill({status:403,headers,json:{error:"invalid_challenge"}});return;
      }
      if(mode!=="impostor") {authorized=true;expires=now()+1800;completed.add("fixture-ticket");}
      if(mode==="lost_ack") {await route.abort();return;}
      await route.fulfill({headers,json:{device_name:"Local impostor",challenge_id:"wrong"}});
    });
    if(mode==="denied")await page.addInitScript(()=>{navigator.permissions.query=async()=>({state:"denied"});});
    const assets={"/editor":["index.html","text/html"],"/editor.js":["editor.js","text/javascript"],"/editor.css":["editor.css","text/css"],"/files":["index.html","text/html"],"/status":["index.html","text/html"],"/atlas.js":["atlas.js","text/javascript"],"/status.js":["status.js","text/javascript"],"/status.css":["status.css","text/css"],"/atlas-icons.svg":["atlas-icons.svg","image/svg+xml"],"/atlas-brand.png":["atlas-brand.png","image/png"],"/atlas-brand-dark.png":["atlas-brand-dark.png","image/png"]};
    await context.route(`${origin}/**`,async route=>{
      const url=new URL(route.request().url());
      if(assets[url.pathname]) {
        const [asset,contentType]=assets[url.pathname];
        await route.fulfill({contentType,headers:{"Content-Security-Policy":csp,"Cache-Control":"no-store"},body:fs.readFileSync(path.join(root,asset))});return;
      }
      if(url.pathname.endsWith("/pdf")) {
        assert.equal(route.request().headers()["x-mysync-web"],undefined,"the PDF uses direct navigation");
        assert.equal(route.request().isNavigationRequest(),true);
        assert.equal(authorized,true);
        const entry=entries.find(entry=>entry.path===url.searchParams.get("path"));
        assert.ok(entry,"the complete PDF path is preserved");
        assert.equal(url.searchParams.get("revision"),String(entry.revision));
        pdfs++;
        await route.fulfill({contentType:"application/pdf",headers:{"Content-Disposition":"inline","Content-Security-Policy":pdfCsp,"Cache-Control":"no-store"},body:pdfContent});return;
      }
      assert.equal(route.request().headers()["x-mysync-web"],"1");
      if(url.pathname==="/v1/web/files/session" && route.request().method()==="GET")sessionReads++;
      const deadlines=[expires];
      if(writeAuthorized && writeExpires>now())deadlines.push(writeExpires);
      if(manageAuthorized && manageExpires>now())deadlines.push(manageExpires);
      const fileSession={device_name:"Approved fixture",expires_at:expires,renew_at:Math.min(...deadlines)-300,download_limit:268435456,chunk_bytes:8388608,...(!options.oldServer?{upload_limit:268435456,manage_limit:10000}:{})};
      if(/^\/v1\/web\/editor\/(edit|run)\/session$/.test(url.pathname)) {await route.fulfill({status:403,json:{error:url.pathname.includes("/edit/")?"files_edit_required":"code_run_required"}});return;}
      if(url.pathname.includes("/manage/")) {
        if(!authorized || expires<=now()) {await route.fulfill({status:401,json:{error:"session_expired"}});return;}
        if(url.pathname.endsWith("/challenges")) {completed.delete("manage-ticket");await route.fulfill({json:{challenge_id:id,ticket:"manage-ticket"}});return;}
        if(url.pathname.includes("/challenges/") && !completed.has("manage-ticket")) {await route.fulfill({status:202,json:{error:"pending"}});return;}
        await route.fulfill(manageAuthorized?{json:fileSession}:url.pathname.endsWith("/session")?{status:403,json:{error:"files_manage_required"}}:{status:202,json:{error:"pending"}});return;
      }
      if(url.pathname.startsWith("/v1/web/files/directories")) {
        if(!authorized || expires<=now()) {await route.fulfill({status:401,json:{error:"session_expired"}});return;}
        const input=route.request().method()==="GET"?{path:url.searchParams.get("path")}:route.request().postDataJSON();
        const children=entries.filter(entry=>entry.path.startsWith(input.path+"/"));
        if(!children.length) {await route.fulfill({status:404,json:{error:"directory_not_found"}});return;}
        const snapshot=crypto.createHash("sha256").update(JSON.stringify(children.map(e=>[e.path,e.revision]))).digest("hex");
        if(route.request().method()==="GET") {await route.fulfill({json:{path:input.path,size:children.reduce((sum,e)=>sum+e.size,0),file_count:children.length,updated_at:Math.max(...children.map(e=>e.updated_at)),snapshot}});return;}
        assert.equal(manageAuthorized,true,"management requires its own local authorization");
        if(input.snapshot!==snapshot || mode==="directory_changed") {await route.fulfill({status:409,json:{error:"directory_changed"}});return;}
        let target=input.path;
        if(url.pathname.endsWith("/rename")) {
          const slash=input.path.lastIndexOf("/");target=(slash>=0?input.path.slice(0,slash+1):"")+input.name;
          if(entries.some(e=>e.path===target || e.path.startsWith(target+"/"))) {await route.fulfill({status:409,json:{error:"directory_exists"}});return;}
          entries=entries.map(e=>children.includes(e)?{...e,path:target+e.path.slice(input.path.length),revision:e.revision+1}:e);
        } else entries=entries.filter(e=>!children.includes(e));
        mutations.push({action:url.pathname.split("/").pop(),path:input.path,target});
        if(mode==="mutation_lost_ack") {await route.abort();return;}
        await route.fulfill({json:{path:target,file_count:children.length}});return;
      }
      if(url.pathname.includes("/write/")) {
        if(!authorized || expires<=now()) {await route.fulfill({status:401,json:{error:"session_expired"}});return;}
        if(url.pathname.endsWith("/challenges")) {completed.delete("upload-ticket");await route.fulfill({json:{challenge_id:id,ticket:"upload-ticket"}});return;}
        if(url.pathname.includes("/challenges/") && !completed.has("upload-ticket")) {await route.fulfill({status:202,json:{error:"pending"}});return;}
        await route.fulfill(writeAuthorized?{json:fileSession}:url.pathname.endsWith("/session")?{status:403,json:{error:"files_write_required"}}:{status:202,json:{error:"pending"}});return;
      }
      if(url.pathname.startsWith("/v1/web/files/uploads")) {
        if(!authorized || expires<=now()) {await route.fulfill({status:401,json:{error:"session_expired"}});return;}
        assert.equal(writeAuthorized,true,"write authority precedes any upload");
        const method=route.request().method(), uploadId=url.pathname.split("/")[5];
        if(method==="POST" && !uploadId) {
          const value=route.request().postDataJSON();
          if(entries.some(e=>e.path===value.path)) {await route.fulfill({status:409,json:{error:"file_exists"}});return;}
          const uuid=crypto.randomUUID();uploads.set(uuid,{...value,parts:[],offset:0});
          await route.fulfill({json:{id:uuid,offset:0}});return;
        }
        const value=uploads.get(uploadId);
        if(!value) {await route.fulfill({status:404,json:{error:"upload_not_found"}});return;}
        if(method==="DELETE") {cancelled.push(uploadId);uploads.delete(uploadId);await route.fulfill({json:{}});return;}
        if(method==="PUT") {
          uploadChunks++;
          assert.equal(Number(url.searchParams.get("offset")),value.offset);
          const part=route.request().postDataBuffer();assert.ok(part.length<=8388608);
          if(mode==="upload_wait")await new Promise(resolve=>pendingUploads.push(resolve));
          value.parts.push(part);value.offset+=part.length;
          await route.fulfill({json:{id:uploadId,offset:value.offset}}).catch(()=>{});return;
        }
        if(url.pathname.endsWith("/commit")) {
          const bytes=Buffer.concat(value.parts);
          assert.equal(bytes.length,value.size);assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"),value.sha256);
          uploaded.push({...value,bytes});
          const entry={path:value.path,size:value.size,sha256:value.sha256,revision:42,deleted:false};
          entries=[...entries,{...entry,kind:"file",updated_at:fixtureTime}];uploads.delete(uploadId);
          if(mode==="upload_lost_commit") {await route.abort();return;}
          await route.fulfill({json:entry});return;
        }
        throw Error(`Unexpected upload request ${method} ${url.pathname}`);
      }
      if(url.pathname.endsWith("/logout")) {authorized=false;loggedOut=true;await route.fulfill({json:{}});return;}
      if(url.pathname.endsWith("/session") && route.request().method()==="POST") {loggedOut=false;await route.fulfill({json:{}});return;}
      if(url.pathname.endsWith("/challenges")) {completed.delete("fixture-ticket");await route.fulfill({json:{challenge_id:id,ticket:"fixture-ticket",expires_at:now()+60}});return;}
      if(url.pathname.endsWith(`/challenges/${id}`) && !completed.has("fixture-ticket")) {await route.fulfill({status:202,json:{error:"pending"}});return;}
      if(!authorized || expires<=now()) {await route.fulfill({status:401,json:{error:"session_expired"}});return;}
      if(url.pathname.endsWith("/session") || url.pathname.endsWith(`/challenges/${id}`)) {await route.fulfill({json:fileSession});return;}
      if(url.pathname.endsWith("/entries")) {
        calls++;
        if(mode==="held")await new Promise(resolve=>pendingListings.push(resolve));
        if(mode==="listing_error") {await route.fulfill({status:503,json:{error:"server_unavailable"}});return;}
        if(mode==="stale" && url.searchParams.get("search")==="README")await new Promise(resolve=>setTimeout(resolve,600));
        await route.fulfill({json:listing(entries,url.searchParams)}).catch(()=>{});return;
      }
      if(url.pathname.endsWith("/chunk")) {
        chunks++;assert.equal(url.searchParams.get("revision"),"1");
        if(mode==="changed")await route.fulfill({status:409,json:{error:"revision_changed"}});
        else if(mode==="download_wait") {await new Promise(resolve=>setTimeout(resolve,1000));await route.fulfill({body:content,contentType:"application/octet-stream"}).catch(()=>{});}
        else await route.fulfill({body:mode==="corrupt"?Buffer.alloc(content.length):content,contentType:"application/octet-stream"});
        return;
      }
      throw Error(`Unexpected URL ${url.pathname}`);
    });
    await page.goto(`${origin}/files`);
    if(authorized && !options.pending)await page.locator("#rows tr").first().waitFor({state:entries.length?"visible":"hidden"});
    async function capture(label) {
      if(screenshotDir){fs.mkdirSync(screenshotDir,{recursive:true});await page.screenshot({path:path.join(screenshotDir,`${name}-${label}.png`)});}
    }
    async function matrix(label, prepare = async () => {}) {
      const oldTheme = await page.locator("html").getAttribute("data-theme");
      const oldClosed = !(await page.locator("#sidebar").isVisible());
      for (const theme of ["light", "dark"]) {
        if (await page.locator("html").getAttribute("data-theme") !== theme) await page.locator("#theme-toggle").click();
        for (const closed of [false, true]) {
          if (!(await page.locator("#sidebar").isVisible()) !== closed) await page.locator("#sidebar-toggle").click();
          await prepare();
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${label}: no horizontal overflow`);
          for (const control of ["#theme-toggle", "#sidebar-toggle"]) {
            const box = await page.locator(control).boundingBox();
          assert.ok(box && box.x >= 0 && box.y >= 0 && box.x + box.width <= page.viewportSize().width);
          }
          await capture(`matrix-${label}-${theme}-${closed ? "closed" : "open"}`);
        }
      }
      if (await page.locator("html").getAttribute("data-theme") !== oldTheme) await page.locator("#theme-toggle").click();
      if (!(await page.locator("#sidebar").isVisible()) !== oldClosed) await page.locator("#sidebar-toggle").click();
    }
    async function finish(label) {
      assert.deepEqual(errors,[],"JavaScript errors");assert.deepEqual(violations,[],"CSP violations");
      releaseListings();releaseUploads();
      await context.close();console.log(`  ${++counter}. ${label}: passed`);
    }
    return {proofs,sessionReads:()=>sessionReads,advance:async ms=>{clockOffset+=ms;await page.clock.fastForward(ms);},page,context,capture,matrix,finish,releaseListings,releaseUploads,uploaded,cancelled,mutations,uploadChunks:()=>uploadChunks,setMode:v=>mode=v,setEntries:v=>entries=v,setAuthorized:v=>authorized=v,setExpiry:v=>expires=v,calls:()=>calls,chunks:()=>chunks,pdfs:()=>pdfs,loggedOut:()=>loggedOut,navigations:()=>navigations};
  }
  async function choose(page, files) {
    const [chooser]=await Promise.all([page.waitForEvent("filechooser"),page.locator("#upload-add").click()]);
    await chooser.setFiles(files);
  }
  async function drag(page, type, target="#drop-target", files=[{name:"incoming.txt",text:"hello"}], folder=false) {
    await page.evaluate(({type,target,files,folder})=>{
      const data=new DataTransfer();
      for(const file of files)data.items.add(new File([file.text],file.name,{type:"text/plain"}));
      const old=Object.getOwnPropertyDescriptor(DataTransferItem.prototype,"webkitGetAsEntry");
      if(folder)Object.defineProperty(DataTransferItem.prototype,"webkitGetAsEntry",{configurable:true,value:()=>({isDirectory:true})});
      document.querySelector(target).dispatchEvent(new DragEvent(type,{bubbles:true,cancelable:true,dataTransfer:data}));
      if(folder) {if(old)Object.defineProperty(DataTransferItem.prototype,"webkitGetAsEntry",old);else delete DataTransferItem.prototype.webkitGetAsEntry;}
    },{type,target,files,folder});
  }
  try {
    for(const viewport of [{width:1440,height:900},{width:390,height:844}]) {
      const t=await setup({viewport,entries:[file("Documents/a.txt",3),file("Documents/Sub/b.txt",5),file("Other/keep.txt")]});const {page}=t;
      const folder=page.getByRole("button",{name:"Documents",exact:true});
      await folder.click();
      assert.equal(await folder.getAttribute("aria-pressed"),"true");
      assert.equal(await page.locator("tr.selected").count(),1);
      assert.equal(await page.locator("#listing-title").textContent(),"Tous les fichiers");
      assert.equal(await page.locator("#details").isVisible(),false,"single-click only selects a directory");
      await folder.press("Space");assert.equal(await page.locator("#listing-title").textContent(),"Tous les fichiers");
      await page.getByRole("button",{name:"Actions pour Documents",exact:true}).click();
      for(const label of ["Renommer","Supprimer","Propriétés"])assert.equal(await page.getByRole("menuitem",{name:label,exact:true}).isVisible(),true);
      await page.getByRole("menuitem",{name:"Propriétés",exact:true}).click();
      await page.locator("#details").waitFor();
      assert.equal(await page.locator("#detail-count").textContent(),"2");
      assert.equal(await page.locator("#detail-size").textContent(),"8 o");
      assert.equal(await page.locator("#detail-hash-row").isVisible(),false);
      assert.equal(await page.locator("#detail-download").isVisible(),false);
      t.setEntries([file("Documents/a.txt",3),file("Documents/Sub/b.txt",5),file("Documents/new.txt",1),file("Other/keep.txt")]);
      // The refresh control stays reachable outside the narrow-screen overlay.
      if(viewport.width>1100) {
        await page.locator("#refresh").click();
        await page.waitForFunction(()=>document.querySelector("#detail-count").textContent==="3");
      }
      t.setEntries([file("Documents/a.txt",3),file("Documents/Sub/b.txt",5),file("Other/keep.txt")]);
      await page.locator("#details-close").click();
      await folder.dblclick();
      await page.waitForFunction(()=>document.querySelector("#listing-title").textContent==="Documents");
      await page.getByRole("button",{name:"Fichiers",exact:true}).click();
      await folder.press("Enter");
      await page.waitForFunction(()=>document.querySelector("#listing-title").textContent==="Documents");
      await page.getByRole("button",{name:"Fichiers",exact:true}).click();
      await page.getByRole("button",{name:"Actions pour Documents",exact:true}).click();
      await page.getByRole("menuitem",{name:"Renommer",exact:true}).click();
      await page.waitForFunction(()=>!document.querySelector("#folder-confirm").disabled);
      await page.locator("#folder-name").fill("Renamed");await page.locator("#folder-confirm").click();
      await page.getByRole("button",{name:"Renamed",exact:true}).waitFor();
      assert.equal(t.mutations[0].action,"rename");
      await page.getByRole("button",{name:"Actions pour Renamed",exact:true}).click();
      await page.getByRole("menuitem",{name:"Supprimer",exact:true}).click();
      await page.waitForFunction(()=>!document.querySelector("#folder-confirm").disabled);
      assert.match(await page.locator("#folder-description").textContent(),/2 fichiers/);
      await page.locator("#folder-cancel").click();assert.equal(t.mutations.length,1,"cancellation never submits a deletion");
      await page.getByRole("button",{name:"Actions pour Renamed",exact:true}).click();
      await page.getByRole("menuitem",{name:"Supprimer",exact:true}).click();
      await page.waitForFunction(()=>!document.querySelector("#folder-confirm").disabled);
      await page.locator("#folder-confirm").click();
      await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===1);
      assert.equal(t.mutations.length,2);assert.match(await page.locator("#rows").textContent(),/Other/);
      await t.finish(`directory selection, properties, rename and confirmed deletion at ${viewport.width}px`);
    }
    for(const mode of ["manage_disabled","manage_impostor","manage_lost_ack","directory_changed","mutation_lost_ack"]) {
      const t=await setup({mode,entries:[file("Documents/a.txt")]});const {page}=t;
      await page.getByRole("button",{name:"Actions pour Documents",exact:true}).click();
      await page.getByRole("menuitem",{name:"Renommer",exact:true}).click();
      await page.waitForFunction(()=>!document.querySelector("#folder-confirm").disabled);
      await page.locator("#folder-name").fill("Renamed");await page.locator("#folder-confirm").click();
      if(mode==="manage_lost_ack") {await page.getByRole("button",{name:"Renamed",exact:true}).waitFor();assert.equal(t.mutations.length,1);}
      else {
        await page.locator("#folder-error").waitFor();
        assert.equal(t.mutations.length,mode==="mutation_lost_ack"?1:0);
        if(mode==="manage_disabled")assert.equal(await page.locator("#folder-help").isVisible(),true);
        if(["directory_changed","mutation_lost_ack"].includes(mode))assert.equal(await page.locator("#folder-confirm").isDisabled(),true);
        await page.locator("#folder-cancel").click();
      }
      await t.finish(`directory management ${mode}`);
    }
    {
      const t=await setup({viewport:{width:1487,height:1058},entries:[
        file("Projets/Application/source.rs"),file("Projets/Documentation/guide.md"),file("Projets/Ressources/image.png"),
        file("Projets/README.md"),file("Projets/architecture-technique.pdf"),file("Projets/notes-projet.txt"),file("Projets/planning.csv")
      ]});const {page}=t;
      await page.getByRole("button",{name:"Projets",exact:true}).dblclick();
      await page.waitForFunction(()=>document.querySelector("#listing-title").textContent==="Projets");
      await drag(page,"dragenter");
      assert.equal(await page.locator("#drop-overlay").isVisible(),true);
      assert.match(await page.locator("#drop-path").textContent(),/Fichiers \/ Projets/);
      await drag(page,"dragenter","#rows tr:first-child");await drag(page,"dragleave","#rows tr:first-child");
      assert.equal(await page.locator("#drop-overlay").isVisible(),true,"nested drag events do not flicker");
      await t.capture("dragdrop-direct-light");
      await t.matrix("dragdrop",async()=>{if(!await page.locator("#drop-overlay").isVisible())await drag(page,"dragenter");});
      await page.keyboard.press("Escape");await drag(page,"drop");
      assert.equal(t.uploaded.length,0,"Escape cancels the drop");
      await drag(page,"dragenter");await drag(page,"drop");
      await page.waitForFunction(()=>!document.querySelector("#upload-close").hidden);
      assert.equal(t.uploaded[0].path,"Projets/incoming.txt");
      assert.equal(t.uploaded[0].bytes.toString(),"hello");
      await page.getByRole("button",{name:"incoming.txt",exact:true}).waitFor();
      assert.match(await page.locator("#rows").textContent(),/incoming.txt/);
      await t.finish("direct drop, nested enter/leave, Escape, target path and refresh");
    }
    for(const mode of ["normal","write_lost_ack"]) {
      const t=await setup({mode});const {page}=t;
      const files=[{name:"large.bin",mimeType:"application/octet-stream",buffer:Buffer.alloc(8388611,97)},
        {name:"empty.txt",mimeType:"text/plain",buffer:Buffer.alloc(0)},
        {name:"README.md",mimeType:"text/plain",buffer:Buffer.from("must not replace")}];
      await choose(page,files);
      await page.waitForFunction(()=>!document.querySelector("#upload-close").hidden);
      assert.equal(t.uploadChunks(),2,"8 MiB chunks, no chunk for an empty file");
      assert.equal(t.uploaded.length,2);
      assert.match(await page.locator("#upload-message").textContent(),/2 fichiers envoyés · 1 non envoyé/);
      assert.match(await page.locator("#upload-results").textContent(),/existant a été conservé/);
      await t.capture(`upload-${mode}`);await t.finish(`picker, multichunk, zero length, conflict and ${mode}`);
    }
    for(const mode of ["write_disabled","write_impostor","upload_lost_commit"]) {
      const t=await setup({mode});const {page}=t;
      await choose(page,{name:"sample.txt",mimeType:"text/plain",buffer:Buffer.from("test")});
      await page.waitForFunction(()=>!document.querySelector("#upload-close").hidden);
      assert.equal(t.uploaded.length,mode==="upload_lost_commit"?1:0);
      assert.match(await page.locator("#upload-status").textContent(),mode==="write_disabled"?/n’est pas autorisé/:mode==="write_impostor"?/pas été confirmée/:/non confirmé/);
      assert.equal(await page.locator("#upload-help").isVisible(),mode==="write_disabled");
      await t.finish(`upload ${mode}`);
    }
    for(const action of ["cancel","logout","expire","navigate"]) {
      const t=await setup({mode:"upload_wait"});const {page}=t;
      if(action==="expire") {await page.clock.install();t.setExpiry(Math.floor(Date.now()/1000)+2);await page.reload();await page.locator("#rows tr").first().waitFor();}
      await choose(page,{name:"pending.txt",mimeType:"text/plain",buffer:Buffer.from("pending")});
      await page.waitForFunction(()=>document.querySelector("#upload-message").textContent.startsWith("Envoi ·"));
      if(action==="cancel")await page.locator("#upload-cancel").click();
      if(action==="logout")await page.locator("#logout").click();
      if(action==="expire") {t.setMode("offline");await page.clock.fastForward(3000);}
      if(action==="navigate")await page.getByRole("button",{name:"Projets",exact:true}).dblclick();
      t.releaseUploads();
      if(["logout","expire"].includes(action)) {
        await page.locator("#access").waitFor();
        assert.equal(await page.locator("#upload-status").isVisible(),false);
        assert.equal(await page.locator("#upload-results").textContent(),"");
      } else {
        await page.waitForFunction(()=>!document.querySelector("#upload-close").hidden);
        if(action==="cancel") {assert.equal(t.cancelled.length,1);assert.match(await page.locator("#upload-message").textContent(),/annulé/);}
        if(action==="navigate") {assert.equal(t.uploaded[0].path,"pending.txt");assert.equal(await page.locator("#listing-title").textContent(),"Projets");}
      }
      if(action!=="navigate")assert.equal(t.uploaded.length,0);
      await t.finish(`upload ${action}`);
    }
    {
      const t=await setup();const {page}=t;
      await drag(page,"drop","#sidebar");assert.equal(t.uploaded.length,0);
      await drag(page,"drop","#drop-target",[{name:"folder",text:""}],true);
      assert.match(await page.locator("#toast-message").textContent(),/fichiers uniquement/);
      await page.locator("#search").fill("README");
      await page.waitForFunction(()=>document.querySelector("#listing-title").textContent==="Résultats de recherche");
      await drag(page,"dragenter");assert.equal(await page.locator("#drop-overlay").isVisible(),false);
      assert.equal(await page.locator("#upload-add").isDisabled(),true);
      assert.equal(t.navigations(),1,"dropping outside never navigates");
      await t.finish("folders and non-target drops refused, search has no ambiguous destination");
    }
    {
      const t=await setup({mobile:true,entries:[]});const {page}=t;
      await choose(page,{name:"first.txt",mimeType:"text/plain",buffer:Buffer.from("first")});
      await page.waitForFunction(()=>!document.querySelector("#upload-close").hidden);
      assert.equal(t.uploaded[0].path,"first.txt");
      for(const width of [320,390,760,1100]) {
        await page.setViewportSize({width,height:844});
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
        const box=await page.locator("#upload-add").boundingBox();assert.ok(box.x>=0&&box.x+box.width<=width);
      }
      await page.setViewportSize({width:390,height:844});await t.capture("dragdrop-mobile");
      await t.finish("empty folder, mobile picker and responsive upload controls");
    }
    {
      const t=await setup({oldServer:true});assert.equal(await t.page.locator("#upload-add").isDisabled(),true);
      await t.finish("read-only compatibility with previous servers");
    }
    {
      const t=await setup();const {page}=t;
      assert.equal(await page.locator("#rows tr").count(),12);
      assert.equal(await page.locator(".more-button").count(),12,"files and directories have action menus");
      assert.equal(await page.getByRole("button",{name:"Configurations",exact:true}).locator("xpath=ancestor::tr").locator("td").nth(1).textContent(),"4 Ko");
      assert.equal(await page.getByRole("button",{name:"Projets",exact:true}).locator("xpath=ancestor::tr").locator("td").nth(1).textContent(),"7 Ko");
      assert.equal(await page.locator("#file-table th").nth(2).textContent(),"Dernière modification");
      const folderTime=page.getByRole("button",{name:"Configurations",exact:true}).locator("xpath=ancestor::tr").locator("time");
      assert.equal(await folderTime.getAttribute("datetime"),"2026-10-01T10:06:00.000Z");
      assert.equal(await folderTime.textContent(),"01/10/2026 12:06");
      const readmeTime=page.getByRole("button",{name:"README.md",exact:true}).locator("xpath=ancestor::tr").locator("time");
      assert.equal(await readmeTime.getAttribute("datetime"),"2026-10-01T10:24:00.000Z");
      assert.equal(await readmeTime.textContent(),"01/10/2026 12:24");
      assert.equal(await page.locator(".toolbar #refresh").count(),1);
      assert.equal(await page.locator(".pagination #refresh").count(),0);
      await t.capture("12-menu-ouvert");
      await t.matrix("explorer");
      await page.locator("#sidebar-toggle").click();assert.equal(await page.locator("#sidebar").isVisible(),false);
      await t.capture("13-menu-ferme");
      await page.locator("#theme-toggle").click();assert.equal(await page.locator("html").getAttribute("data-theme"),"dark");
      await page.reload();await page.locator("#rows tr").first().waitFor();
      assert.equal(await page.locator("#sidebar").isVisible(),false);assert.equal(await page.locator("html").getAttribute("data-theme"),"dark");
      await page.locator("#sidebar-toggle").click();await page.locator("#theme-toggle").click();
      await page.getByRole("button",{name:"Actions pour architecture-technique.pdf",exact:true}).click();
      await t.capture("02-menu");
      await t.matrix("file-menu", async () => {
        if (!(await page.locator("#file-menu").isVisible())) await page.getByRole("button",{name:"Actions pour architecture-technique.pdf",exact:true}).click();
      });
      await page.getByRole("button",{name:"Actions pour architecture-technique.pdf",exact:true}).click();
      await page.keyboard.press("ArrowDown");await page.keyboard.press("Enter");
      assert.equal(await page.locator("#detail-name").textContent(),"architecture-technique.pdf");
      assert.equal(await page.locator("#detail-modified time").getAttribute("datetime"),"2026-10-01T10:18:00.000Z");
      assert.match(await page.locator("#detail-modified").textContent(),/1 octobre 2026.*12:18:00/);
      assert.equal(await page.locator("#detail-hash").textContent(),digest);await t.capture("03-details");
      await t.matrix("details");
      await page.keyboard.press("Escape");assert.equal(await page.locator("#details").isVisible(),false);
      await page.getByRole("button",{name:"Configurations",exact:true}).dblclick();
      await page.waitForFunction(()=>document.querySelector("#listing-title").textContent==="Configurations" && document.querySelectorAll("#rows tr").length===2);
      assert.match(await page.locator("#rows").textContent(),/client.example.json/);
      await page.locator("#breadcrumbs button").first().click();await page.locator("#rows tr").nth(11).waitFor();
      await page.locator("#search").fill("config");await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===5);
      await page.locator("#theme-toggle").click();await t.capture("04-recherche-sombre");
      await t.matrix("search");
      assert.ok(await page.locator("#rows mark").count()>0);
      await page.locator("#search").fill("absent");await page.locator("#empty").waitFor();await t.capture("07-sans-resultat");
      await t.matrix("no-result");
      await page.locator("#empty-reset").click();await page.locator("#rows tr").nth(11).waitFor();
      if (name === "chromium") {
        await t.context.grantPermissions(["clipboard-read", "clipboard-write"], {origin});
        await page.getByRole("button", {name:"Actions pour README.md",exact:true}).click();
        await page.getByRole("menuitem", {name:"Copier le chemin"}).click();
        await page.waitForFunction(() => document.querySelector("#toast-message").textContent === "Chemin copié.");
        assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "README.md");
      }
      await page.locator("#logout").click();await page.waitForFunction(()=>document.querySelector("#access-message").textContent==="Vous êtes déconnecté.");
      assert.equal(t.loggedOut(),true);assert.equal(await page.locator("#rows tr").count(),0);assert.equal(await page.locator("#search").inputValue(),"");
      assert.doesNotMatch(await page.locator("body").innerText(),/architecture-technique|client.example/);
      await t.finish("navigation, themes, menus, details, folder, search, logout");
    }
    for(const mode of ["normal","lost_ack","impostor","disabled","rejected","misleading_rejection","denied","waiting"]) {
      const t=await setup({authorized:false,mode,manual:true});const {page}=t;
      assert.equal(t.calls(),0);await t.capture(mode==="normal"?"05-verification":"access-"+mode);
      if(mode==="normal")await t.matrix("verification");
      await page.locator("#file-verify").click();
      if(mode==="normal" || mode==="lost_ack" || mode==="misleading_rejection") {await page.locator("#rows tr").first().waitFor();assert.equal(t.calls(),1);}
      else if(mode==="waiting") {await page.waitForFunction(()=>document.querySelector("#access-message").textContent.includes("En attente"));await page.locator("#file-cancel").click();await page.waitForFunction(()=>document.querySelector("#access-message").textContent.includes("annulée"));}
      else {await page.waitForFunction(()=>!document.querySelector("#file-verify").disabled);assert.equal(t.calls(),0);assert.equal(await page.locator("#rows tr").count(),0);if(mode==="disabled")assert.match(await page.locator("#access-title").textContent(),/non autorisée/);if(mode==="rejected") {assert.match(await page.locator("#access-title").textContent(),/Vérification locale refusée/);assert.doesNotMatch(await page.locator("body").innerText(),/architecture-technique|client.example/);}if(mode==="denied")assert.match(await page.locator("#access-title").textContent(),/refusée/);}
      if(mode==="denied")await t.capture("10-permission-refusee");
      if(mode==="denied" || mode==="disabled")await t.matrix(mode);
      await t.finish(`verification ${mode}`);
    }
    for (const mode of ["normal", "lost_ack", "impostor", "disabled", "rejected", "denied"]) {
      const t=await setup({authorized:false,mode});const {page}=t;
      if (["normal","lost_ack"].includes(mode)) {
        await page.locator("#rows tr").first().waitFor();
        assert.equal(t.calls(),1,"opening Atlas authorizes without a click");
        assert.equal(await page.locator("#session-time").textContent(),"Accès automatique");
        await page.locator("#logout").click();
        await page.waitForFunction(()=>document.querySelector("#access-message").textContent==="Vous êtes déconnecté.");
        const proofs=t.proofs.length;
        await page.reload();
        assert.equal(await page.locator("#rows tr").count(),0);
        assert.equal(t.proofs.length,proofs,"logout prevents automatic reconnect after reload");
        await page.locator("#file-verify").click();
        await page.locator("#rows tr").first().waitFor();
      } else {
        await page.waitForFunction(()=>!document.querySelector("#file-verify").disabled && document.querySelector("#access-message").textContent!=="Vérification en cours…");
        assert.equal(t.calls(),0);
        assert.equal(await page.locator("#rows tr").count(),0);
      }
      await t.finish(`automatic access ${mode}`);
    }
    {
      const t=await setup({clock:true});const {page}=t;
      await choose(page,{name:"before-renewal.txt",mimeType:"text/plain",buffer:Buffer.from("before")});
      await page.waitForFunction(()=>document.querySelector("#upload-message").textContent.includes("1 fichier envoyé"));
      const initialProofs=t.proofs.length;
      // Several deadlines, including the original cookie's 35-minute lifetime.
      for(let cycle=1;cycle<=3;cycle++) {
        const done=page.waitForResponse(r=>r.url().includes("/write/challenges/") && r.status()===200);
        await t.advance(25*60*1000);await done;
        await page.waitForResponse(r=>r.url().endsWith("/files/session") && r.request().method()==="GET");
        assert.equal(t.proofs.length,initialProofs+cycle*2,"read and write each renew with their own proof");
        assert.equal(await page.locator("#explorer").isVisible(),true);
        assert.equal(t.calls(),2,"renewal preserves the current view");
      }
      await t.advance(25*60*1000-5000);
      t.setMode("upload_wait");
      await choose(page,{name:"across-renewal.txt",mimeType:"text/plain",buffer:Buffer.from("across")});
      await page.waitForFunction(()=>document.querySelector("#upload-message").textContent.startsWith("Envoi ·"));
      const renewed=page.waitForResponse(r=>r.url().includes("/write/challenges/") && r.status()===200);
      await t.advance(5000);await renewed;
      t.releaseUploads();
      await page.waitForFunction(()=>document.querySelector("#upload-message").textContent.includes("1 fichier envoyé"));
      assert.equal(t.uploaded.length,2);
      await t.finish("renewals beyond 30 minutes preserve view, scopes and in-flight uploads");
    }
    {
      const t=await setup({clock:true});const {page}=t;
      t.setMode("offline");
      const failed=page.waitForResponse(r=>r.url().includes("/files/challenges/") && r.status()===202);
      // The mock retains the last valid lease, like the real server. A local
      // failure cannot extend it; the hard deadline still hides private data.
      await t.advance(25*60*1000);await failed;
      await t.advance(5*60*1000+1000);
      await page.waitForFunction(()=>document.querySelector("#access-title").textContent==="Session expirée");
      assert.equal(await page.locator("#rows tr").count(),0);
      t.setMode("normal");
      await page.evaluate(()=>document.dispatchEvent(new Event("visibilitychange")));
      await page.locator("#rows tr").first().waitFor();
      await t.finish("stopped client cannot extend access; returning to the tab reconnects automatically");
    }
    {
      const t=await setup({clock:true});
      const other=await t.context.newPage();
      await other.goto(`${origin}/files`);
      await other.locator("#rows tr").first().waitFor();
      const before=t.sessionReads();
      await t.advance(25*60*1000); // Playwright's clock is shared by the context.
      // Both tabs must finish: one checks, proves and rereads; the other
      // observes the renewed session under the same browser lock.
      const deadline=Date.now()+10000;
      while(t.sessionReads()<before+3 && Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,20));
      assert.ok(t.sessionReads()>=before+3);
      assert.deepEqual(t.proofs,["fixture-ticket"],"tabs share one renewal");
      await t.page.locator("#logout").click();
      await other.locator("#access").waitFor();
      assert.equal(await other.locator("#rows tr").count(),0);
      await other.reload();
      assert.equal(await other.locator("#rows tr").count(),0);
      await t.finish("simultaneous tabs share renewal and respect logout");
    }
    {
      const long="rapport-"+"documentation-".repeat(13)+"final.pdf";
      const unsafe="<img src=x onerror=alert(1)>.txt";
      const t=await setup({entries:[file(long),file(unsafe)],mobile:true});const {page}=t;
      assert.equal(await page.locator("#sidebar").isVisible(),false);
      assert.equal(await page.locator("#rows img").count(),0);
      await page.getByRole("button",{name:long,exact:true}).click();await page.locator("#details").waitFor();assert.equal(await page.locator("#detail-name").textContent(),long);
      await t.capture("09-nom-long-mobile");
      await t.matrix("long-name-mobile");
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
      await page.locator("#details-close").focus();
      for (let i=0;i<6;i++) {
        await page.keyboard.press("Tab");
        assert.equal(await page.evaluate(()=>document.querySelector(".file-list").contains(document.activeElement)),false,"covered rows must not receive keyboard focus");
      }
      await page.keyboard.press("Escape");
      t.setAuthorized(false);await page.locator("#refresh").click();await page.waitForFunction(()=>document.querySelector("#access-title").textContent==="Session expirée");
      assert.doesNotMatch(await page.locator("body").innerText(),/rapport-|onerror/);await t.capture("11-session-expiree-mobile");
      await t.finish("mobile, long names, text escaping, revoked session");
    }
    {
      const t=await setup({entries:[]});await t.page.locator("#empty").waitFor();await t.capture("08-espace-vide");
      await t.matrix("empty");
      assert.match(await t.page.locator("#empty-title").textContent(),/Aucun fichier/);await t.finish("empty space");
    }
    {
      const legacy=file("legacy.txt");delete legacy.updated_at;
      const t=await setup({entries:[legacy,{...file("unknown.txt"),updated_at:null}]});const {page}=t;
      assert.equal(await page.locator("#rows time").count(),0);
      for(const row of await page.locator("#rows tr").all())assert.equal(await row.locator("td").nth(2).textContent(),"—");
      await page.getByRole("button",{name:"legacy.txt",exact:true}).click();
      assert.equal(await page.locator("#detail-modified").textContent(),"—");
      await t.finish("missing modification dates remain unknown");
    }
    {
      const t=await setup();const {page}=t;
      const title=await page.locator("#listing-title").textContent();
      const rows=await page.locator("#rows").textContent();
      const listBounds=await page.locator("#file-table").boundingBox();
      t.setMode("held");
      await page.getByRole("button",{name:"Configurations",exact:true}).dblclick();
      await page.locator("#refresh.is-loading").waitFor();
      assert.equal(await page.locator("#rows").textContent(),rows,"keep the previous listing while waiting");
      assert.equal(await page.locator("#listing-title").textContent(),title,"commit title and rows together");
      assert.deepEqual(await page.locator("#file-table").boundingBox(),listBounds,"loading must not move or resize the list");
      assert.equal(await page.locator("#listing-message").isVisible(),false);
      assert.equal(await page.locator("#refresh").getAttribute("aria-disabled"),"true");
      await page.emulateMedia({reducedMotion:"reduce"});
      assert.equal(await page.locator("#refresh svg").evaluate(el=>getComputedStyle(el).animationName),"none");
      await t.capture("navigation-pending");
      t.setMode("normal");t.releaseListings();
      await page.waitForFunction(()=>document.querySelector("#listing-title").textContent==="Configurations");
      assert.equal(await page.locator("#rows tr").count(),2);
      assert.equal(await page.locator("#listing-title").evaluate(el=>el===document.activeElement),true,"navigation keeps focus in the file view");
      await page.locator("#files-nav").click();
      await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===12);
      assert.equal(t.navigations(),1,"the Files link must not reload the document");
      await page.getByRole("button",{name:"README.md",exact:true}).click();
      await page.evaluate(()=>{window.savedRow=document.querySelector("#rows tr");});
      t.setMode("held");await page.locator("#refresh").click();t.setMode("offline");
      await page.locator("#refresh.is-loading").waitFor();
      assert.equal(await page.locator("#details").isVisible(),true);
      t.setMode("normal");t.releaseListings();
      await page.waitForFunction(()=>document.querySelector("#refresh").getAttribute("aria-disabled")==="false");
      assert.equal(await page.evaluate(()=>window.savedRow===document.querySelector("#rows tr")),true,"unchanged refresh preserves DOM nodes");
      assert.equal(await page.locator("#details").isVisible(),true);
      assert.equal(await page.locator("#detail-name").textContent(),"README.md");
      const refreshedEntries=fixtures.map(entry=>entry.path==="README.md"?{...entry,size:2048,revision:25}:entry);
      t.setEntries(refreshedEntries);
      await page.locator("#refresh").click();
      await page.waitForFunction(()=>document.querySelector("#detail-revision").textContent==="25");
      assert.equal(await page.locator("#detail-size").textContent(),"2 Ko");
      assert.equal(await page.locator("#refresh").evaluate(el=>el===document.activeElement),true,"refresh must retain keyboard focus");
      t.setEntries(refreshedEntries.map(entry=>entry.path==="README.md"?{...entry,updated_at:fixtureTime+3600}:entry));
      await page.locator("#refresh").click();
      await page.waitForFunction(()=>document.querySelector("#detail-modified time")?.dateTime==="2026-10-01T11:00:00.000Z");
      assert.equal(await page.getByRole("button",{name:"README.md",exact:true}).locator("xpath=ancestor::tr").locator("time").textContent(),"01/10/2026 13:00","a date-only change must refresh the row");
      await page.locator("#details-close").click();
      t.setMode("listing_error");await page.getByRole("button",{name:"Configurations",exact:true}).dblclick();
      await page.locator("#listing-message").waitFor();
      assert.equal(await page.locator("#rows tr").count(),12,"a failed navigation keeps the previous view");
      assert.equal(await page.locator("#listing-title").textContent(),"Tous les fichiers");
      t.setMode("normal");await page.locator("#refresh").click();
      await page.waitForFunction(()=>document.querySelector("#listing-title").textContent==="Configurations");
      await page.locator(".brand").click();
      await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===12);
      assert.equal(t.navigations(),1,"the brand link must not reload the document");
      await t.finish("stable navigation, refresh, details and retry after failure");
    }
    for (const viewport of [{width:1920,height:1080},{width:1440,height:900},{width:1100,height:900},{width:768,height:1024},{width:760,height:900},{width:390,height:844},{width:320,height:740}]) {
      const t=await setup({viewport});const {page}=t;
      const inViewport=async selector=>{
        const box=await page.locator(selector).boundingBox();
        assert.ok(box && box.x>=0 && box.y>=0 && box.x+box.width<=viewport.width+1 && box.y+box.height<=viewport.height+1,`${selector} must remain reachable at ${viewport.width}px`);
      };
      for (const theme of ["light","dark"]) {
        if(await page.locator("html").getAttribute("data-theme")!==theme)await page.locator("#theme-toggle").click();
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,"no page overflow");
        for(const control of ["#search-box","#sidebar-toggle","#theme-toggle","#refresh"])await inViewport(control);
        assert.ok((await page.locator("#rows tr").first().locator("td").last().boundingBox()).width>=40,"actions retain their own column when dates are hidden");
        if(viewport.width<=760)assert.ok((await page.locator("#search-box").boundingBox()).width>=240,"mobile search has room for a useful query");
        await t.capture(`viewport-${viewport.width}-${theme}-list`);
        const entry=page.getByRole("button",{name:"README.md",exact:true});
        const row=entry.locator("xpath=ancestor::tr");
        await row.locator("td").nth(1).click();
        assert.equal(await entry.getAttribute("aria-expanded"),"true","row click opens the associated details");
        assert.equal(await page.locator("tr.selected").count(),1);
        assert.equal(await page.locator("#detail-name").textContent(),"README.md");
        for(const control of ["#details-close","#detail-download"])await inViewport(control);
        assert.equal(await page.locator(".file-list").evaluate(el=>el.inert),viewport.width<=1100,"overlay prevents focus on covered files");
        await t.capture(`viewport-${viewport.width}-${theme}-details`);
        if(viewport.width>480 && viewport.width<=1100)await page.locator("#details-dismiss").click({position:{x:8,y:80}});
        else await page.keyboard.press("Escape");
        assert.equal(await entry.getAttribute("aria-expanded"),"false");
        assert.equal(await entry.evaluate(el=>el===document.activeElement),true,"closing details restores file focus");
        assert.equal(await page.locator(".file-list").evaluate(el=>el.inert),false);
        await page.getByRole("button",{name:"Actions pour README.md",exact:true}).click();
        await inViewport("#file-menu");
        await t.capture(`viewport-${viewport.width}-${theme}-menu`);
        await page.keyboard.press("Escape");
        await page.locator("#search").fill("config");
        await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===5);
        await t.capture(`viewport-${viewport.width}-${theme}-search`);
        await page.locator("#clear-search").click();
        await page.locator("#rows tr").nth(11).waitFor();
      }
      await t.finish(`responsive list, search, menu and details at ${viewport.width}px`);
    }
    {
      const t=await setup({mode:"held",pending:true,mobile:true});const {page}=t;
      await page.locator("#refresh.is-loading").waitFor();
      assert.equal(await page.locator("#empty").isVisible(),false,"initial loading cannot claim the space is empty");
      assert.match(await page.locator("#count").textContent(),/Chargement/);
      const initialTableTop=(await page.locator("#file-table").boundingBox()).y;
      await t.capture("initial-loading-mobile");
      t.setMode("listing_error");t.releaseListings();
      await page.locator("#listing-message").waitFor();
      assert.match(await page.locator("#count").textContent(),/indisponible/);
      await t.capture("initial-error-mobile");
      t.setMode("normal");await page.locator("#refresh").click();
      await page.locator("#rows tr").nth(11).waitFor();
      assert.equal((await page.locator("#file-table").boundingBox()).y,initialTableTop,"initial loading reserves the breadcrumb height");
      t.setMode("listing_error");await page.locator("#refresh").click();
      await page.locator("#listing-message").waitFor();
      assert.equal(await page.locator("#rows tr").count(),12);
      await t.capture("refresh-error-mobile");
      await t.finish("initial loading, visible errors and recovery on mobile");
    }
    {
      const folders=["Archives-"+"documentation-".repeat(5),"Rapports-"+"synchronisation-".repeat(4),"2026"];
      const long="rapport-"+"documentation-".repeat(13)+"final.pdf";
      const fullPath=[...folders,long].join("/");
      const t=await setup({mobile:true,entries:[file(fullPath)]});const {page}=t;
      for(const folder of folders) {
        await page.getByRole("button",{name:folder,exact:true}).dblclick();
        await page.waitForFunction(title=>document.querySelector("#listing-title").textContent===title,folder);
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,"deep paths stay within the page");
      }
      assert.equal(await page.locator("#breadcrumbs [aria-current=page]").textContent(),"2026");
      assert.equal(await page.locator("#breadcrumbs button").nth(1).getAttribute("title"),folders[0]);
      await t.capture("deep-path-mobile");
      await page.getByRole("button",{name:long,exact:true}).click();
      await page.locator("#details").waitFor();
      assert.equal(await page.locator("#detail-path").textContent(),fullPath,"details retain the complete path");
      const download=await page.locator("#detail-download").boundingBox();
      assert.ok(download && download.y+download.height<=844,"long names cannot push the download off screen");
      await t.capture("deep-path-mobile-details");
      await page.locator(".details-content").evaluate(el=>{el.scrollTop=el.scrollHeight;});
      const hash=await page.locator("#detail-hash").boundingBox();
      assert.ok(hash && hash.y>=0 && hash.y+hash.height<=download.y,"all metadata is reachable independently of the action");
      await t.capture("deep-path-mobile-metadata");
      await page.setViewportSize({width:1440,height:900});
      await page.waitForFunction(()=>!document.querySelector(".file-list").inert);
      await page.setViewportSize({width:768,height:1024});
      await page.waitForFunction(()=>document.querySelector(".file-list").inert);
      await page.locator("#details-close").click();
      assert.equal(await page.locator("#details-dismiss").isVisible(),false);
      await t.finish("deep breadcrumbs, long details and resizing between panel modes");
    }
    {
      const t=await setup({entries:Array.from({length:201},(_,i)=>file(`page-${String(i).padStart(3,"0")}.txt`))});const {page}=t;
      assert.equal(await page.locator("#rows tr").count(),200);await page.locator("#next-page").click();
      await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===1);assert.match(await page.locator("#rows").textContent(),/page-200/);
      await page.locator("#refresh").click();
      await page.waitForFunction(()=>document.querySelector("#refresh").getAttribute("aria-disabled")==="false");
      assert.equal(await page.locator("#rows tr").count(),1,"refresh keeps the current page");
      assert.match(await page.locator("#count").textContent(),/page 2/);
      await page.locator("#previous-page").click();await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===200);await t.finish("pagination");
    }
    {
      const t=await setup({mode:"stale"});const {page}=t;
      await page.locator("#search").fill("README");await page.waitForTimeout(250);await page.locator("#search").fill("Cargo");
      await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===2);await page.waitForTimeout(700);
      assert.doesNotMatch(await page.locator("#rows").textContent(),/README/);await t.finish("stale search responses");
    }
    {
      const pdfName="rapport été #1.PDF";
      const t=await setup({entries:[file(`Documents/${pdfName}`,pdfContent.length,7),file("sample.txt"),file("too-large.pdf",268435457)]});
      const {page,context}=t;
      let downloaded=false;context.on("page",popup=>popup.on("download",()=>downloaded=true));
      await page.getByRole("button",{name:"sample.txt",exact:true}).dblclick();
      assert.equal(context.pages().length,1,"other files keep their details behavior");
      await page.locator("#details-close").click();
      await page.getByRole("button",{name:"too-large.pdf",exact:true}).dblclick();
      assert.match(await page.locator("#toast-message").textContent(),/256 Mio/);
      assert.equal(context.pages().length,1,"oversized PDFs do not open a new tab");
      await page.locator("#details-close").click();
      await page.getByRole("button",{name:"Documents",exact:true}).dblclick();
      const entry=page.getByRole("button",{name:pdfName,exact:true});
      await entry.click();
      assert.equal(context.pages().length,1,"a single click still opens the details");
      const before=t.navigations();
      const opened=context.waitForEvent("page");
      await entry.dblclick();
      const popup=await opened;
      await popup.waitForURL(url=>url.pathname==="/v1/web/files/pdf");
      const url=new URL(popup.url());
      assert.equal(url.searchParams.get("path"),`Documents/${pdfName}`);
      assert.equal(url.searchParams.get("revision"),"7");
      if(name==="firefox") await popup.locator("#viewerContainer .page canvas").waitFor();
      else {
        const viewerUrl=url=>url.startsWith("chrome-extension://");
        let viewer=popup.frames().find(frame=>viewerUrl(frame.url()));
        if(!viewer) viewer=await popup.waitForEvent("framenavigated",{predicate:frame=>viewerUrl(frame.url())});
        await viewer.locator("pdf-viewer").waitFor();
      }
      assert.equal(await popup.evaluate(()=>window.opener===null),true,"the PDF tab has no access to Atlas");
      assert.equal(downloaded,false,"the browser displays the PDF inline");
      assert.equal(t.navigations(),before,"Atlas stays on the current folder");
      assert.equal(t.chunks(),0,"opening does not assemble a download in JavaScript");
      assert.equal(t.pdfs(),1);
      await t.finish("PDF double-click opens a direct URL in an isolated tab");
    }
    for(const width of [1100,390]) {
      const t=await setup({viewport:{width,height:900},entries:[file("report.pdf",pdfContent.length)]});
      const {page,context}=t;
      const entry=page.getByRole("button",{name:"report.pdf",exact:true});
      await entry.click();
      await page.locator("#details").waitFor();
      assert.equal(await page.locator(".file-list").evaluate(el=>el.inert),true);
      await page.locator("#details-close").click();
      const opened=context.waitForEvent("page");
      await entry.locator("xpath=ancestor::tr").locator("td").nth(1).dblclick();
      const popup=await opened;
      await popup.waitForURL(url=>url.pathname==="/v1/web/files/pdf");
      await page.waitForTimeout(600);
      assert.equal(await page.locator("#details").isVisible(),false,"the overlay cannot interrupt a PDF double-click");
      assert.equal(t.pdfs(),1);
      await t.finish(`PDF double-click on the row at ${width}px`);
    }
    for(const mode of ["normal","corrupt","changed","download_wait"]) {
      const t=await setup({entries:[file("sample.txt")],mode});const {page}=t;
      await page.getByRole("button",{name:"sample.txt",exact:true}).click();
      let received=false;page.on("download",()=>received=true);
      const downloading=mode==="normal"?page.waitForEvent("download"):undefined;
      await page.locator("#detail-download").click();
      if(mode==="download_wait") {await page.locator("#download-cancel").click();await page.waitForFunction(()=>document.querySelector("#toast-message").textContent.includes("annulé"));}
      else if(mode==="normal") {const download=await downloading;assert.equal(download.suggestedFilename(),"sample.txt");const stream=await download.createReadStream();const chunks=[];for await(const chunk of stream)chunks.push(chunk);assert.deepEqual(Buffer.concat(chunks),content);await t.capture("06-telechargement");}
      else {await page.waitForFunction(()=>document.querySelector("#download-cancel").hidden);assert.equal(received,false);assert.match(await page.locator("#toast-message").textContent(),mode==="corrupt"?/empreinte/:/changé/);}
      await t.finish(`download ${mode}`);
    }
    {
      const t=await setup();const {page}=t;
      await page.clock.install();t.setExpiry(Math.floor(Date.now()/1000)+2);await page.reload();await page.locator("#rows tr").first().waitFor();
      t.setMode("held");await page.locator("#refresh").click();
      await page.clock.fastForward(3000);await page.waitForFunction(()=>document.querySelector("#access-title").textContent==="Session expirée");
      t.setMode("normal");t.releaseListings();await page.clock.runFor(100);
      assert.equal(await page.locator("#rows tr").count(),0);await t.capture("11-session-expiree");await t.matrix("expired");await t.finish("automatic session expiry");
    }
  } finally {await browser.close();}
}
(async()=>{
  if(process.env.MYSYNC_BROWSER!=="firefox")await run(chromium,"chromium");
  if(process.env.MYSYNC_BROWSER!=="chromium")await run(firefox,"firefox");
})().catch(e=>{console.error(e);process.exitCode=1;});
