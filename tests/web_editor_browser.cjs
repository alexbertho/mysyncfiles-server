// Atlas editor regressions. The backend is simulated; Rust covers TPM authority
// and the sandbox. NODE_PATH=/path/to/node_modules node tests/web_editor_browser.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {chromium, firefox} = require("playwright");
const origin = "https://sync.example.test";
const root = path.join(__dirname, "../web");
const csp = fs.readFileSync(path.join(__dirname,"../src/server/web_status.rs"),"utf8").match(/const CSP: &str = "([^"]+)"/)[1];
const hash = value => crypto.createHash("sha256").update(value).digest("hex");
const sample = 'def calculer_total(valeurs):\n    total = 0\n    for valeur in valeurs:\n        total += valeur\n    return total\n\nvaleurs = [4, 8, 15, 16, 23, 42]\nresultat = calculer_total(valeurs)\nprint(f"Somme : {resultat}")\n';
const readCode = async page => (await page.locator("#code-input .cm-line").allTextContents()).join("\n");
async function replaceCode(page, text) {
  const input = page.locator("#code-input");
  await input.press("Control+a");
  await input.press("Backspace");
  if (text) await page.keyboard.insertText(text);
}
async function suite(type, name) {
  const executablePath = name === "chromium" ? process.env.MYSYNC_CHROMIUM : process.env.MYSYNC_FIREFOX;
  const browser = await type.launch({headless:true, ...(executablePath ? {executablePath} : {})});
  console.log(`${name} ${browser.version()}`);
  async function setup(options={}) {
    const context = await browser.newContext({viewport:options.viewport || {width:1487,height:1058}, acceptDownloads:true});
    const page = await context.newPage(), errors = [], violations = [], saves = [], starts = [], tickets = new Map(), pending = [];
    if(options.clock)await page.clock.install();
    let clockOffset=0;
    const now=()=>Math.floor((Date.now()+clockOffset)/1000), proofs=[];
    let expires=now()+1800, editExpires=expires, runExpires=expires;
    const file = options.path || "Projets/Exemples/calcul.py";
    let content = options.content ?? sample, revision=1, mode=options.mode || "normal", edit=false, run=false, currentRun, reads=0;
    const release = () => pending.splice(0).forEach(r=>r());
    const entry = () => ({path:file, revision, sha256:hash(content), size:Buffer.byteLength(content), deleted:false});
    const session = () => ({device_name:"test-device", expires_at:expires,renew_at:Math.min(expires,edit?editExpires:expires,run?runExpires:expires)-300,chunk_bytes:8388608,download_limit:268435456});
    page.on("pageerror",e=>errors.push(e.message));
    page.on("console",m=>{if(m.type()==="error" && /Content Security Policy|Refused to|violates/.test(m.text())) violations.push(m.text());});
    if (name==="chromium") await context.grantPermissions(["local-network-access"],{origin}).catch(()=>{});
    await context.route("http://127.0.0.1:47831/**",async route=>{
      const req=route.request(), url=new URL(req.url());
      const headers={"Access-Control-Allow-Origin":origin,"Access-Control-Allow-Headers":"X-MySync-Bridge, X-MySync-Challenge, Content-Type","Access-Control-Allow-Methods":"GET, POST, OPTIONS","Access-Control-Allow-Private-Network":"true"};
      const reply = (json,status=200) => route.fulfill({headers,status,json}).catch(()=>{});
      if(req.method()==="OPTIONS") {await route.fulfill({status:204,headers});return;}
      if(mode==="offline") {await route.abort();return;}
      if(url.pathname==="/v1/status") {
        const scope=req.headers()["x-mysync-challenge"];
        proofs.push(scope);
        if(scope==="edit-ticket") {
          if(mode==="edit_denied") {await reply({error:"files_edit_disabled"},403);return;}
          edit=true;editExpires=expires;
        } else if(scope==="run-ticket") {
          if(mode==="run_denied") {await reply({error:"code_run_disabled"},403);return;}
          run=true;runExpires=expires;
        } else if(scope==="read-ticket") {
          expires=now()+1800;
        }
        await reply({});return;
      }
      assert.equal(url.pathname,"/v1/editor");
      const ticket=req.postDataJSON().ticket, op=tickets.get(ticket);
      assert.ok(op,"issued ticket required");tickets.delete(ticket);
      if(op.action==="tools") {await reply({python:mode!=="missing",compiler:mode==="missing"?null:"gcc",isolation:mode!=="sandbox_missing"});return;}
      if(op.action==="start") {
        if(mode==="start_error") {await reply({error:"runner_authorization_refused"},403);return;}
        assert.equal(op.revision,revision);assert.equal(op.sha256,hash(content));
        starts.push({op,content});
        currentRun={job_id:op.job_id,sha256:op.sha256,state:"running",compilation:null,execution:null};
      } else {
        assert.equal(op.job_id,currentRun.job_id);
        currentRun={...currentRun,state:op.action==="stop"?"stopped":mode==="keep_running"?"running":mode==="compile_error"?"compile_failed":mode==="runtime_error"?"failed":mode==="timeout"?"timeout":"finished",
          compilation:file.endsWith(".c")?{stdout:"",stderr:mode==="compile_error"?"error: expected expression":"",exit_code:mode==="compile_error"?1:0,duration_ms:41}:null,
          execution:mode==="compile_error"?null:{stdout:options.stdout ?? "Somme : 108\n",stderr:mode==="runtime_error"?"ValueError: test":"",exit_code:mode==="runtime_error"?7:0,duration_ms:24}};
      }
      await reply(currentRun);
    });
    await context.route(`${origin}/**`,async route=>{
      const req=route.request(), url=new URL(req.url());
      const asset=["/files","/editor","/status"].includes(url.pathname)?"index.html":url.pathname.slice(1);
      if(["index.html","atlas.js","status.js","editor.js","editor.css","status.css","atlas-icons.svg","atlas-brand.png","atlas-brand-dark.png"].includes(asset)) {
        const mime=asset.endsWith(".html")?"text/html":asset.endsWith(".js")?"text/javascript":asset.endsWith(".css")?"text/css":asset.endsWith(".svg")?"image/svg+xml":"image/png";
        await route.fulfill({contentType:mime,headers:{"Content-Security-Policy":csp},body:fs.readFileSync(path.join(root,asset))});return;
      }
      if(url.pathname==="/v1/web/files/session") {await route.fulfill({json:session()});return;}
      if(url.pathname==="/v1/web/files/challenges") {await route.fulfill({json:{challenge_id:"a".repeat(64),ticket:"read-ticket"}});return;}
      if(url.pathname.startsWith("/v1/web/files/challenges/")) {await route.fulfill({json:session()});return;}
      if(/^\/v1\/web\/files\/(write|manage)\/session$/.test(url.pathname)) {await route.fulfill({status:403,json:{error:url.pathname.includes("/write/")?"files_write_required":"files_manage_required"}});return;}
      if(url.pathname==="/v1/web/files/entries") {
        const folder=url.searchParams.get("directory")||"", prefix=folder?folder+"/":"";
        const rest=file.slice(prefix.length), next=rest.split("/")[0];
        const entries=file.startsWith(prefix)?[rest.includes("/")?{kind:"directory",path:prefix+next,size:100,revision:null,sha256:null,updated_at:1}:{...entry(),kind:"file",updated_at:1}]:[];
        await route.fulfill({json:{entries,next:null}});return;
      }
      if(url.pathname==="/v1/web/editor/file") {
        if(req.method()==="GET") {reads++;await route.fulfill({json:{entry:entry(),content}});return;}
        assert.equal(edit,true,"editing requires its own authority");
        const value=req.postDataJSON();saves.push(value);
        if(mode==="hold")await new Promise(r=>pending.push(r));
        if(mode==="conflict" || value.base_revision!==revision) {await route.fulfill({status:409,json:{error:"revision_changed"}}).catch(()=>{});return;}
        if(mode==="save_error") {await route.fulfill({status:503,json:{error:"server_unavailable"}});return;}
        content=value.content;revision++;
        if(mode==="lost_ack") {await route.abort();return;}
        await route.fulfill({json:entry()}).catch(()=>{});return;
      }
      const match=url.pathname.match(/^\/v1\/web\/editor\/(edit|run)\/(session|challenges)(\/.*)?$/);
      if(match) {
        const allowed=match[1]==="edit"?edit:run;
        if(match[2]==="challenges" && !match[3]) {await route.fulfill({json:{challenge_id:"a".repeat(64),ticket:`${match[1]}-ticket`}});return;}
        await route.fulfill(allowed?{json:{}}:{status:match[3]?202:403,json:{error:match[3]?"pending":match[1]==="edit"?"files_edit_required":"code_run_required"}});return;
      }
      if(url.pathname==="/v1/web/editor/tickets") {
        assert.equal(run,true,"execution requires its own authority");
        const token=crypto.randomBytes(32).toString("hex");tickets.set(token,req.postDataJSON());await route.fulfill({json:{ticket:token}});return;
      }
      throw Error(`Unexpected ${req.method()} ${url.pathname}`);
    });
    await page.goto(`${origin}/editor?${new URLSearchParams({path:file,directory:file.slice(0,file.lastIndexOf("/"))})}`);
    await page.waitForFunction(()=>!document.querySelector("#editor-tool").textContent.includes("en cours"));
    async function finish(label) {release();assert.deepEqual(errors,[]);assert.deepEqual(violations,[]);await context.close();console.log(`  ${label}: passed`);}
    async function capture(label) {if(process.env.MYSYNC_SCREENSHOTS){fs.mkdirSync(process.env.MYSYNC_SCREENSHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.MYSYNC_SCREENSHOTS,`${name}-editor-${label}.png`)});}}
    return {proofs,advance:async ms=>{clockOffset+=ms;await page.clock.fastForward(ms);},page,context,saves,starts,release,finish,capture,setMode:v=>mode=v,setRemote:v=>{content=v;revision++;},reads:()=>reads};
  }
  try {
    {
      const t=await setup({clock:true,mode:"keep_running"}),p=t.page;
      await t.advance(25*60*1000-3000);
      await replaceCode(p,"print('renewed')");
      await p.waitForFunction(()=>document.querySelector("#editor-save-state").textContent==="Enregistré");
      await p.locator("#editor-run").click();
      await p.waitForFunction(()=>document.querySelector("#editor-run").textContent.includes("Arrêter"));
      const renewed=p.waitForResponse(r=>r.url().includes("/run/challenges/") && r.status()===200);
      await t.advance(3000);await renewed;
      assert.deepEqual(t.proofs,["edit-ticket","run-ticket","read-ticket","edit-ticket","run-ticket"]);
      assert.equal(await readCode(p),"print('renewed')");
      assert.equal(await p.locator("#code-input").getAttribute("contenteditable"),"true");
      assert.equal(await p.locator("#code-editor").isVisible(),true);
      assert.match(await p.locator("#editor-run").textContent(),/Arrêter/);
      assert.equal(t.starts.length,1,"renewal must not restart a running program");
      assert.equal(t.reads(),1,"renewal must not replace the open editor buffer");
      await t.finish("automatic renewal preserves editing, buffer and running program");
    }
    {
      const t=await setup({content:"if ready:"}),p=t.page,input=p.locator("#code-input");
      await input.press("Control+End");await p.keyboard.press("Enter");
      assert.equal(await readCode(p),"if ready:\n    ");
      await p.keyboard.press("Tab");assert.equal(await readCode(p),"if ready:\n        ");
      await p.keyboard.press("Shift+Tab");assert.equal(await readCode(p),"if ready:\n    ");
      await p.keyboard.press("Backspace");assert.equal(await readCode(p),"if ready:\n");
      await p.keyboard.press("Control+z");assert.equal(await readCode(p),"if ready:\n    ");
      await p.keyboard.press("Control+Shift+Z");assert.equal(await readCode(p),"if ready:\n");
      await p.keyboard.press("Escape");await p.keyboard.press("Tab");
      assert.equal(await p.locator("#editor-goto").evaluate(e=>e===document.activeElement),true);
      await t.finish("Python automatic indentation, tab stops, smart backspace, history and keyboard escape");
    }
    {
      const source="first = 1\nsecond = 2\n",t=await setup({content:source}),p=t.page,input=p.locator("#code-input");
      await input.press("Control+a");await p.keyboard.press("Tab");
      assert.equal(await readCode(p),"    first = 1\n    second = 2\n");
      await p.keyboard.press("Shift+Tab");assert.equal(await readCode(p),source);
      await p.keyboard.press("Control+Home");await p.keyboard.press("Alt+ArrowDown");
      assert.equal(await readCode(p),"second = 2\nfirst = 1\n");
      await p.keyboard.press("Alt+Shift+ArrowDown");
      assert.equal(await readCode(p),"second = 2\nfirst = 1\nfirst = 1\n");
      await input.press("Control+a");await p.keyboard.press("Control+/");
      assert.equal(await readCode(p),"# second = 2\n# first = 1\n# first = 1\n");
      await p.keyboard.press("Control+/");assert.equal(await readCode(p),"second = 2\nfirst = 1\nfirst = 1\n");
      await t.finish("block indentation, move and duplicate lines, Python comments");
    }
    {
      const t=await setup({content:""}),p=t.page,input=p.locator("#code-input");
      await input.focus();await p.keyboard.type("(");assert.equal(await readCode(p),"()");
      await p.keyboard.press("Backspace");assert.equal(await readCode(p),"");
      await p.keyboard.type("[1]");assert.equal(await readCode(p),"[1]");
      await replaceCode(p,"");await p.keyboard.type('"hello"');assert.equal(await readCode(p),'"hello"');
      await replaceCode(p,"value");await input.press("Control+a");await p.keyboard.type("(");
      assert.equal(await readCode(p),"(value)");
      await t.finish("paired brackets and quotes, paired deletion, skipping closers and surrounding a selection");
    }
    {
      const t=await setup({path:"Projets/example.c",content:"int main(void) {}"}),p=t.page,input=p.locator("#code-input");
      await input.press("Control+End");await p.keyboard.press("ArrowLeft");await p.keyboard.press("Enter");
      assert.equal(await readCode(p),"int main(void) {\n    \n}");
      await p.keyboard.type("return 0;");await p.keyboard.press("Control+/");
      assert.equal(await readCode(p),"int main(void) {\n    // return 0;\n}");
      await p.locator("#editor-indent").selectOption("2");
      await input.press("Control+Home");await p.keyboard.press("Tab");
      assert.match(await readCode(p),/^  int/);
      await p.keyboard.press("Control+s");
      await p.waitForFunction(()=>document.querySelector("#editor-save-state").textContent==="Enregistré");
      assert.equal(t.saves.at(-1).content,await readCode(p));
      await t.finish("C brace indentation, comments, configurable tab width and explicit save");
    }
    {
      const t=await setup({content:"pri"}),p=t.page,input=p.locator("#code-input");
      await input.press("Control+End");await p.keyboard.press("Control+Space");
      await p.locator(".cm-completionLabel").filter({hasText:/^print$/}).click();
      assert.equal(await readCode(p),"print");
      await replaceCode(p,"def");await p.keyboard.press("Control+Space");
      await p.getByRole("option").filter({hasText:"Fonction"}).click();
      assert.equal(await readCode(p),"def nom(arguments):\n    pass");
      await p.keyboard.type("greet");await p.keyboard.press("Tab");await p.keyboard.type("name");
      assert.equal(await readCode(p),"def greet(name):\n    pass");
      await t.finish("local Python completion and snippets with editable tab stops");
    }
    {
      const t=await setup({path:"Projets/example.c",content:"mai"}),p=t.page,input=p.locator("#code-input");
      await input.press("Control+End");await p.keyboard.press("Control+Space");
      await p.getByRole("option").filter({hasText:"Point d’entrée"}).click();
      assert.equal(await readCode(p),"int main(void) {\n    \n    return 0;\n}");
      await t.finish("C completion and main snippet");
    }
    {
      const t=await setup({content:"total = 1\nTOTAL = 2\nsubtotal = 3\n"}),p=t.page;
      await p.locator("#editor-find").click();
      await p.locator('input[name="search"]').fill("total");
      await p.locator('input[name="replace"]').fill("sum");
      await p.locator('input[name="case"]').check();await p.locator('input[name="word"]').check();
      await p.locator('button[name="replaceAll"]').click();
      assert.equal(await readCode(p),"sum = 1\nTOTAL = 2\nsubtotal = 3\n");
      await p.locator('input[name="word"]').uncheck();await p.locator('input[name="re"]').check();
      await p.locator('input[name="search"]').fill("[0-9]+");await p.locator('input[name="replace"]').fill("0");
      await p.locator('button[name="replaceAll"]').click();
      assert.equal(await readCode(p),"sum = 0\nTOTAL = 0\nsubtotal = 0\n");
      await p.locator('button[name="close"]').click();await p.locator("#editor-goto").click();
      await p.locator('input[name="line"]').fill("3");await p.locator('input[name="line"]').press("Enter");
      assert.match(await p.locator("#editor-position").textContent(),/^Ln 3, Col 1/);
      await t.finish("French search and replace, case, whole words, regular expressions and go to line");
    }
    {
      const t=await setup({content:"value = 1\nprint(value)\n"}),p=t.page,input=p.locator("#code-input");
      await input.press("Control+Home");await p.keyboard.press("Control+d");await p.keyboard.press("Control+d");
      assert.match(await p.locator("#editor-position").textContent(),/2 curseurs/);
      await p.keyboard.type("number");assert.equal(await readCode(p),"number = 1\nprint(number)\n");
      await t.finish("multiple cursors replace the next occurrence together");
    }
    {
      const t=await setup(),p=t.page;
      assert.ok(await p.locator(".syntax-function").count()>0);
      assert.ok(await p.locator(".syntax-definition").count()>0);
      assert.ok(await p.locator(".syntax-number").count()>0);
      assert.ok(await p.locator(".cm-indent-guide").count()>0);
      await p.locator(".cm-foldGutter .cm-gutterElement").filter({hasText:"⌄"}).first().click();
      await p.locator(".cm-foldPlaceholder").waitFor();
      await p.locator(".cm-foldPlaceholder").click();assert.equal(await readCode(p),sample);
      await p.locator("#editor-whitespace").click();assert.ok(await p.locator(".cm-highlightSpace").count()>0);
      await p.locator("#editor-wrap").click();assert.equal(await p.locator(".cm-lineWrapping").count(),1);
      assert.equal(t.saves.length,0,"presentation changes must not save a file");
      await p.locator("#editor-shortcuts").click();assert.equal(await p.locator("#editor-help").isVisible(),true);
      await p.keyboard.press("Escape");assert.equal(await p.locator("#editor-help").isVisible(),false);
      await t.finish("syntax, indentation guides, folding, whitespace, wrapping and shortcut help");
    }
    {
      const source="def example():\n\treturn 1\n",t=await setup({content:source}),p=t.page;
      assert.equal(await p.locator("#editor-indent").inputValue(),"tab");
      await p.locator("#code-input").press("Control+End");await p.keyboard.press("Tab");
      assert.equal(await readCode(p),source+"\t");
      await t.finish("existing hard tabs are detected and retained");
    }
    {
      const t=await setup({mode:"edit_denied"}),p=t.page,input=p.locator("#code-input");
      await input.press("Control+a");await p.keyboard.type("overwrite");await p.keyboard.press("Backspace");
      await input.press("Control+/");await input.press("Control+z");
      assert.equal(await readCode(p),sample);assert.equal(t.saves.length,0);
      await p.locator("#editor-find").click();assert.equal(await p.locator('input[name="replace"]').count(),0);
      await t.finish("read-only permission blocks typing, comments, undo and replacements");
    }
    {
      const t=await setup({viewport:{width:1920,height:1080}}),p=t.page;
      const typography=await p.locator("#code-input").evaluate(e=>({size:getComputedStyle(e).fontSize,line:parseFloat(getComputedStyle(e).lineHeight)}));
      assert.equal(typography.size,"13px");assert.ok(typography.line<23);
      const toolbar=await p.locator(".toolbar").boundingBox();assert.equal(toolbar.height,56);
      await t.capture("1080p");await p.locator("#editor-back").click();await p.locator(".entry-name").waitFor();
      assert.equal(await p.locator(".entry-name").first().evaluate(e=>getComputedStyle(e).fontSize),typography.size);
      assert.equal((await p.locator(".toolbar").boundingBox()).height,toolbar.height);
      await t.capture("files-1080p");await t.finish("identical typography and toolbar density in /files and /editor at 1080p");
    }
    {
      const t=await setup(), p=t.page;
      assert.equal(await readCode(p),sample);
      assert.equal(await p.locator("#sidebar").isVisible(),false);
      assert.equal(await p.locator("#editor-run").isDisabled(),false);
      await p.locator("#editor-run").click();
      await p.waitForFunction(()=>document.querySelector("#run-result").textContent.includes("Terminé"));
      assert.equal(t.starts.length,1);assert.equal(t.saves.length,0);
      assert.match(await p.locator("#run-output").textContent(),/Somme : 108/);
      assert.match(await p.locator("#run-result").textContent(),/Code de retour : 0.*Durée d’exécution : 24 ms/);
      for(const theme of ["dark","light"]) {
        if(await p.locator("html").getAttribute("data-theme")!==theme)await p.locator("#theme-toggle").click();
        const box=await p.locator("#editor-panes").boundingBox();assert.equal(Math.round(box.y+box.height),1058);
        assert.equal(await p.locator("#editor-save-state").textContent(), "Enregistré");
        assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
        await t.capture(theme);
      }
      await p.locator("#editor-splitter").focus();await p.keyboard.press("ArrowLeft");assert.equal(await p.locator("#editor-splitter").getAttribute("aria-valuenow"),"63");
      await p.locator("#sidebar-toggle").click();assert.equal(await p.locator("#sidebar").isVisible(),true);
      await p.locator("#sidebar-toggle").click();
      await p.locator("#editor-clear").click();assert.equal(await p.locator("#run-output").textContent(),"");
      await p.locator("#editor-back").click();await p.waitForURL(/\/files\?/);
      await p.locator("#rows tr").first().waitFor();assert.match(await p.locator("#listing-title").textContent(),/Exemples/);
      await p.getByRole("button",{name:"Actions pour calcul.py",exact:true}).click();await p.getByRole("menuitem",{name:"Modifier le code"}).click();
      await p.waitForURL(/\/editor\?/);await p.locator("#code-input:not([aria-readonly=true])").waitFor();
      await t.finish("open, themes, viewport height, output, splitter, navigation and reopening");
    }
    {
      const t=await setup({content:"print('line')\n".repeat(200),stdout:"output\n".repeat(200)}),p=t.page;
      await p.locator("#editor-run").click();await p.waitForFunction(()=>document.querySelector("#run-result").textContent.includes("Terminé"));
      const header=await p.locator(".editor-heading").boundingBox();
      await p.locator("#code-input").hover();await p.mouse.wheel(0,600);
      await p.waitForFunction(()=>document.querySelector("#code-host").shadowRoot.querySelector("#code-scroll").scrollTop>0);
      assert.equal(await p.locator("#editor-output").evaluate(e=>e.scrollTop),0);
      const codeTop=await p.locator("#code-scroll").evaluate(e=>e.scrollTop);
      await p.locator("#editor-output").hover();await p.mouse.wheel(0,600);
      await p.waitForFunction(()=>document.querySelector("#editor-output").scrollTop>0);
      assert.equal(await p.locator("#code-scroll").evaluate(e=>e.scrollTop),codeTop);
      assert.deepEqual(await p.locator(".editor-heading").boundingBox(),header);
      const divider=await p.locator("#editor-splitter").boundingBox();
      await p.mouse.move(divider.x+divider.width/2,divider.y+100);await p.mouse.down();
      await p.mouse.move(650,divider.y+100);await p.mouse.up();
      assert.ok(Number(await p.locator("#editor-splitter").getAttribute("aria-valuenow"))<50);
      await p.locator("#code-input").focus();await p.keyboard.press("Escape");await p.keyboard.press("Tab");
      assert.equal(await p.locator("#editor-goto").evaluate(e=>e===document.activeElement),true);
      await t.finish("independent scrolling, stationary header, pointer resize and keyboard escape");
    }
    {
      const t=await setup(),p=t.page;await p.clock.install();
      await replaceCode(p, "print(1)");await p.clock.runFor(50);await replaceCode(p, "print(2)");
      await p.clock.runFor(99);assert.equal(t.saves.length,0);
      const saved=p.waitForResponse(r=>r.url().endsWith("/v1/web/editor/file")&&r.request().method()==="PUT");await p.clock.runFor(1);await saved;
      assert.equal(t.saves.length,1);assert.equal(t.saves[0].content,"print(2)");
      await t.finish("100 ms debounce after the last edit");
    }
    {
      const t=await setup({mode:"hold"}),p=t.page;
      await replaceCode(p, "print('first')");await p.waitForTimeout(180);assert.equal(t.saves.length,1);
      await replaceCode(p, "print('latest')");await p.locator("#editor-run").click();
      assert.equal(t.starts.length,0);assert.equal(await p.locator("#code-input").getAttribute("aria-readonly"),"true");
      t.setMode("normal");t.release();
      await p.waitForFunction(()=>document.querySelector("#run-result").textContent.includes("Terminé"));
      assert.equal(t.saves.length,2);assert.equal(t.saves[1].base_revision,2);assert.equal(t.starts[0].content,"print('latest')");
      await replaceCode(p, "print('after run')");assert.equal(await p.locator("#output-stale").isVisible(),true);
      await t.finish("serialized saves, exact run snapshot, and stale output");
    }
    for(const mode of ["conflict","save_error","lost_ack"]) {
      const t=await setup({mode}),p=t.page;
      await replaceCode(p, "my draft");await p.locator("#editor-run").click();
      await p.locator("#editor-notice").waitFor();assert.equal(t.starts.length,0);assert.equal(await readCode(p),"my draft");
      await p.locator("#editor-back").click();assert.match(p.url(),/\/editor\?/);
      if(mode==="lost_ack") {t.setMode("normal");await p.locator("#editor-retry").click();await p.locator("#editor-notice").waitFor({state:"hidden"});assert.equal(t.saves.length,1);}
      else {const download=p.waitForEvent("download");await p.locator("#editor-draft").click();assert.match((await download).suggestedFilename(),/^brouillon-/);}
      await t.finish(`draft recovery and blocked execution: ${mode}`);
    }
    {
      const t=await setup({mode:"hold"}),p=t.page;
      await replaceCode(p, "first draft");await p.waitForTimeout(180);
      await replaceCode(p, "latest draft");t.setMode("lost_ack");t.release();
      await p.locator("#editor-notice").waitFor();t.setMode("normal");await p.locator("#editor-retry").click();
      await p.locator("#editor-notice").waitFor({state:"hidden"});
      assert.equal(t.saves.length,2);assert.equal(t.saves[1].base_revision,2);assert.equal(t.saves[1].content,"latest draft");
      assert.equal(await readCode(p),"latest draft");
      await t.finish("a lost acknowledgement retains edits made during the previous save");
    }
    {
      const t=await setup({mode:"hold"}),p=t.page;
      await replaceCode(p, "keep this draft");await p.waitForTimeout(180);
      await p.locator("#code-input").click();await p.keyboard.press("End");
      const dialog=p.waitForEvent("dialog");
      const navigation=p.evaluate(()=>{location.href="/files";});
      const warning=await dialog;assert.equal(warning.type(),"beforeunload");await warning.dismiss();
      await navigation;
      assert.match(p.url(),/\/editor\?/);assert.equal(await readCode(p),"keep this draft");
      await p.evaluate(()=>{const channel=new BroadcastChannel("mysync-files");channel.postMessage("logout");channel.close();});
      await p.waitForFunction(()=>document.querySelector("#editor-error").textContent.includes("session a expiré"));
      assert.equal(await readCode(p),"keep this draft");assert.equal(await p.locator("#editor-run").isDisabled(),true);
      assert.equal(await p.locator("#editor-draft").isVisible(),true);
      await t.finish("native leave warning and draft retained on cross-tab logout");
    }
    {
      const t=await setup(),p=t.page;
      await p.locator("#editor-run").click();await p.waitForFunction(()=>document.querySelector("#run-result").textContent.includes("Terminé"));
      await replaceCode(p, "print('new version')");t.setMode("start_error");await p.locator("#editor-run").click();
      await p.waitForFunction(()=>document.querySelector("#runner-message").textContent.includes("n’a pas confirmé"));
      assert.equal(await p.locator("#run-output").textContent(),"");assert.equal(await p.locator("#run-result").isVisible(),false);
      await t.finish("a refused launch cannot display an earlier run as its result");
    }
    {
      const t=await setup({content:"print(1)\r\n"}),p=t.page;
      await replaceCode(p, "print(2)\n");await p.locator("#editor-run").click();
      await p.waitForFunction(()=>document.querySelector("#run-result").textContent.includes("Terminé"));
      assert.equal(t.starts[0].content,"print(2)\r\n");
      await replaceCode(p, "x".repeat(262145));await p.locator("#editor-notice").waitFor();
      assert.match(await p.locator("#editor-error").textContent(),/256 Kio/);
      await replaceCode(p, "print(3)\n");await p.locator("#editor-retry").click();await p.locator("#editor-notice").waitFor({state:"hidden"});
      assert.equal(t.saves.at(-1).content,"print(3)\r\n");
      await t.finish("CRLF preservation, size limit and recovery");
    }
    for(const mode of ["edit_denied","run_denied","offline","missing","sandbox_missing"]) {
      const t=await setup({mode}),p=t.page;
      if(mode==="edit_denied") {assert.equal(await p.locator("#code-input").getAttribute("aria-readonly"),"true");assert.match(await p.locator("#editor-error").innerText(),/enable-edit/);}
      else {assert.equal(await p.locator("#editor-run").isDisabled(),true);assert.equal(await p.locator("#runner-retry").isVisible(),true);}
      assert.equal(t.starts.length,0);await t.finish(`permission and detection: ${mode}`);
    }
    for(const mode of ["normal","compile_error","runtime_error","timeout","keep_running"]) {
      const t=await setup({mode,path:"Projets/example.c",content:"int main(void) { return 0; }"}),p=t.page;
      await p.locator("#editor-run").click();await p.waitForFunction(()=>document.querySelector("#editor-run span").textContent==="Arrêter");
      if(mode==="keep_running")await p.locator("#editor-run").click();
      await p.waitForFunction(()=>document.querySelector("#editor-run span").textContent==="Exécuter");
      const result=await p.locator("#run-result").textContent();
      assert.match(result,/Durée de compilation : 41 ms/);
      if(mode==="compile_error") {assert.match(result,/Échec de la compilation/);assert.doesNotMatch(result,/Durée d’exécution/);}
      else assert.match(result,/Durée d’exécution : 24 ms/);
      await t.finish(`C compilation, execution and stop: ${mode}`);
    }
    for(const viewport of [{width:390,height:844},{width:768,height:900}]) {
      const t=await setup({viewport,path:`Projets/${"dossier-long-".repeat(8)}/${"fichier-long-".repeat(8)}.py`,stdout:"<script>window.exposed=true</script>"}),p=t.page;
      await p.locator("#editor-run").click();await p.waitForFunction(()=>document.querySelector("#run-result").textContent.includes("Terminé"));
      assert.equal(await p.evaluate(()=>window.exposed),undefined);
      await t.capture(`responsive-${viewport.width}`);
      assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,
        JSON.stringify(await p.evaluate(()=>[...document.querySelectorAll("body *")].filter(e=>e.getBoundingClientRect().right>innerWidth+1 && getComputedStyle(e).display!=="none").map(e=>[e.id||e.className,e.getBoundingClientRect().width]).slice(0,15))));
      const box=await p.locator("#editor-panes").boundingBox();assert.equal(Math.round(box.y+box.height),viewport.height);
      await t.capture(`responsive-${viewport.width}`);await t.finish(`responsive and escaped output: ${viewport.width}`);
    }
  } finally {await browser.close();}
}
(async()=>{
  if(process.env.MYSYNC_BROWSER!=="firefox")await suite(chromium,"chromium");
  if(process.env.MYSYNC_BROWSER!=="chromium")await suite(firefox,"firefox");
})().catch(error=>{console.error(error);process.exitCode=1;});
