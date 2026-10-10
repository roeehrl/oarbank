// Exercise the shipped wizard script without a browser, network or real credentials.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const html=fs.readFileSync(new URL('../src/oarbank/setup.html',import.meta.url),'utf8');
const source=html.match(/<script nonce="__NONCE__">([\s\S]*)<\/script>/)[1];
function page(fail=false,{gate=null,hang=false}={}){
 const nodes=new Map();
 const node=id=>{if(!nodes.has(id))nodes.set(id,{id,hidden:!!html.match(new RegExp(`<[^>]*id="${id}"[^>]*\\bhidden\\b`)),textContent:'',value:'',dataset:{},attrs:{},listeners:{},removeAttribute(name){delete this.attrs[name];if(name==='src')this.src='';},setAttribute(name,value){this.attrs[name]=String(value);},style:{},classes:new Set(),get classList(){const c=this.classes;return{add:n=>c.add(n),remove:n=>c.delete(n),contains:n=>c.has(n)};},addEventListener(name,callback){this.listeners[name]=callback;},focus(){},querySelector(){return node('submit');}});return nodes.get(id);};
 const form=node('setup');form.elements={password:node('password'),confirmation:node('confirmation')};
 node('choices').options=[{},{},{}];node('choices').querySelectorAll=()=>[];node('choices').insertBefore=()=>{};
 const requests=[],intervals=[],timers=[];let failure=fail;
 const document={getElementById:node,createElement:()=>({dataset:{}}),querySelector:selector=>node(selector==='button'?'submit':selector)};
 const context=vm.createContext({document,location:{hash:'#synthetic',replace(){}},FormData:class{constructor(){return Object.entries({address:'100.64.0.2',name:'demo',password:'synthetic password',confirmation:''});}},setInterval(fn){intervals.push(fn);return intervals.length;},clearInterval(){},timers,setTimeout(fn){timers.push(fn);return timers.length;},clearTimeout(){},AbortController,
 fetch:async(path,request)=>{requests.push({path,body:JSON.parse(request.body)});if(failure)throw Error('Failed to fetch');if(path==='/start'&&gate)await gate;if(path==='/finish'&&hang)await new Promise((_,reject)=>request.signal.addEventListener('abort',()=>reject(Object.assign(Error('aborted'),{name:'AbortError'}))));return{ok:true,json:async()=>path==='/state'?{addresses:[{address:'100.64.0.2',label:'Tailscale'}],pending:{name:'demo',address:'100.64.0.2'}}:path==='/start'?{totp_secret:'synthetic',totp_qr:'data:image/png;base64,test',otpauth:'otpauth://synthetic',primary_key:'primary',backup_key:'backup'}:{console:'http://127.0.0.1/console'}};}});
 assert.equal(form.hidden,true,'no editable first step before state loads');
 vm.runInContext(source,context);
 return{node,context,requests,timers,retry(){failure=false;return context.loadState();}};
}
const failed=page(true);await new Promise(resolve=>setImmediate(resolve));
assert.equal(failed.node('setup').hidden,true);
assert.equal(failed.node('retry').hidden,false);
assert.match(failed.node('error').textContent,/saved choices have not been reset/);
await failed.retry();
assert.equal(failed.node('setup').hidden,false);
assert.equal(failed.node('name').value,'demo');
assert.equal(failed.node('name').readOnly,true);
assert.equal(failed.node('address').value,'100.64.0.2');
assert.equal(failed.node('address').readOnly,true);
assert.equal(failed.node('confirm-password').hidden,true);
assert.equal(failed.node('confirmation').required,false);
assert.equal(failed.node('password').autocomplete,'current-password');
assert.match(failed.node('heading').textContent,/Resume/);
await failed.node('setup').listeners.submit({preventDefault(){},target:failed.node('setup')});
assert.equal(failed.requests.find(r=>r.path==='/start').body.confirmation,'synthetic password');
assert.equal(failed.node('enrollment').hidden,false);
assert.equal(failed.node('totp-qr').src,'data:image/png;base64,test');
assert.equal(failed.node('password').value,'');
failed.context.done('http://127.0.0.1/console',false);
assert.equal(failed.node('totp-qr').src,'');
assert.equal(failed.node('secret').textContent,'');
assert.equal(failed.node('done').hidden,false);

// ---------------------------------------------------------------- busy states (docs/design/console-loading-states.md)
const flush=()=>new Promise(resolve=>setImmediate(resolve));
{
 let release;const gate=new Promise(resolve=>{release=resolve;});
 const p=page(false,{gate});await flush();
 const button=p.node('submit'),form=p.node('setup');
 assert.equal(button.textContent,'Continue authenticator setup');
 const pending=form.listeners.submit({preventDefault(){},target:form});await flush();
 assert.equal(button.textContent,'Continuing…','the button says what is happening');
 assert.ok(button.classList.contains('busy')&&button.disabled,'busy and not clickable twice');
 assert.equal(form.attrs['aria-busy'],'true');
 assert.match(p.node('progress').textContent,/Installing services/);
 assert.ok(!p.node('progress').classList.contains('working'),'one spinner: the button\'s');
 release();await pending;
 assert.equal(button.textContent,'Continue authenticator setup','the label comes back');
 assert.ok(!button.classList.contains('busy')&&!button.disabled);
 assert.equal(form.attrs['aria-busy'],undefined);
 assert.equal(p.node('progress').textContent,'');
 assert.equal(p.node('elapsed').hidden,true);
 // the elapsed time shows only past 10 s, and a note past 90 s
 assert.equal(p.context.elapsedText(4,'slow'),'');
 assert.match(p.context.elapsedText(12,'slow'),/^Working for 12 seconds\.$/);
 assert.match(p.context.elapsedText(95,'Keep this tab open.'),/95 seconds\. Keep this tab open\.$/);
}
{
 // a verification that never answers ends in an error after 30 s, never an endless spinner
 const p=page(false,{hang:true});await flush();
 const verify=p.node('verify');verify.elements={code:{value:'123456'}};
 const pending=verify.listeners.submit({preventDefault(){},target:verify});await flush();
 const button=p.node('submit');
 assert.equal(button.textContent,'Verifying…');
 for(const fn of p.timers.splice(0))fn();await pending;
 assert.match(p.node('error').textContent,/did not answer within 30 seconds/);
 assert.ok(!button.disabled&&!button.classList.contains('busy'));
}
