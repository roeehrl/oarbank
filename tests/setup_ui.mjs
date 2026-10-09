// Exercise the shipped wizard script without a browser, network or real credentials.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const html=fs.readFileSync(new URL('../src/oarbank/setup.html',import.meta.url),'utf8');
const source=html.match(/<script nonce="__NONCE__">([\s\S]*)<\/script>/)[1];
function page(fail=false){
 const nodes=new Map();
 const node=id=>{if(!nodes.has(id))nodes.set(id,{id,hidden:!!html.match(new RegExp(`<[^>]*id="${id}"[^>]*\\bhidden\\b`)),textContent:'',value:'',dataset:{},attrs:{},listeners:{},removeAttribute(name){delete this.attrs[name];if(name==='src')this.src='';},addEventListener(name,callback){this.listeners[name]=callback;},focus(){},querySelector(){return node('submit');}});return nodes.get(id);};
 const form=node('setup');form.elements={password:node('password'),confirmation:node('confirmation')};
 node('choices').options=[{},{},{}];node('choices').querySelectorAll=()=>[];node('choices').insertBefore=()=>{};
 const requests=[];let failure=fail;
 const document={getElementById:node,createElement:()=>({dataset:{}}),querySelector:selector=>node(selector==='button'?'submit':selector)};
 const context=vm.createContext({document,location:{hash:'#synthetic',replace(){}},FormData:class{constructor(){return Object.entries({address:'100.64.0.2',name:'demo',password:'synthetic password',confirmation:''});}},setInterval(){},
 fetch:async(path,request)=>{requests.push({path,body:JSON.parse(request.body)});if(failure)throw Error('Failed to fetch');return{ok:true,json:async()=>path==='/state'?{addresses:[{address:'100.64.0.2',label:'Tailscale'}],pending:{name:'demo',address:'100.64.0.2'}}:path==='/start'?{totp_secret:'synthetic',totp_qr:'data:image/png;base64,test',otpauth:'otpauth://synthetic',primary_key:'primary',backup_key:'backup'}:{console:'http://127.0.0.1/console'}};}});
 assert.equal(form.hidden,true,'no editable first step before state loads');
 vm.runInContext(source,context);
 return{node,context,requests,retry(){failure=false;return context.loadState();}};
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
