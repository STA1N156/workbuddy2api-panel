package panel

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Large pools must only render the selected page; filters also reset/clamp the page.
func TestAccountPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	script := `const fs = require('fs'), vm = require('vm'), assert = require('assert');
const source = fs.readFileSync('app.js', 'utf8');
const begin = source.indexOf('function accountStatus(');
const end = source.indexOf('function updateAccountFilter(');
const context = { accFilter: {q:'',status:'',realm:'',sort:'default',page:1,size:50}, remarkOf: u => u === 'id-747' ? '备用' : '' };
vm.createContext(context);
vm.runInContext(source.slice(begin, end), context);
const rows = Array.from({length:748}, (_,i) => ({uid:'id-'+i,nickname:'account '+i,realm:i%2?'global':'cn',credits:i,disabled:i===747}));
let page = context.accountPage(rows);
assert.equal(page.rows.length,50); assert.equal(page.pages,15); assert.equal(page.total,748);
context.accFilter.page=15; page=context.accountPage(rows);
assert.equal(page.rows.length,48); assert.equal(page.rows[0].uid,'id-700');
context.accFilter.status='disabled'; page=context.accountPage(rows);
assert.equal(page.total,1); assert.equal(context.accFilter.page,1); assert.equal(page.rows[0].uid,'id-747');
Object.assign(context.accFilter,{status:'',q:'备用'}); assert.equal(context.accountPage(rows).total,1);
Object.assign(context.accFilter,{q:'',realm:'global',sort:'credits'}); page=context.accountPage(rows);
assert.equal(page.total,374); assert.equal(page.rows[0].credits,747);
Object.assign(context.accFilter,{q:'missing',page:99}); page=context.accountPage(rows);
assert.equal(page.rows.length,0); assert.equal(context.accFilter.page,1);
// Exercise the real renderer, including the empty-page and unchanged-data paths.
Object.assign(context.accFilter,{q:'',realm:'',sort:'default',page:1});
const nodes = {}, writes = {};
context.$ = id => nodes[id] || (nodes[id] = {
  set innerHTML(value) { this.html=value; writes[id]=(writes[id]||0)+1; },
  get innerHTML() { return this.html || ''; }
});
context.remarksAll = () => ({});
context.remarkName = (uid, name) => name;
context.rateLimitRowsHtml = () => '';
context.esc = value => String(value == null ? '' : value).replace(/</g,'&lt;').replace(/>/g,'&gt;');
for (const name of ['dur','formatTokenCount','formatLatency','formatRate','ago']) context[name] = value => String(value || 0);
context.accountRenderKey = '';
context.overviewData = null;
context.Date = class extends Date { static now() { return 1800000000000; } };
vm.runInContext(source.slice(source.indexOf('function renderAccounts('), source.indexOf('// renderModelLocks')), context);
context.renderAccounts(rows);
assert.equal((nodes.accBody.innerHTML.match(/<tr /g)||[]).length,50);
context.renderAccounts(rows); assert.equal(writes.accBody,1);
context.accFilter.page=15; context.renderAccounts(rows);
assert.equal((nodes.accBody.innerHTML.match(/<tr /g)||[]).length,48);
assert.equal(nodes.accNext.disabled,true);
context.accFilter.q='nothing'; context.renderAccounts(rows);
assert.ok(nodes.accBody.innerHTML.includes('暂无匹配账号'));
`
	p := filepath.Join(t.TempDir(), "accounts.cjs")
	if err := os.WriteFile(p, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, p).CombinedOutput(); err != nil {
		t.Fatalf("account pagination: %v\n%s", err, out)
	}
}

func TestPanelDefaultsAndRemovedReminder(t *testing.T) {
	js := string(appJS)
	if !strings.Contains(js, "let usDim = 'model', usCreditDim = 'model'") {
		t.Fatal("both usage tables must default to model")
	}
	if strings.Contains(string(indexHTML), `id="expBox"`) || strings.Contains(js, "function loadExpiry(") {
		t.Fatal("expiry reminder must be removed")
	}
	start := strings.Index(js, "$('btnRefresh').onclick")
	if start < 0 {
		t.Fatal("missing page refresh")
	}
	end := strings.Index(js[start:], "$('btnBalanceAll').onclick")
	if end < 0 || strings.Contains(js[start:start+end], "balance_all") {
		t.Fatal("page refresh must not request all upstream balances")
	}
}
