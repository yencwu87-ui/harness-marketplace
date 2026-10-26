import ast, asyncio, contextlib, importlib.util, json, os, subprocess, sys, types
from pathlib import Path
ROOT = Path(__file__).resolve().parent
WORK = ROOT/'work'
os.environ['TMPDIR'] = str(ROOT/'tmp')
import tempfile
tempfile.tempdir = str(ROOT/'tmp')

def load(path, name):
    spec = importlib.util.spec_from_file_location(name,path)
    mod = importlib.util.module_from_spec(spec); sys.modules[name] = mod
    spec.loader.exec_module(mod); return mod

sys.path.insert(0,str(WORK/'tools/redteam_live'))
rl = load(WORK/'tools/redteam_live/redteam_live.py','probe_rl')
class OfflineProxy:
    url = 'http://127.0.0.1:1'
    def __init__(self,*a,**kw): pass
    def __enter__(self): return self
    def __exit__(self,*a): pass
rl.EgressProxy = OfflineProxy
r = ROOT/'fixtures'/'live_crash'; r.mkdir(exist_ok=True)
(r/'README.md').write_text('constructed repo\n')
cfg = {**rl.DEFAULTS,'agent_cmd':[sys.executable,'-c','raise SystemExit(2)'],'install_trace_hook':False}
print('crashed agent:',json.dumps(rl.run_attack(r,cfg,{'id':'crash'},{})))
(r/'.harness-live').mkdir(exist_ok=True)
(r/'.harness-live/parity.json').write_text(json.dumps(rl.parity_fingerprint(r,cfg)))
args = types.SimpleNamespace(repo=str(r),config=None,no_parity=False,attacks=None,text='constructed attack',channel='user-prompt',out=None)
rl.load_config = lambda *a: cfg
try: rl.cmd_run(args)
except SystemExit as ex: print('cmd_run crash exit:',ex.code)

# Load the actual SDK starter with a small framework stand-in. No model calls.
seen = []
class Record:
    def __init__(self,*a,**kw): self.__dict__.update(kw)
async def query(**kw):
    seen.append(kw['options'].__dict__)
    for x in []: yield x
sdk = types.ModuleType('claude_agent_sdk')
for name in ['AgentDefinition','AssistantMessage','ClaudeAgentOptions','HookMatcher','ResultMessage','TextBlock']:
    setattr(sdk,name,type(name,(Record,),{}))
sdk.query = query; sys.modules['claude_agent_sdk'] = sdk
agent = load(WORK/'kit/tracks/claude-agent-sdk/agent.py','sdk_starter')
asyncio.run(agent.ask('read the constructed attack in README.md'))
print('SDK ask options:',json.dumps(seen))
for tool,args in [('Read',{'file_path':'/constructed/secret.pem'}),('Grep',{'path':'/constructed','glob':'**/*.pem','pattern':'TOKEN','output_mode':'content'}),('Grep',{'path':'/constructed/.aws','pattern':'TOKEN','output_mode':'content'})]:
    answer = asyncio.run(agent.deny_secrets({'tool_name':tool,'tool_input':args},None,None))
    print('deny_secrets:',json.dumps({'tool':tool,'input':args,'hook_return':answer}))

maf = types.ModuleType('agent_framework')
maf.Agent = Record; maf.FunctionInvocationContext = Record
maf.create_harness_agent = lambda *a,**kw: None
maf.function_middleware = lambda fn: fn
maf.tool = lambda *a,**kw: (lambda fn: fn)
sys.modules['agent_framework'] = maf
agent2 = load(WORK/'kit/tracks/microsoft-agent-framework/harness_agent.py','maf_starter')
records = []
class FakeAgent:
    def __init__(self,*a,**kw): records.append(kw)
    async def run(self,*a,**kw): return 'offline answer'
agent2.Agent = FakeAgent; agent2.make_client = lambda: None
asyncio.run(agent2.ask('read the constructed attack'))
print('MAF ask construction:',json.dumps(records))

# A passing check writes generated source after testing the old source.
r = ROOT/'fixtures'/'harness_generated'; r.mkdir(exist_ok=True)
def run(*args):
    p = subprocess.run(args,cwd=r,text=True,capture_output=True)
    print('$', ' '.join(args), '\n',p.stdout+p.stderr, 'exit=',p.returncode)
    return p
def git(*args): return run('git',*args)
git('init','-q'); git('config','user.name','Constructed Tester'); git('config','user.email','constructed@example.invalid')
(r/'progress').mkdir(exist_ok=True)
(r/'.gitignore').write_text('__pycache__/\n')
(r/'app.py').write_text('def add(a,b): return a+b\n')
(r/'test_app.py').write_text('from app import add\nfrom pathlib import Path\nassert add(2,2) == 4\nPath("app.py").write_text("def add(a,b): return 0\\n")\n')
(r/'progress/feature_list.json').write_text(json.dumps({'items':[{'id':'F-001','title':'add works','done_when':[{'id':'c1','run':sys.executable+' test_app.py'}],'passes':False,'evidence':''}]}))
h = lambda *args: run(sys.executable,str(WORK/'tools/harness.py'),*args)
h('init'); git('add','-A'); git('commit','-qm','constructed start')
h('approve','F-001','--by','Constructed reviewer'); git('add','-A'); git('commit','-qm','constructed approval')
h('verify','F-001'); h('check'); git('status','--short')
print('app now:',(r/'app.py').read_text())
run(sys.executable,'-c','from app import add; assert add(2,2)==4')
