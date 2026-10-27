import asyncio, importlib.util, json, os, subprocess, sys
from pathlib import Path
R=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('audit_r2',R/'work/plugins/harness-audit/skills/audit/scripts/audit.py'); a=importlib.util.module_from_spec(spec);sys.modules[spec.name]=a;spec.loader.exec_module(a)
pre='from agents import Agent, function_tool\nimport subprocess, re\n'
cases={
'nested_guard':pre+'''def run(command, enforce=False):
    if enforce:
        if re.search(r".env|.pem|.key", command) or 'rm -rf' in command or 'git push' in command:
            return 'denied'
    return subprocess.run(command, shell=True).returncode
agent=Agent(name='w', tools=[run])
''',
'conditional_hook':'from google.adk.agents import Agent\nimport subprocess, re\n'+'''def gate(tool, args, tool_context):
    if tool.name == 'safe':
        if re.search(r".env|.pem|.key", str(args)) or 'rm -rf' in str(args) or 'git push' in str(args):
            return {'error':'denied'}
    return None
def unsafe(command):
    return subprocess.run(command, shell=True).returncode
agent=Agent(name='w', tools=[unsafe], before_tool_callback=gate)
''',
'crewai_task_pooling':'''from crewai import Agent, Task
import subprocess
def run(command):
    return subprocess.run(command,shell=True).returncode
safe=Agent(role='safe', goal='g', backstory='b', tools=[])
unsafe=Agent(role='unsafe', goal='g', backstory='b', tools=[run])
task=Task(description='review safe work', expected_output='report', agent=safe, human_input=True)
''',
'bound_method':pre+'''def run(command):
    runner = subprocess
    return runner.run(command,shell=True).returncode
agent=Agent(name='w',tools=[run])
''',
'fixed_command':pre+'''def run():
    return subprocess.run('git push origin main',shell=True).returncode
agent=Agent(name='w',tools=[run])
''',
'path_open':pre+'''from pathlib import Path
def read(path):
    with Path(path).open() as f:
        return f.read()
agent=Agent(name='w',tools=[read])
''',
'and_guard':pre+'''def run(command):
    if '.env' in command and 'rm -rf' in command:
        return 'denied'
    return subprocess.run(command,shell=True).returncode
agent=Agent(name='w',tools=[run])
''',
}
out={}
for name,src in cases.items():
    p=R/'r2_fixtures'/name;p.mkdir(parents=True,exist_ok=True);(p/'agent.py').write_text(src)
    rep=a.audit(p);out[name]=[c for c in rep.checks if c['id'] in ('G1','G2','G3')]
    print(name,[(c['id'],c['status']) for c in out[name]])
# Execute only the constructed inline function with subprocess replaced by a recording stand-in.
import types
for name, args in [('nested_guard',('rm -rf /constructed',)),('and_guard',('rm -rf /constructed',))]:
    tree=__import__('ast').parse(cases[name]);fn=next(n for n in tree.body if isinstance(n,__import__('ast').FunctionDef));calls=[]
    ns={'subprocess':types.SimpleNamespace(run=lambda *x,**k:(calls.append(x[0]) or types.SimpleNamespace(returncode=0))), 're':__import__('re')}
    exec(compile(__import__('ast').Module(body=[fn],type_ignores=[]),'<constructed>','exec'),ns)
    ns['run'](*args);print('recorded_execution',name,calls)
# Invoke actual SDK search implementation with SDK stand-in; use constructed symlinks only.
sys.path.insert(0,str(R/'work/tests/fixtures/standins'))
s=importlib.util.spec_from_file_location('sdk_r2',R/'work/kit/tracks/claude-agent-sdk/agent.py');sdk=importlib.util.module_from_spec(s);s.loader.exec_module(sdk)
p=R/'r2_fixtures/search_symlink';p.mkdir(parents=True,exist_ok=True);(p/'.env').write_text('TOKEN=constructed-canary-symlink\n');(p/'ordinary.txt').symlink_to('.env') if not (p/'ordinary.txt').exists() else None
sdk.set_repo(p)
res=asyncio.run(sdk.search_code.handler({'pattern':'TOKEN','path':'.'}));print('symlink_search',json.dumps(res));out['symlink_search']=res
(R/'r2_results.json').write_text(json.dumps(out,indent=2))
