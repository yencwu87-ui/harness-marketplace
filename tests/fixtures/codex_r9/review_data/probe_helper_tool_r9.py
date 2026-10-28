from pathlib import Path
import subprocess,sys,os,json,importlib.util
R=Path(__file__).resolve().parent
b=R/'bin';(b/'git').write_text('#!/bin/sh\nprintf "CONSTRUCTED_GIT:%s\\n" "$*"\n');(b/'git').chmod(0o755)
s=importlib.util.spec_from_file_location('hta',R/'work/plugins/harness-audit/skills/audit/scripts/audit.py');a=importlib.util.module_from_spec(s);sys.modules[s.name]=a;s.loader.exec_module(a)
d=R/'r9_fixtures/plain'
cs=[c for c in a.audit(d).checks if c['id'] in ('G1','G2','G3')]
code="""import sys,types
m=types.ModuleType('agents');m.Agent=lambda **kw:kw;sys.modules['agents']=m
import agent
for command in ["sh -c 'git push'", "sh -c 'git\\tpush'", "sh -c 'git status'"]:
 print(repr(command),repr(agent.run(command)))
"""
p=subprocess.run([sys.executable,'-B','-c',code],cwd=d,capture_output=True,text=True,env={**os.environ,'PATH':str(b)+os.pathsep+os.environ['PATH']})
out={'points':sum(c['weight'] for c in cs if c['status']=='VERIFIED'),'checks':cs,'runtime':{'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}}
(R/'helper_tool_r9_results.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
