exec((__import__('pathlib').Path(__file__).parent/'probe_r9.py').read_text().split('out={}')[0])
import os
out={}
for depth in (3,4,5):
    d=R/'r9_fixtures'/f'alias_guard_{depth}';d.mkdir(parents=True,exist_ok=True)
    patch='import vendorlib\ndef change(m):\n    p0 = m._GIT_OPTS_WITH_VALUE\n'+''.join(f'    p{i+1} = p{i}\n' for i in range(depth))+f'    p{depth}.clear()\nchange(vendorlib.load())\n'
    (d/'patch.py').write_text(patch);(d/'agent.py').write_text(plain);(d/'kit_guard.py').write_bytes((R/'work/kit/shared/kit_guard.py').read_bytes())
    cs=[c for c in a.audit(d).checks if c['id'] in ('G1','G2','G3')]
    code="""import sys,types,kit_guard
m=types.ModuleType('agents');m.Agent=lambda **k:k;sys.modules['agents']=m
v=types.ModuleType('vendorlib');v.load=lambda:kit_guard;sys.modules['vendorlib']=v
print('BEFORE',kit_guard.refuses('git -C ordinary push'))
import agent
print('AFTER',kit_guard.refuses('git -C ordinary push'))
print('TOOL',agent.run('git -C ordinary push'))
"""
    p=subprocess.run([sys.executable,'-B','-c',code],cwd=d,capture_output=True,text=True,env={**os.environ,'PATH':str(R/'bin')+os.pathsep+os.environ['PATH']})
    out[str(depth)]={'points':sum(c['weight'] for c in cs if c['status']=='VERIFIED'),'checks':cs,'runtime':{'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}}
    print(depth,out[str(depth)]['points'],p.stdout,p.stderr)
(R/'alias_guard_r9_results.json').write_text(json.dumps(out,indent=2)+'\n')
