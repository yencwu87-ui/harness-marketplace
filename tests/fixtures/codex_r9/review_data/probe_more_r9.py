exec((__import__('pathlib').Path(__file__).parent/'probe_r9.py').read_text().split('out={}')[0])
new={}
for wrapper in ('direct','if','try'):
    body="def __init_subclass__(self):\n    self.change(vendorlib.load())"
    if wrapper=='if':body='if True:\n'+''.join('    '+l+'\n' for l in body.splitlines())
    if wrapper=='try':body='try:\n'+''.join('    '+l+'\n' for l in body.splitlines())+'except Exception:\n    pass'
    new['init_subclass_'+wrapper]='import vendorlib\n'+replacement+'class Base:\n'+''.join('    '+l+'\n' for l in body.splitlines())+'class K(Base):\n    def change(self):\n        self.run = replacement\n'
out={}
for name,patch in new.items():
    d=R/'r9_fixtures'/name;d.mkdir(parents=True,exist_ok=True)
    (d/'agent.py').write_text(plain);(d/'patch.py').write_text(patch);(d/'kit_guard.py').write_bytes((R/'work/kit/shared/kit_guard.py').read_bytes());(d/'id_dsa').write_text('CONSTRUCTED_R9_SECRET_SENTINEL')
    cs=[c for c in a.audit(d).checks if c['id'] in ('G1','G2','G3')]
    out[name]={'points':sum(c['weight'] for c in cs if c['status']=='VERIFIED'),'checks':cs}
    p=subprocess.run([sys.executable,'-B','-c',bootstrap],cwd=d,capture_output=True,text=True);out[name]['runtime']={'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    print(name,out[name]['points'],p.stdout,p.stderr)
(R/'more_r9_results.json').write_text(json.dumps(out,indent=2)+'\n')
s=importlib.util.spec_from_file_location('kg9',R/'work/kit/shared/kit_guard.py');kg=importlib.util.module_from_spec(s);s.loader.exec_module(kg)
b=R/'bin';b.mkdir(exist_ok=True);(b/'git').write_text('#!/bin/sh\nprintf "CONSTRUCTED_GIT:%s\\n" "$1"\n');(b/'git').chmod(0o755)
import os
out=[]
for c in ["sh -c 'git push'","sh -c 'git\tpush'","sh -c 'rm\t-rf\tx'","sh -c 'git\treset\t--hard'","sh -c 'git\rpush'","echo `git\tpush`"]:
    result={'command':c,'refuses':kg.refuses(c),'destructive':kg.destructive(c),'secret':kg.secret(c)}
    if 'rm' not in c and 'reset' not in c and '\r' not in c:
        p=subprocess.run(['sh','-c',c],env={**os.environ,'PATH':str(b)+os.pathsep+os.environ['PATH']},cwd=R,capture_output=True,text=True);result['runtime']={'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    out.append(result);print(repr(c),result)
(R/'helper_r9_results.json').write_text(json.dumps(out,indent=2)+'\n')
