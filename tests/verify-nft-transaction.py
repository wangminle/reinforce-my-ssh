#!/usr/bin/env python3
"""真实 nft 原子替换回归；所有 nft 操作仅在独立用户/网络命名空间内执行。

用法：python3 tests/verify-nft-transaction.py
缺少 Linux/nft/unshare 时退出 2，不操作宿主防火墙。
"""
import shutil
import subprocess
import sys
from pathlib import Path

PROGRAM = r'''
import importlib.util,sys,subprocess,json,hashlib
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'tests'))
spec=importlib.util.spec_from_file_location('test_guides',str(root / 'tests/test-guides.py'));g=importlib.util.module_from_spec(spec);sys.modules['test_guides']=g;spec.loader.exec_module(g)
def generated(allows):
 _,_,_,steps=g.TestStage2Steps().build(session_port=62207,listeners=[62207],backup=True,allow=allows)
 lines=steps['1-allowlist']['do'];i=next(i for i,x in enumerate(lines) if x.startswith('sudo tee '+g.STAGE2.ALLOWLIST_FILE))
 end=lines.index('EOF',i+1)
 return '\n'.join(lines[i+1:end])+'\n'
def nft(*args,input=None,check=True):
 return subprocess.run(['nft',*args],input=input,capture_output=True,text=True,check=check)
nft('add','table','inet','MUST_KEEP')
rules1=generated(['203.0.113.0/24']); rules2=generated(['203.0.113.0/24','198.51.100.0/24'])
nft('-c','-f','-',input=rules1); nft('-f','-',input=rules1)
first=json.loads(nft('-j','list','chain','inet','sshguard','ssh_allow').stdout)
first_rules=[x['rule'] for x in first['nftables'] if 'rule' in x]
assert len(first_rules)==3,first_rules
nft('-c','-f','-',input=rules2);nft('-f','-',input=rules2)
after=nft('-j','list','ruleset').stdout
obj=json.loads(after);items=[x['rule'] for x in obj['nftables'] if 'rule' in x and x['rule']['table']=='sshguard']
assert len(items)==3,items
assert '198.51.100.0' in json.dumps(items[1]),items
assert 'drop' in items[2]['expr'][-1],items
nft('list','table','inet','MUST_KEEP')
invalid=rules2+'add rule inet sshguard ssh_allow INVALID TOKEN\n'
r=nft('-f','-',input=invalid,check=False)
assert r.returncode!=0,'invalid transaction unexpectedly accepted'
assert nft('-j','list','ruleset').stdout==after,'failed transaction changed old state'
print('真实 nft 首装、第二次来源更新、无旧 drop 堆积、失败保留完整旧规则、无关表保留：全部通过')
for name in ('stage0-check.sh','stage1-port-key.sh','stage2-lockdown.sh'):
 print(name,hashlib.sha256((root / name).read_bytes()).hexdigest())
'''


def main():
    if not all(shutil.which(name) for name in ('unshare', 'nft')):
        print('需要 Linux unshare/nft；本机未执行原生验收', file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    return subprocess.run(['unshare', '-Urn', '--', sys.executable, '-c', PROGRAM, str(root)]).returncode


if __name__ == '__main__':
    raise SystemExit(main())
