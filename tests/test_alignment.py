"""Native contracts for shared boundaries, independent coverage, roots and tails."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from function_manifest import elf_info, validate
from memory_model import read_rows

OUTPUT = ROOT/'build/alignment-regressions'
ENV = dict(os.environ,PYTHONDONTWRITEBYTECODE='1',BPA_PYTHON=sys.executable)
ENV['PATH'] = str(Path.home()/'.local/bin')+':'+ENV.get('PATH','')
RESULTS = []


def command(args, log, expected=0):
    result = subprocess.run(list(map(str,args)),cwd=ROOT,env=ENV,text=True,
                            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
    log.parent.mkdir(parents=True,exist_ok=True)
    log.write_text(result.stdout)
    if result.returncode != expected:
        raise AssertionError(f'exit {result.returncode}, see {log}\n{result.stdout}')
    return result


class AlignmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUTPUT.mkdir(parents=True,exist_ok=True)
        cls.binaries = {}
        for fixture,opt in [('roots','O0'),('tails','O2')]:
            for bits in (64,32):
                label = f'{fixture}_{bits}'
                binary = OUTPUT/label
                command(['gcc',f'-m{bits}',f'-{opt}','-g','-fno-pie','-no-pie',
                    '-fno-ipa-cp','-fno-ipa-sra','-fno-stack-protector',
                    ROOT/f'tests/fixtures/alignment_{fixture}.c','-o',binary],OUTPUT/f'{label}_compile.log')
                command([binary],OUTPUT/f'{label}_native.log')
                cls.binaries[label] = binary

    def analyze(self,label,binary,extra=()):
        dest = OUTPUT/label
        command([sys.executable,ROOT/'tools/run_pipeline.py',binary,'--output',dest,*extra],OUTPUT/f'{label}.log')
        summary = json.loads((dest/'summary.json').read_text())
        self.assertEqual(summary['status'],'completed')
        RESULTS.append(dict(case=label,summary=str(dest/'summary.json'),coverage=summary['coverage']))
        (OUTPUT/'results.json').write_text(json.dumps(RESULTS,indent=2)+'\n')
        return dest

    def test_roots_keep_at_separate_from_main_reachability(self):
        for bits in (64,32):
            for policy in ('main','main-and-at'):
                dest = self.analyze(f'roots_{bits}_{policy}',self.binaries[f'roots_{bits}'],['--roots',policy])
                facts = dest/'facts'
                at = {r[0] for r in read_rows(facts,'address_taken')}
                self.assertIn('unused_dispatch',at)
                self.assertIn('alpha',at)
                self.assertNotIn('only_direct',at,'direct branch destinations alone are not AT evidence')
                analyzed = {r[0] for r in read_rows(facts,'analyzed_func')}
                reached = {r[0] for r in read_rows(facts,'reachable_func')}
                self.assertNotIn('unused_dispatch',reached)
                self.assertEqual('unused_dispatch' in analyzed,policy=='main-and-at')
                coverage = json.loads((dest/'coverage.json').read_text())
                self.assertEqual(coverage['counts']['fixed_indirect_calls'],1)
                self.assertEqual(coverage['counts']['frontend_extracted'],1)
                site = next(r for r in coverage['calls'] if r['function']=='unused_dispatch')
                self.assertFalse(site['reachable_from_main'])
                direct = next(r for r in coverage['calls'] if r['function']=='main' and not r['indirect'])
                self.assertEqual(direct['targets'],['only_direct'])
                self.assertEqual(direct['status'],'resolved')
                if policy=='main-and-at':
                    self.assertEqual(site['targets'],['alpha'])
                else:
                    self.assertEqual(site['status'],'not-analyzed')

    def test_manifest_roundtrip_validation_and_bpax_adapter(self):
        binary = self.binaries['roots_64']
        first = self.analyze('manifest_source',binary,['--roots','main-and-at'])
        manifest = first/'facts/functions.json'
        second = self.analyze('manifest_import',binary,['--functions',manifest,'--roots','main-and-at'])
        self.assertEqual(read_rows(first/'facts','function'),read_rows(second/'facts','function'))
        self.assertEqual(read_rows(first/'facts','indirect_call_target'),read_rows(second/'facts','indirect_call_target'))
        doc = json.loads(manifest.read_text())
        info = elf_info(binary)
        bad = dict(doc,binary_sha256='0'*64)
        with self.assertRaisesRegex(ValueError,'SHA256'):
            validate(bad,info)
        bad = dict(doc,functions=[dict(doc['functions'][0]),dict(doc['functions'][1],start=doc['functions'][0]['start']+1)])
        with self.assertRaisesRegex(ValueError,'Overlapping'):
            validate(bad,info)
        tsv = OUTPUT/'bpax_ranges.facts'
        tsv.write_text(''.join(f"{r['name']}\t{r['start']+info['linked_base']}\t{r['end']+info['linked_base']}\n" for r in doc['functions']))
        converted = OUTPUT/'bpax_functions.json'
        command([sys.executable,ROOT/'tools/function_manifest.py',binary,'--from-bpax',tsv,
                 '--mapped-base',hex(info['linked_base']),'--output',converted],OUTPUT/'bpax_convert.log')
        self.assertEqual([(r['name'],r['start'],r['end']) for r in validate(json.loads(converted.read_text()),info)],
                         [(r['name'],r['start'],r['end']) for r in doc['functions']])

    def test_pie_rva_roundtrip(self):
        binary = OUTPUT/'roots_pie'
        command(['gcc','-m64','-O0','-g','-fPIE','-pie',ROOT/'tests/fixtures/alignment_roots.c','-o',binary],OUTPUT/'pie_compile.log')
        command([binary],OUTPUT/'pie_native.log')
        first = self.analyze('pie_source',binary,['--roots','main-and-at'])
        second = self.analyze('pie_import',binary,['--functions',first/'facts/functions.json','--roots','main-and-at'])
        self.assertEqual(read_rows(first/'facts','indirect_call_target'),read_rows(second/'facts','indirect_call_target'))
        doc = json.loads((first/'facts/functions.json').read_text())
        self.assertTrue(all(0 <= r['start'] < 0x400000 for r in doc['functions']))
        self.assertEqual(json.loads((first/'coverage.json').read_text())['calls'],json.loads((second/'coverage.json').read_text())['calls'])

    def test_stripped_with_supplied_boundaries_and_hash_rejection(self):
        binary = self.binaries['roots_64']
        original = self.analyze('stripped_source',binary,['--roots','main-and-at'])
        stripped = OUTPUT/'roots_stripped'
        command(['strip','--strip-all','-o',stripped,binary],OUTPUT/'strip.log')
        # Rebind only after checking executable bytes are unchanged. This is
        # supplied-boundary analysis, not an automatic recovery claim.
        from elftools.elf.elffile import ELFFile
        with binary.open('rb') as a,stripped.open('rb') as b:
            self.assertEqual(ELFFile(a).get_section_by_name('.text').data(),ELFFile(b).get_section_by_name('.text').data())
        doc = json.loads((original/'facts/functions.json').read_text())
        manifest = OUTPUT/'stripped_functions.json'
        manifest.write_text(json.dumps(doc))
        failed = OUTPUT/'wrong_hash'
        result = command([sys.executable,ROOT/'tools/run_pipeline.py',stripped,'--output',failed,'--functions',manifest],OUTPUT/'wrong_hash.log',expected=1)
        self.assertIn('SHA256',result.stdout)
        doc['binary_sha256'] = hashlib.sha256(stripped.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(doc))
        actual = self.analyze('stripped_import',stripped,['--functions',manifest,'--roots','main-and-at'])
        self.assertEqual(read_rows(actual/'facts','indirect_call_target'),read_rows(original/'facts','indirect_call_target'))

    def test_native_tail_calls_arguments_results_and_return_continuation(self):
        for bits in (64,32):
            dest = self.analyze(f'tails_{bits}_analysis',self.binaries[f'tails_{bits}'])
            facts = dest/'facts'
            calls = read_rows(facts,'call')
            tail_ids = {r[0] for r in read_rows(facts,'tail_call')}
            by_func = {r[1]:r for r in calls if r[0] in tail_ids}
            for name in ('tail_direct','tail_chain','tail_indirect','tail_factory','tail_factory_indirect','many_tail','tail_allocate'):
                self.assertIn(name,by_func,f'{bits}: {name} must be extracted as a tail call')
            targets = {}
            for site,name in read_rows(facts,'indirect_call_target'):
                targets.setdefault(site,set()).add(name)
            for function,expected_sites in [('leaf',1),('many_leaf',1),('consume_factory',2)]:
                sites = [r[3] for r in calls if r[1]==function and r[-1]=='1' and r[0] not in tail_ids]
                self.assertEqual(len(sites),expected_sites)
                for site in sites:
                    self.assertIn('alpha',targets.get(site,set()),f'{bits}/{function}: {targets.get(site)}')
            tail_targets = {(site,name) for site,name in read_rows(facts,'tail_call_target')}
            self.assertIn((by_func['tail_indirect'][3],'leaf'),tail_targets)
            self.assertIn((by_func['tail_factory_indirect'][3],'factory'),tail_targets)
            self.assertFalse(set(targets) & {r[3] for r in by_func.values()},'ordinary call output must exclude tail jumps')
            chain_site = next(site for caller,callee,site in read_rows(facts,'call_graph') if caller=='driver' and callee=='tail_chain')
            chain_call = next(r for r in calls if r[3]==chain_site)
            continuation = next(r[2] for r in read_rows(facts,'edge') if r[0]=='driver' and r[1]==chain_call[2] and r[3]=='Ijk_FakeRet')
            self.assertIn(['leaf',continuation],read_rows(facts,'return_continuation'))
            returns = {r[1] for r in read_rows(facts,'return_block') if r[0]=='leaf'}
            self.assertTrue(any([ret,continuation,'return'] in read_rows(facts,'interproc_edge') for ret in returns))
            self.assertFalse({r[2] for r in by_func.values()} & {r[0] for r in read_rows(facts,'interproc_edge') if r[2]=='return'})
            if bits==64:
                partial = OUTPUT/'tail_boundary_stage'
                command([sys.executable,ROOT/'tools/run_pipeline.py',self.binaries['tails_64'],
                         '--output',partial,'--stage','boundary_gen'],OUTPUT/'tail_boundary_stage.log')
                snapshot = json.loads((partial/'coverage.json').read_text())
                self.assertFalse(snapshot['analysis_complete'])
                self.assertEqual(snapshot['counts']['tail_calls'],len(read_rows(partial/'facts','tail_call')))
                self.assertTrue(all(r['targets'] is None for r in snapshot['calls']))

    def test_indirect_tail_requires_complete_restored_sp(self):
        from run_regressions import fixture,run_rules
        for name,stack,unknown,wanted in [('entry',1,False,True),('not_restored',10,False,False),('unknown',1,True,False)]:
            path = fixture('tail_guard_'+name,{
                'function':[('f',100,190),('g',200,290)],'root':[('f',)],
                'block':[('f',100,1),('g',200,1)],'stack_root':[(1,'f')],
                'constant':[(8,64,200),(9,64,16)],'binary':[(10,'Sub64',64,1,9)],
                'tail_candidate':[(100,'f',100,150,8,1)],'call_stack':[(100,stack)],
                'unknown_seed':[(1,)] if unknown else []})
            run_rules(path,analysis=True)
            self.assertEqual(bool(read_rows(path,'tail_call')),wanted)
            self.assertEqual(bool(read_rows(path,'call')),wanted)
            if not wanted:
                self.assertTrue(any('not certified' in r[-1] for r in read_rows(path,'unsupported')))

    def test_computed_goto_is_not_an_indirect_tail_call(self):
        source = OUTPUT/'computed_goto.c'
        source.write_text('''__attribute__((noinline,noclone)) int dispatch(unsigned n) {
          static void *table[] = {&&a,&&b,&&c}; goto *table[n%3];
          a:return 1; b:return 2; c:return 3;
        }
        int main(void) { return !(dispatch(0)==1 && dispatch(1)==2 && dispatch(2)==3); }
        ''')
        binary = OUTPUT/'computed_goto'
        command(['gcc','-m64','-O2','-g','-fno-pie','-no-pie',source,'-o',binary],OUTPUT/'goto_compile.log')
        command([binary],OUTPUT/'goto_native.log')
        dest = self.analyze('computed_goto_analysis',binary)
        inventory = json.loads((dest/'facts/instruction_inventory.json').read_text())
        self.assertTrue(any(r['function']=='dispatch' and r['kind']=='jump' and r['indirect'] for r in inventory['sites']))
        self.assertFalse([r for r in read_rows(dest/'facts','tail_candidate') if r[1]=='dispatch'])
        self.assertFalse([r for r in read_rows(dest/'facts','call') if r[1]=='dispatch'])


if __name__=='__main__':
    unittest.main(verbosity=2)
