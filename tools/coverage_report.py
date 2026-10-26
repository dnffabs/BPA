"""Fixed-denominator call coverage, independent of target nonemptiness."""
import json
from pathlib import Path

from memory_model import read_rows


def report(facts, output, complete=False):
    facts,output = Path(facts),Path(output)
    if not (facts/'instruction_inventory.json').exists():
        return {}
    catalog = json.loads((facts/'instruction_inventory.json').read_text())
    metadata = json.loads((facts/'metadata.json').read_text())
    base = metadata['mapped_base']
    calls = {int(r[3])-base:r for r in read_rows(facts,'call')}
    candidates = {int(r[3])-base:r for r in read_rows(facts,'tail_candidate')}
    tails = {int(r[0]) for r in read_rows(facts,'tail_call')}
    analyzed = {r[0] for r in read_rows(facts,'analyzed_func')} if complete else set()
    reached = {r[0] for r in read_rows(facts,'reachable_func')} if complete else set()
    targets,external = {},{}
    uncertain = set()
    if complete:
        for _,name,site in read_rows(facts,'call_graph'):
            targets.setdefault(int(site)-base,set()).add(name)
        for relation in ('indirect_call_target','tail_call_target'):
            for site,name in read_rows(facts,relation):
                targets.setdefault(int(site)-base,set()).add(name)
        for site,name in read_rows(facts,'external_call_target'):
            external.setdefault(int(site)-base,set()).add(name)
        for relation in ('uncertain_call','uncertain_tail_call'):
            uncertain.update(int(r[0])-base for r in read_rows(facts,relation))
    entries = []
    for site in catalog['sites']:
        rva = site['rva']
        call = calls.get(rva)
        candidate = candidates.get(rva)
        if site['kind'] != 'call' and call is None and candidate is None:
            continue
        kind = 'call' if site['kind']=='call' else ('tail' if call and int(call[0]) in tails else 'tail-candidate')
        state = 'pending'
        if complete:
            if not site['instruction_lifted']:
                state = 'not-lifted'
            elif call is None:
                state = 'unconfirmed-tail' if candidate else 'not-extracted'
            elif site['function'] not in analyzed:
                state = 'not-analyzed'
            elif rva in uncertain:
                state = 'partial' if targets.get(rva) or external.get(rva) else 'unknown'
            else:
                state = 'resolved' if targets.get(rva) or external.get(rva) else 'unresolved'
        entries.append(dict(site,transfer=kind,frontend_extracted=call is not None,
             analyzed=(site['function'] in analyzed if complete else None),
             reachable_from_main=(site['function'] in reached if complete else None),
             reachability_note='static resolved-edge closure; absence does not prove runtime unreachability',
             targets=sorted(targets.get(rva,())) if complete else None,
             external_targets=sorted(external.get(rva,())) if complete else None,
             uncertain=(rva in uncertain if complete else None),status=state))
    ordinary = [r for r in entries if r['transfer']=='call' and r['indirect']]
    tail_entries = [r for r in entries if r['transfer']=='tail']
    counts = dict(fixed_indirect_calls=len(ordinary),
        instruction_lifted=sum(r['instruction_lifted'] for r in ordinary),
        frontend_extracted=sum(r['frontend_extracted'] for r in ordinary),
        analyzed=sum(r['analyzed'] for r in ordinary) if complete else None,
        reachable_from_main=sum(r['reachable_from_main'] for r in ordinary) if complete else None,
        nonempty=sum(bool(r['targets'] or r['external_targets']) for r in ordinary) if complete else None,
        tail_calls=len(tail_entries),unconfirmed_tail_candidates=sum(r['transfer']=='tail-candidate' for r in entries),
        decode_gaps=len(catalog['decode_gaps']))
    (output/'coverage.json').write_text(json.dumps(dict(schema=1,address_space='elf-rva',
        binary_sha256=catalog['binary_sha256'],analysis_complete=complete,counts=counts,
        calls=entries,decode_gaps=catalog['decode_gaps']),indent=2)+'\n')
    roots = {}
    for func,reason in read_rows(facts,'root_reason'):
        roots.setdefault(func,set()).add(reason)
    at = {r[0] for r in read_rows(facts,'address_taken')}
    functions = [dict(name=f,start=int(a)-base,end=int(b)-base,retained_for_analysis=True,
         entry_lifted=f not in metadata['functions_without_entry_block'],address_taken=f in at,
         root_reasons=sorted(roots.get(f,())),analyzed=(f in analyzed if complete else None),
         reachable_from_main=(f in reached if complete else None)) for f,a,b in read_rows(facts,'function')]
    (output/'function_coverage.json').write_text(json.dumps(dict(schema=1,address_space='elf-rva',
         root_policy=metadata['root_policy'],function_source=metadata['function_source'],functions=functions),indent=2)+'\n')
    return counts
