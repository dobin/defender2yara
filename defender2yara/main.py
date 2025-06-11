from typing import List,Dict,Tuple
import os
import sys
import shutil
import yara
from collections import defaultdict

from defender2yara.defender.threat import Threat
from defender2yara.yara.rule import YaraRule
from defender2yara.defender.vdm import Vdm
from defender2yara.defender.download import get_latest_signature_vdm, download_latest_signature, parse_mpam_exe
from defender2yara.defender.luaparse import fixup_lua_data
from defender2yara.defender.signature import *

from tqdm import tqdm
import logging

logger = logging.getLogger(__package__)

def clean_up_dir(path:str):
    if not os.path.exists(path):
        raise ValueError(f"Path does not exists: {path}")
    
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                os.remove(file_path)
            except Exception as e:
                logger.error(f"Failed to delete: {file_path}. Error: {e}")
        
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            try:
                shutil.rmtree(dir_path)
            except Exception as e:
                logger.error(f"Failed to delete directory: {dir_path}. Error: {e}")


def write_rules_to_single_file(path,filename,results:Dict[Threat,List[str]]):
    output = []
    for rules in results.values():
        output.extend(rules)
    # write result
    output_file = os.path.join(path,f"{filename}.yara")        
    with open(output_file,'w') as f:
        f.writelines(output)
        logger.info(f"Write YARA rules to {output_file}")


def write_rules_by_family(path,results:Dict[Threat,List[str]]):
    threat:Threat
    for threat,rules in results.items():
        output_dir = os.path.join(path,threat.threat_platform,threat.threat_type)
        if not threat.threat_family:
            output_file = os.path.join(output_dir,"misc.yara")
        else:
            output_file = os.path.join(output_dir,threat.threat_family+".yara")

        os.makedirs(output_dir, exist_ok=True)
        with open(output_file,'a') as f:
            f.writelines(rules)
    logger.info(f"Write YARA rules to {path}")


def parse_asr_entry(threat: Threat, n: int) -> int:
    for sig in threat.signatures:
        if len(sig.sig_data) < 42:
            continue
        idx = sig.sig_data.find(b'-')
        if idx == -1:
            continue

        # heuristics to find guid: xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        if sig.sig_data[16] == 0x2d and sig.sig_data[idx+5] == 0x2d and sig.sig_data[idx+5+5] == 0x2d and sig.sig_data[idx+5+5+5] == 0x2d:
            # Remove fale positives which has the exact same format lol
            # CVE-2019-1652-1653-AD
            if sig.sig_data[8:8+4] == b"CVE-":
                continue

            print(f"ASR {n}: {threat.threat_name} ({threat.threat_id}) -  TC:{threat.category_id} TT:{threat.threat_type} TP:{threat.threat_platform} TF:{threat.threat_family} TV:{threat.threat_variant}")
            print("  GUID: {}".format(
                sig.sig_data[8:8+36]
            ))
            if threat.category_id != 43:
                # no issue, just print a warning
                print("  Unexpected Category ID: {}".format(threat.category_id))

            lua_header_offset = sig.sig_data.find(b'\x1bLuaQ')
            if lua_header_offset == -1:
                print("  No Lua header found in signature data.")
                continue
            if lua_header_offset != 45:
                # no issue, just print a warning
                print("  Lua header offset is not at expected position (45): {}".format(lua_header_offset))
            #print("Lua header offset: {}".format(lua_header_offset))
            
            filename_out = os.path.join("rules", "lua_{}.lua".format(n))
            open(filename_out, "wb").write(sig.sig_data[lua_header_offset:])
            n += 1
    return n

def parse_asr(vdm: Vdm):
    threats = vdm.get_threats()
    progress = False
    progress_bar: tqdm

    if progress:
        progress_bar = tqdm(
                total=len(threats),
                unit='threat',
                bar_format='{l_bar}{bar:20}{r_bar}',
                colour='green',
                desc="Converting signatures",
                leave=False)

    # Parse Threats to find ASR entries
    n = 0
    for threat in threats:
        if threat.threat_id == 2147483632: # !InfrastructureShared
            n = parse_asr_entry(threat, n)
        
        if progress:
            progress_bar.update(1)

    if progress:
        progress_bar.close()


def covert_vdm_to_yara(vdm:Vdm,filesize_check:str,header_check:bool=False) -> Tuple[Dict[Threat,List[str]],int]:
    logger.info(f"Parsing signature database...")
    results:Dict[Threat,List[str]] = defaultdict(list)
    rule_count = 0
    # convert to yara rule
    threats = vdm.get_threats()

    progress_bar = tqdm(
            total=len(threats),
            unit='threat',
            bar_format='{l_bar}{bar:20}{r_bar}',
            colour='green',
            desc="Converting signatures",
            leave=False)

    for threat in threats:
        yara_rules = YaraRule(threat,filesize_check=filesize_check,do_header_check=header_check)
        if not yara_rules:
            continue
        for yara_rule in yara_rules.generate_rules():
            try:
                yara.compile(source=yara_rule)
            except yara.SyntaxError as e:
                logger.warn(f"Failed to convert {threat.threat_name}: {str(e)}")
                logger.debug("\n"+yara_rule)
                continue
            results[threat].append(yara_rule)
            rule_count += 1
        progress_bar.update(1)

    progress_bar.close()

    return results,rule_count


def main(args):
    cache_dir = args.cache
    signature_version:str = ""
    engine_version:str = ""

    if args.latest_signature_version:
        url, signature_version, engine_version = get_latest_signature_vdm(proxy=args.proxy)
        print(f"{signature_version}")
        sys.exit(0)

    if args.cacheonly:
        signature_version = "1.429.489.0"
        engine_version = "1.1.25040.1"
        use_cache = False
    else:
        if (args.download or not args.base) and not args.mpam:
            logger.info("Downloading latest signature database.")
            signature_version, engine_version, use_cache = download_latest_signature(cache_dir,proxy=args.proxy)
            logger.info(f"Complete (use_cache:{use_cache})")
            logger.info(f"Latest Signature Version:{signature_version}")
            logger.info(f"Latest Engine Version   :{engine_version}")

    if args.download:
        sys.exit(0)

    if args.mpam:
        signature_version, engine_version = parse_mpam_exe(args.mpam,cache_path=cache_dir,rm_mpam=False)
        logger.info(f"Loaded {args.mpam}")
        logger.info(f"Latest Signature Version:{signature_version}")
        logger.info(f"Latest Engine Version   :{engine_version}")

    base_file:str = ""
    delta_file:str = ""
    results:Dict[Threat,List[str]]

    output_path = os.path.join(args.output,signature_version)
    os.makedirs(output_path, exist_ok=True)
    logger.info(f"Clean up output directory: {output_path}")
    clean_up_dir(output_path)

    if args.base: # use manually specified vdm files.
        logger.info(f"Loading base signature file: {args.base}")
        vdm = Vdm(args.base)
        if args.delta:
            logger.info(f"Applying delta patch: {args.delta}")
            vdm.apply_delta_vdm(args.delta)

        logger.info(f"Target signature version: {vdm.version}")
        logger.info(f"Target signature type   : {vdm.vdm_type}")

        results,rule_counts = covert_vdm_to_yara(vdm,args.filesize_check,args.header_check)
        logger.info(f"Convert {rule_counts} signatures.")

        if args.single_file:
            write_rules_to_single_file(output_path,vdm.vdm_type,results)
        else:
            write_rules_by_family(output_path,results)
    else: # use vdm files parsed from mpam-fe.exe
        major_version = ".".join(signature_version.split(".")[0:2])
        minor_version = ".".join(signature_version.split(".")[2:4])
        vdm_base_path = os.path.join(cache_dir,"vdm",major_version,'0.0')
        vdm_delta_path = os.path.join(cache_dir,"vdm",major_version,minor_version)
        
        for name in ["mpav","mpas"]:
            base_file = os.path.join(vdm_base_path,name+"base.vdm")
            delta_file = os.path.join(vdm_delta_path,name+"dlta.vdm")
        
            logger.info(f"Loading base signature file: {base_file}")
            if args.cacheonly:
                logger.info(f"Loading vdm cache: {args.cache}")
                vdm = Vdm.make_from_cache(cache_dir,name)
                logger.info("VDM from cache: signatures: {}  threats: {}".format(
                    len(vdm.signatures),
                    len(vdm.threats)))
            else:
                logger.info(f"Creating vdm from files: {vdm_base_path}")
                vdm = Vdm(base_file)
                vdm.parse_files()
                if os.path.exists(delta_file):
                    logger.info(f"Applying delta patch: {delta_file}")
                    vdm.apply_delta_vdm(delta_file)

            logger.info(f"Target signature version: {vdm.version}")
            logger.info(f"Target signature type   : {vdm.vdm_type}")

            if args.writecache:
                vdm.write_cache(args.cache, name)
                logger.info("Cache written")
            else:
                parse_asr(vdm)

                if False: # no yara atm
                    results,rule_counts = covert_vdm_to_yara(vdm,args.filesize_check,args.header_check)
                    logger.info(f"Convert {rule_counts} signatures")

                    if args.single_file:
                        write_rules_to_single_file(output_path,vdm.vdm_type,results)
                    else:
                        write_rules_by_family(output_path,results)

    logger.info("Complete")
    sys.exit(0)
