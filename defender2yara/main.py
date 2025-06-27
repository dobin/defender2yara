from typing import List,Dict,Tuple
import os
import sys
import shutil
import yara
from collections import defaultdict
from peewee import Model, CharField, SqliteDatabase, BlobField, IntegerField
from defender2yara.defender.dbthreat import NiceThreat, DbThreat, db
from packaging.version import Version

from defender2yara.defender.threat import Threat
from defender2yara.yara.rule import YaraRule
from defender2yara.defender.vdm import Vdm
from defender2yara.defender.download import get_latest_signature_vdm, download_latest_signature, parse_mpam_exe
from defender2yara.defender.luaparse import fixup_lua_data, lua_disassemble
from defender2yara.defender.signature import *
from defender2yara.util.utils import hexdump
import pickle
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

            # fixup lua data
            lua_fixed = fixup_lua_data(sig.sig_data[lua_header_offset:])
            
            filename_out = os.path.join("rules", "asr_lua_{}.bin".format(n))
            open(filename_out, "wb").write(lua_fixed)
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


def parse_sig_lua(vdm:Vdm, name: str):
    logger.info("Parsing Threat Lua signatures...")
    signatures = vdm.get_signatures()

    n = 0
    for sig in signatures:
        if sig.sig_type == "SIGNATURE_TYPE_LUASTANDALONE":
            lua_header_offset = sig.sig_data.find(b'\x1bLuaQ')
            lua_data = fixup_lua_data(sig.sig_data[lua_header_offset:])
            if lua_data != None:
                # write file
                filepath = os.path.join("rules", "lua", name, "{}.bin".format(n))
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                #print("Write file raw: {}".format(filepath))
                with open(filepath, "wb") as f:
                    f.write(lua_data)

                # convert
                lua_disassembled = lua_disassemble(filepath)

                # write disassembled lua to file
                filepath2 = filepath + ".txt"
                if lua_disassembled is not None:
                    with open(filepath2, "wb") as f:
                        f.write(lua_disassembled)

                    #print("Lua signature full written to: {}".format(filepath2))
                else:
                    #print("Lua signature only raw written to: {}".format(filepath2))
                    pass

            n += 1


def parse_threat_lua(vdm:Vdm):
    logger.info("Parsing Threat Lua signatures...")
    results:Dict[Threat,List[str]] = defaultdict(list)
    threats = vdm.get_threats()

    progress_bar = tqdm(
            total=len(threats),
            unit='threat',
            bar_format='{l_bar}{bar:20}{r_bar}',
            colour='green',
            desc="Converting signatures",
            leave=False)

    count = 0
    for threat in threats:
        print("Threat: {} ({}) - TC:{} TT:{} TP:{} TF:{} TV:{} -> {}".format(
            threat.threat_name,
            threat.threat_id,
            threat.category_id,
            threat.threat_type,
            threat.threat_platform,
            threat.threat_family,
            threat.threat_variant,
            len(threat.signatures)
        ))
        #for sig in threat.signatures:
        #    print("  Signature: {} ({})  Size:{}".format(
        #        sig.sig_type_id,
        #        sig.sig_type,
        #        sig.size
        #    ))


        if False:
            luas = []

            for sig in threat.signatures:
                if sig.sig_type == "SIGNATURE_TYPE_LUASTANDALONE":
                    print("  Lua signature found: {}".format(sig.sig_name))

                    lua_header_offset = sig.sig_data.find(b'\x1bLuaQ')
                    lua_data = fixup_lua_data(sig.sig_data[lua_header_offset:])
                    if lua_data:
                        luas.append(lua_data)
                    else:
                        print("  Invalid Lua signature data found in threat: {}".format(threat.threat_name))

            print("  Lua signatures found: {}".format(len(luas)))
            if len(luas) != 0:
                # write file
                if False:
                    print("Lua Event: {} ({}) - TC:{} TT:{} TP:{} TF:{} TV:{}".format(
                        threat.threat_name,
                        threat.threat_id,
                        threat.category_id,
                        threat.threat_type,
                        threat.threat_platform,
                        threat.threat_family,
                        threat.threat_variant
                    ))

                # rules/[Exploit/Trojan/VirTool/...]
                filepath = os.path.join("rules", threat.threat_type)
                filepath = os.path.join(filepath, "lua")

                # rules/Exploit/Exploit:Win32/CVE-2015-2545.A
                # replace: space / : 
                threat_name = threat.threat_name.replace(" ", "_").replace("/", "_").replace(":", "_").replace("\\", "_")

                # create directory if not exists
                os.makedirs(os.path.dirname(filepath), exist_ok=True)

                n = 0
                for lua in luas:
                    fname = "{}_{}.bin".format(threat_name, n)
                    filepath = os.path.join(filepath, fname)

                    # raw
                    print("Write raw: {}".format(filepath))
                    with open(filepath, "wb") as f:
                        f.write(lua)

                    # convert
                    lua_disassembled = lua_disassemble(filepath)
                    if lua_disassembled is not None:
                        with open(filepath + ".txt", "wb") as f:
                            f.write(lua)
                            f.write("Lua rule for {}\n".format(threat.threat_name).encode('utf-8'))
                            f.write("Threat ID: {}\n".format(threat.threat_id).encode('utf-8'))
                            f.write("Category ID: {}\n".format(threat.category_id).encode('utf-8'))
                            f.write("Threat Type: {}\n".format(threat.threat_type).encode('utf-8'))
                            f.write("Threat Platform: {}\n".format(threat.threat_platform).encode('utf-8'))
                            f.write("Threat Family: {}\n".format(threat.threat_family).encode('utf-8'))
                            f.write("Threat Variant: {}\n\n".format(threat.threat_variant).encode('utf-8'))
                            f.write(lua_disassembled.encode('utf-8'))
                            f.write(b"\n\n")
                n += 1

        progress_bar.update(1)

        count += 1

        if count == 100:
            break

    progress_bar.close()
    return results


def parse_threats_by_name(vdm:Vdm, search: str):
    logger.info("Parsing Threats for name: {}".format(search))
    threats = vdm.get_threats()
    for threat in threats:
        if search in threat.threat_name:
            print("Threat: {} ({}) - TC:{} TT:{} TP:{} TF:{} TV:{}  Sigs:{}".format(
                threat.threat_name,
                threat.threat_id,
                threat.category_id,
                threat.threat_type,
                threat.threat_platform,
                threat.threat_family,
                threat.threat_variant,
                len(threat.signatures)
            ))

            if True:
                for sig in threat.signatures:
                    print("  {} Signature: {} ({})  Size:{}".format(
                        threat.threat_name,
                        sig.sig_type_id,
                        sig.sig_type,
                        sig.size
                    ))
                    hexdump(sig.sig_data)


# convert
def convert_threats(vdm:Vdm):
    logger.info("Writing threats to database: {}".format(db.database))
    logger.info("Sit back and relax")
    threats = vdm.get_threats()

    if os.path.exists(db.database):
        logger.info("Database already exists, removing it.")
        os.remove(db.database)

    db.connect()
    db.create_tables([DbThreat])

    progress_bar = tqdm(
        total=len(threats),
        unit='threat',
        bar_format='{l_bar}{bar:20}{r_bar}',
        colour='green',
        desc="Converting signatures",
        leave=False)

    n = 0
    for threat in threats:
        name = threat.threat_name

        sig_unique = set()
        for sig in threat.signatures:
            if sig.sig_type not in sig_unique:
                sig_unique.add(sig.sig_type)
            else:
                continue
        sigs = " ".join(sig_unique)

        niceThreat = NiceThreat(threat)
        niceThreat.lua_scripts = get_lua_from_threat(threat)
        niceThreat.yara_rules = get_yara_from_threat(threat)

        threatObj = pickle.dumps(niceThreat)
        DbThreat.create(
            name=name,
            sigs=sigs,
            sigcount=len(threat.signatures),
            threatObject=threatObj
        )

        progress_bar.update(1)

    progress_bar.close()
    db.close()


def get_lua_from_threat(threat:Threat) -> List[bytes]:
    lua_scripts = []
    for sig in threat.signatures:
        if sig.sig_type == "SIGNATURE_TYPE_LUASTANDALONE":
            lua_header_offset = sig.sig_data.find(b'\x1bLuaQ')
            lua_data = fixup_lua_data(sig.sig_data[lua_header_offset:])
            if lua_data != None:
                # write file
                filepath = os.path.join("cache", "lua.tmp")
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                with open(filepath, "wb") as f:
                    f.write(lua_data)

                # convert
                lua_disassembled = lua_disassemble(filepath)
                lua_scripts.append(lua_disassembled)

    return lua_scripts


def get_yara_from_threat(threat:Threat) -> List[str]:
    result = []

    yara_rules = YaraRule(threat,filesize_check="20MB",do_header_check=False)
    if not yara_rules:
        return result
    
    for yara_rule in yara_rules.generate_rules():
        try:
            yara.compile(source=yara_rule)
        except yara.SyntaxError as e:
            logger.warn(f"Failed to convert {threat.threat_name}: {str(e)}")
            logger.debug("\n"+yara_rule)
            continue
        result.append(yara_rule)

    return result


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


cache_dir = "cache"


def get_latest_engine_version(engine_path):
    versions = []
    for entry in os.listdir(engine_path):
        try:
            versions.append(Version(entry))
        except:
            continue
    return str(max(versions)) if versions else None

def get_latest_signature_version(vdm_path):
    major_minor_versions = []
    for entry in os.listdir(vdm_path):
        if os.path.isdir(os.path.join(vdm_path, entry)):
            try:
                major_minor_versions.append(Version(entry))
            except:
                continue
    if not major_minor_versions:
        return None

    latest_major_minor = str(max(major_minor_versions))
    sub_path = os.path.join(vdm_path, latest_major_minor)
    builds = []
    for entry in os.listdir(sub_path):
        try:
            builds.append(Version(entry))
        except:
            continue

    if not builds:
        return None

    latest_build = str(max(builds))
    return f"{latest_major_minor}.{latest_build}"


def main(args):
    signature_version:str = ""
    engine_version:str = ""

    if args.download:
        logger.info("Downloading latest signature database")
        signature_version, engine_version, use_cache = download_latest_signature(cache_dir,proxy=args.proxy)
        logger.info(f"Written to: {cache_dir}")
        logger.info(f"  Latest Signature Version:{signature_version}")
        logger.info(f"  Latest Engine Version   :{engine_version}")
        return
    else:
        logger.info("Using existing signature database")
        signature_version = get_latest_signature_version(os.path.join(cache_dir,"vdm"))
        engine_version = get_latest_engine_version(os.path.join(cache_dir,"engine"))

        logger.info(f"  Latest Signature Version:{signature_version}")
        logger.info(f"  Latest Engine Version   :{engine_version}")

        if not signature_version:
            logger.error("No signature version found. Please download the latest signature database with --download option.")
            sys.exit(1)

    # iterate through mpav and mpas - each can take a lot of memory
    for name in ["mpav","mpas"]:
        vdm: Vdm = None

        if args.frompickle:  # Load from cache/*.vdm.pickle
            logger.info(f"Loading vdm cache: {cache_dir}")
            vdm = Vdm.make_from_cache(cache_dir,name)
            logger.info("VDM from cache: signatures: {}  threats: {}".format(
                len(vdm.signatures),
                len(vdm.threats)))
        else:  # convert from the latest signature files: cache/[engine, vdm] (takes some time)
            major_version = ".".join(signature_version.split(".")[0:2])
            minor_version = ".".join(signature_version.split(".")[2:4])
            vdm_base_path = os.path.join(cache_dir,"vdm",major_version,'0.0')
            vdm_delta_path = os.path.join(cache_dir,"vdm",major_version,minor_version)
            base_file = os.path.join(vdm_base_path,name+"base.vdm")
            delta_file = os.path.join(vdm_delta_path,name+"dlta.vdm")
        
            logger.info(f"Loading base signature file: {base_file}")
            logger.info(f"Creating vdm from files: {vdm_base_path}")
            vdm = Vdm(base_file)
            vdm.parse_files()
            if os.path.exists(delta_file):
                logger.info(f"Applying delta patch: {delta_file}")
                vdm.apply_delta_vdm(delta_file)

        #logger.info(f"VDM Target signature version: {vdm.version}")
        #logger.info(f"VDM Target signature type   : {vdm.vdm_type}")

        if args.topickle:
            vdm.write_cache(cache_dir, name)
            logger.info("Pickle Cache written to: {}".format(os.path.join(cache_dir, name + ".vdm.pickle")))
        elif args.convert:
            # convert threats to database
            convert_threats(vdm)
        elif args.asr:
            # extract ASR entries
            parse_asr(vdm)
        else:
            # extract ASR entries - around 24
            #parse_asr(vdm)

            # extract all threats with LUA
            #parse_threat_lua(vdm)

            # extract all LUA - around 50k, including ASR
            #parse_sig_lua(vdm, name)

            # extract all threats
            #parse_threats(vdm, search="Bearfoos.A!ml")

            # find a threat
            #find = "Bearfoos.A"
            #logger.info(f"Searching for threats with name: {find}")
            #parse_threats(vdm, search=find)

            pass

    logger.info("Complete")
    sys.exit(0)
