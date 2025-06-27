from defender2yara.defender.dbthreat import db, DbThreat
import pickle


#  DbThreat:
#    name = CharField()
#    sigs = CharField()
#    sigcount = IntegerField()
#    threatObject = BlobField() = NiceThreat object serialized with pickle


def main():
    db.connect()
    dbThreats = DbThreat.select().where(DbThreat.name.contains(""))

    for n, dbThreat in enumerate(dbThreats):
        niceThreat = pickle.loads(dbThreat.threatObject)

        print(f"Threat Name: {dbThreat.name}")
        print(f"  Signatures: {dbThreat.sigs}")
        print(f"  Sig num: {dbThreat.sigcount}")
        
        print(f"  Lua scripts: {len(niceThreat.lua_scripts)}")
        print(f"  Yara rules: {len(niceThreat.yara_rules)}")

        #for lua_script in niceThreat.lua_scripts:
        #    print(lua_script)

        #for yara_rule in niceThreat.yara_rules:
        #    print(yara_rule)

        if n == 10:
            print("Stopping after 10 threats.")
            break

    db.close()


if __name__ == '__main__':
    main()
    