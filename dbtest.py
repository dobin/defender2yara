from peewee import Model, CharField, SqliteDatabase, BlobField, IntegerField
import pickle

# import threat
from defender2yara.defender.threat import Threat

db = SqliteDatabase('threats.db')

class BaseModel(Model):
    class Meta:
        database = db

class DbThreat(BaseModel):
    name = CharField()
    sigs = CharField()
    sigcount = IntegerField()
    threatObject = BlobField()


class NiceThreat():
    def __init__(self, threat:Threat):
        self.name = threat.threat_name
        self.id = threat.threat_id
        self.category = threat.category_id
        self.severity = threat.severity
        self.type = threat.threat_type
        self.platform = threat.threat_platform
        self.family = threat.threat_family
        self.variant = threat.threat_variant
        self.suffixes = threat.threat_suffixes

        self.signatures = threat.signatures
        self.lua_scripts = []
        self.yara_rules= []

    def __str__(self):
        return f"{self.name} ({self.id}) - {self.type} {self.platform} {self.family} {self.variant}"



def main():
    db.connect()
    dbThreats = DbThreat.select().where(DbThreat.name.contains(""))

    for dbThreat in dbThreats:
        niceThreat = pickle.loads(dbThreat.threatObject)

        if len(niceThreat.lua_scripts) > 0 or len(niceThreat.yara_rules) > 0:
            print(f"Threat Name: {dbThreat.name}")
            print(f"  Signatures: {dbThreat.sigs}")
            print(f"  Sig num: {dbThreat.sigcount}")
            
            print(f"  Lua scripts: {len(niceThreat.lua_scripts)}")
            print(f"  Yara rules: {len(niceThreat.yara_rules)}")

            for lua_script in niceThreat.lua_scripts:
                print(lua_script)

            for yara_rule in niceThreat.yara_rules:
                print(yara_rule)


    db.close()


if __name__ == '__main__':
    main()
    