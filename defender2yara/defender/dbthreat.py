from peewee import Model, CharField, SqliteDatabase, BlobField, IntegerField
from defender2yara.defender.threat import Threat


db = SqliteDatabase('cache/threats.db')

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

