# stix2arango notes

A short doc showing some arangodb queries of the ransomwhere-bundle.json once impored to arango

## Import to stix2arango

https://github.com/muchdogesec/stix2arango/

```shell
python3 stix2arango.py \
  --file PATH/TO/ransomwhere-bundle.json \
  --database ransomwhere \
  --collection ransomwhere \
  --ignore_embedded_relationships true
```

## Searches

Get all Malware names 

```sql
FOR doc IN ransomwhere_vertex_collection
    FILTER doc.type == "malware"
    SORT doc.name
    RETURN {
        ransomwhere_name: doc.name,
        created_stix_object_id: doc.id
        }
```

Map this list to MIRTE ATT&CK

```sql
LET names = [
    "7ev3n", "AES-NI", "Akira", "Ako", "AlbDecryptor", "APT", "Avaddon", "AvosLocker", "Bagli", 
    "Bitpaymer / DoppelPaymer", "Black Basta", "Black Kingdom", "Black Mamba", "Black Ruby", 
    "BlackCat", "BlackMatter", "BlackRouter", "Bucbi", "Chimera", "ChupaCabra", "ComradeCircle", 
    "Conti", "CryptConsole", "Cryptohitman", "CryptoHost", "CryptoLocker", "CryptoTorLocker2015", 
    "Cryptowall", "CryptXXX", "CTB-Locker", "Cuba", "darkangels", "DarkSide", "DeadBolt", 
    "DecryptIomega", "Decryptiomega", "DMALocker", "DMALockerv3", "Ecovector", "EDA2", "Egregor", 
    "Encrpt3d", "Exotic", "File-Locker", "Flyper", "Git", "Globe", "GlobeImposter", "Globev3", 
    "Gula", "HC6/HC7", "HelloKitty", "Hive", "JigSaw", "Jigsaw", "Karakurt", "Kelly", "LamdaLocker", 
    "LockBit", "LockBit 2.0", "LockOn", "Locky", "Makop", "Mallox", "Maui", "MedusaLocker", 
    "MountLocker", "Netwalker (Mailto)", "NoobCrypt", "NotNevada", "NotPetya", "NullByte", "Phobos", 
    "Phoenix", "PopCornTime", "Predator", "Qlocker", "Quantum", "Qweuirtksd", "RagnarLocker", 
    "Ransomnix", "Ranzy Locker", "Razy", "REvil / Sodinokibi", "Ryuk", "Sam", "SamSam", "Spora", 
    "StorageCrypter", "SunCrypt", "SynAck", "Tejodes", "TeslaCrypt", "TowerWeb", "TripleM", 
    "Vega / Jamper / Buran", "VenusLocker", "Vevolocker", "WannaCry", "WannaRen", "WannaSmile", 
    "XLocker", "XLockerv5.0", "Xorist", "XTPLocker"
]

LET results = (
    FOR name IN names
        LET lowerName = LOWER(name)
        LET doc = FIRST(
            FOR d IN mitre_attack_enterprise_vertex_collection
                FILTER d.type == "malware" AND (LOWER(d.name) == lowerName OR lowerName IN LOWER(d.aliases[*]))
                LET attack_id = FIRST(
                    FOR ref IN d.external_references
                        FILTER ref.source_name == "mitre-attack"
                        RETURN ref.external_id
                )
                RETURN { name: d.name, id: d.id, attack_id: attack_id }
        )
        RETURN {
            name: name,
            id: doc ? doc.id : null,
            attack_id: doc ? doc.attack_id : null
        }
)
LET sortedResults = (
    FOR r IN results
    SORT r.name
    RETURN r
)

RETURN sortedResults

```