import json
import os
import re
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from confluent_kafka import Consumer, KafkaError
from neo4j import GraphDatabase

# ──────────────────────────────────────────────────────────────────────
#  CONFIGURACIÓN
# ──────────────────────────────────────────────────────────────────────
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASSWORD", "skyfall2026")
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "kafka:29092")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "cg-neo4j-universal")
KAFKA_TOPICS = os.getenv("KAFKA_TOPICS", "enrichment.results").split(",")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("Skyfall-Neo4j")

# ──────────────────────────────────────────────────────────────────────
#  MOTOR DE INGESTA UNIVERSAL
# ──────────────────────────────────────────────────────────────────────

class SkyfallNeo4jIngestor:
    CWE_TO_MITRE: Dict[str, List[str]] = {
        "CWE-913": ["T1059", "T1203"],
        "CWE-78":  ["T1059.004"],
        "CWE-89":  ["T1190"],
        "CWE-22":  ["T1083", "T1055"],
        "CWE-79":  ["T1059.007"],
        "CWE-94":  ["T1059", "T1055"],
        "CWE-190": ["T1499"],
        "CWE-416": ["T1203"],
        "CWE-502": ["T1059"],
        "CWE-20":  ["T1190"],
        "CWE-918": ["T1190", "T1210"],
        "CWE-288": ["T1078"],
        "CWE-306": ["T1078", "T1133"],
    }

    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        self._create_constraints()

    def _create_constraints(self):
        """Prepara el esquema de la DB para búsquedas rápidas."""
        with self.driver.session() as s:
            # Constraints de unicidad por label semántico (sin :StixObject)
            SEMANTIC_LABELS = [
                "IP", "Domain", "URL", "Email", "File",
                "Indicator", "Malware", "Technique", "Tool",
                "ThreatActor", "IntrusionSet", "Campaign",
                "Infrastructure", "Vulnerability", "Mitigation",
                "Location", "Identity", "Report", "Software",
                "NetworkTraffic", "ObservedData", "Sighting",
            ]
            for lbl in SEMANTIC_LABELS:
                try:
                    s.run(
                        f"CREATE CONSTRAINT {lbl.lower()}_id_unique IF NOT EXISTS "
                        f"FOR (n:{lbl}) REQUIRE n.id IS UNIQUE"
                    )
                except Exception as e:
                    log.warning(f"Constraint {lbl}_id_unique: {e}")
            # Índices auxiliares por label semántico específico
            for idx_name, lbl, prop in [
                ("stix_value_idx",    "Indicator",     "value"),
                ("stix_mitre_id",     "Technique",     "x_mitre_id"),
                ("stix_otx_pulse_id", "Indicator",     "x_otx_pulse_id"),
                ("stix_country_code", "Location",      "country_code"),
                ("stix_asn",          "Infrastructure", "asn"),
            ]:
                try:
                    s.run(f"CREATE INDEX {idx_name} IF NOT EXISTS FOR (n:{lbl}) ON (n.{prop})")
                except Exception as e:
                    log.warning(f"Index {idx_name}: {e}")

    @staticmethod
    def _flatten(data: Any) -> Any:
        """Serializa diccionarios/listas para propiedades de Neo4j.
        Convierte tipos no soportados a strings seguros."""
        import math
        if isinstance(data, (dict, list)):
            return json.dumps(data, default=str)
        if isinstance(data, float):
            if math.isnan(data) or math.isinf(data):
                return None
            # Floats enteros (ej. 15169.0) → int para evitar 22NB1
            if data == int(data):
                return int(data)
            return data
        if isinstance(data, bool):
            return data
        return data

    @staticmethod
    def _coerce_float(value: Any) -> Any:
        """Convert numeric strings to float when possible, preserving other values."""
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            txt = value.strip().replace(",", ".")
            try:
                return float(txt)
            except Exception:
                return value
        return value

    @staticmethod
    def _extract_cwe_id(text: str | None) -> str | None:
        """Extract CWE identifier (e.g. CWE-79) from free text."""
        if not text:
            return None
        m = re.search(r"\bCWE-\d+\b", str(text).upper())
        return m.group(0) if m else None

    @staticmethod
    def _extract_cve_id(text: str | None) -> str | None:
        """Extract CVE identifier (e.g. CVE-2025-68613) from free text."""
        if not text:
            return None
        m = re.search(r"\bCVE-\d{4}-\d{4,7}\b", str(text).upper())
        return m.group(0) if m else None

    @staticmethod
    def _build_descriptive_cve_name(node: Dict[str, Any]) -> tuple[str | None, str | None]:
        """Build a readable CVE display name and return (cve_id, display_name)."""
        cve_id = (
            SkyfallNeo4jIngestor._extract_cve_id(node.get("name"))
            or SkyfallNeo4jIngestor._extract_cve_id(node.get("external_id"))
            or SkyfallNeo4jIngestor._extract_cve_id(node.get("id"))
            or SkyfallNeo4jIngestor._extract_cve_id(node.get("x_cve_id"))
        )

        if not cve_id:
            refs = node.get("external_references") or []
            if isinstance(refs, str):
                try:
                    refs = json.loads(refs)
                except Exception:
                    refs = []
            if isinstance(refs, list):
                for ref in refs:
                    if not isinstance(ref, dict):
                        continue
                    cve_id = (
                        SkyfallNeo4jIngestor._extract_cve_id(ref.get("external_id"))
                        or SkyfallNeo4jIngestor._extract_cve_id(ref.get("url"))
                        or SkyfallNeo4jIngestor._extract_cve_id(ref.get("description"))
                    )
                    if cve_id:
                        break

        if not cve_id:
            return None, None

        title_candidates = [
            node.get("name"),
            node.get("x_title"),
            node.get("description"),
        ]

        title = ""
        for candidate in title_candidates:
            if not candidate:
                continue
            value = str(candidate).strip()
            if not value:
                continue
            value = re.sub(r"\bCVE-\d{4}-\d{4,7}\b\s*[-:–]?\s*", "", value, flags=re.IGNORECASE).strip()
            if value:
                title = value.split(".")[0][:160].strip()
                break

        display_name = f"{cve_id} - {title}" if title else cve_id
        return cve_id, display_name

    @staticmethod
    def _build_descriptive_cwe_name(node: Dict[str, Any]) -> tuple[str | None, str | None]:
        """Build a readable CWE display name and return (cwe_id, display_name)."""
        cwe_id = (
            SkyfallNeo4jIngestor._extract_cwe_id(node.get("name"))
            or SkyfallNeo4jIngestor._extract_cwe_id(node.get("x_mitre_id"))
            or SkyfallNeo4jIngestor._extract_cwe_id(node.get("external_id"))
            or SkyfallNeo4jIngestor._extract_cwe_id(node.get("x_cwe_id"))
        )
        if not cwe_id:
            refs = node.get("external_references") or []
            if isinstance(refs, str):
                try:
                    refs = json.loads(refs)
                except Exception:
                    refs = []
            if isinstance(refs, list):
                for ref in refs:
                    if isinstance(ref, dict):
                        cwe_id = SkyfallNeo4jIngestor._extract_cwe_id(ref.get("external_id"))
                        if cwe_id:
                            break
        if not cwe_id:
            return None, None

        title_candidates = [
            node.get("x_cwe_name"),
            node.get("x_name"),
            node.get("name"),
            node.get("description"),
        ]

        title = ""
        for candidate in title_candidates:
            if not candidate:
                continue
            value = str(candidate).strip()
            if not value:
                continue
            if SkyfallNeo4jIngestor._extract_cwe_id(value) == value.upper().strip():
                continue
            value = re.sub(r"^\s*CWE-\d+\s*[-:–]?\s*", "", value, flags=re.IGNORECASE).strip()
            if value:
                title = value.split(".")[0][:140].strip()
                break

        display_name = f"{cwe_id} - {title}" if title else cwe_id
        return cwe_id, display_name

    @staticmethod
    def _extract_attack_mitre_ids(node: Dict[str, Any]) -> List[str]:
        """Extract ATT&CK technique IDs (Txxxx[/sub-technique]) from an attack-pattern-like object."""
        raw_ids: List[str] = []

        for field in ("x_mitre_id", "external_id", "x_mitre_ids", "mitre_attack_ids", "attack_ids", "name"):
            value = node.get(field)
            if isinstance(value, str):
                raw_ids.extend(re.findall(r"T\d{4}(?:\.\d{3})?", value.upper()))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        raw_ids.extend(re.findall(r"T\d{4}(?:\.\d{3})?", item.upper()))

        refs = node.get("external_references") or []
        if isinstance(refs, str):
            try:
                refs = json.loads(refs)
            except Exception:
                refs = []
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                for field in ("external_id", "url", "description"):
                    value = ref.get(field)
                    if isinstance(value, str):
                        raw_ids.extend(re.findall(r"T\d{4}(?:\.\d{3})?", value.upper()))

        return sorted(set(raw_ids))

    @staticmethod
    def _mitre_ids_from_cwe(cwe_id: str | None) -> List[str]:
        if not cwe_id:
            return []
        return SkyfallNeo4jIngestor.CWE_TO_MITRE.get(cwe_id.upper(), [])

    @staticmethod
    def _extract_indicator_observable(indicator: Dict[str, Any]) -> Dict[str, str] | None:
        """Extract observable type/value from a simple STIX indicator pattern.
        Supports patterns like: [ipv4-addr:value = '1.2.3.4']
        """
        pattern = indicator.get("pattern")
        if not pattern or not isinstance(pattern, str):
            return None
        m = re.search(r"\[(ipv4-addr|ipv6-addr|domain-name|url|email-addr|file):value\s*=\s*'([^']+)'\]", pattern)
        if not m:
            return None
        return {"type": m.group(1), "value": m.group(2)}

    @staticmethod
    def _consolidate_ioc_nodes(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Keep a single central IOC node by collapsing observable nodes referenced by BASED_ON.
        The observable payload is merged into the Indicator and relationships are rewritten.
        """
        by_id: Dict[str, Dict[str, Any]] = {o.get("id"): o for o in objects if o.get("id")}

        rels = [o for o in objects if o.get("type") == "relationship"]
        alias_map: Dict[str, str] = {}

        OBS_TYPES = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "file"}

        for rel in rels:
            rtype = (rel.get("relationship_type") or "").lower()
            if rtype not in ("based-on", "based_on"):
                continue
            src = rel.get("source_ref")
            tgt = rel.get("target_ref")
            src_obj = by_id.get(src)
            tgt_obj = by_id.get(tgt)
            if not src_obj or not tgt_obj:
                continue
            if src_obj.get("type") != "indicator" or tgt_obj.get("type") not in OBS_TYPES:
                continue

            if not src_obj.get("name"):
                src_obj["name"] = tgt_obj.get("value") or src_obj.get("id")
            if not src_obj.get("value") and tgt_obj.get("value"):
                src_obj["value"] = tgt_obj.get("value")
            if not src_obj.get("x_ioc_type"):
                src_obj["x_ioc_type"] = tgt_obj.get("type")

            for key in ("country", "country_code", "city", "asn", "reputation", "pulse_count", "x_otx_tags"):
                if src_obj.get(key) is None and tgt_obj.get(key) is not None:
                    src_obj[key] = tgt_obj.get(key)

            alias_map[tgt] = src

        rewritten: List[Dict[str, Any]] = []
        for obj in objects:
            if obj.get("type") == "relationship":
                rtype = (obj.get("relationship_type") or "").lower()
                if rtype in ("based-on", "based_on"):
                    continue
                source_ref = alias_map.get(obj.get("source_ref"), obj.get("source_ref"))
                target_ref = alias_map.get(obj.get("target_ref"), obj.get("target_ref"))
                if source_ref == target_ref:
                    continue
                new_obj = dict(obj)
                new_obj["source_ref"] = source_ref
                new_obj["target_ref"] = target_ref
                rewritten.append(new_obj)
                continue

            oid = obj.get("id")
            if oid in alias_map:
                continue

            if obj.get("type") == "report" and not obj.get("name"):
                refs = obj.get("object_refs") or []
                if refs:
                    obj = dict(obj)
                    obj["name"] = f"Report {obj.get('id', '')[-8:]}"
            rewritten.append(obj)

        return rewritten

    @staticmethod
    def _normalize_weakness_objects(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize non-standard CWE modeling to ATT&CK-compatible STIX semantics.

        - weakness -> attack-pattern (Technique)
        - vulnerability DERIVED_FROM weakness -> HAS_WEAKNESS
        """
        by_id: Dict[str, Dict[str, Any]] = {o.get("id"): o for o in objects if o.get("id")}
        alias_map: Dict[str, str] = {}

        for obj in objects:
            if obj.get("type") != "weakness":
                continue
            oid = obj.get("id")
            if not oid:
                continue
            if oid.startswith("weakness--"):
                alias_map[oid] = "attack-pattern--" + oid.split("--", 1)[1]
            else:
                alias_map[oid] = oid

        rewritten: List[Dict[str, Any]] = []

        for obj in objects:
            if obj.get("type") == "weakness":
                new_obj = dict(obj)
                new_obj["type"] = "attack-pattern"
                oid = new_obj.get("id")
                if oid in alias_map:
                    new_obj["id"] = alias_map[oid]
                rewritten.append(new_obj)
                continue

            if obj.get("type") == "relationship":
                rtype = (obj.get("relationship_type") or "").lower()
                src = alias_map.get(obj.get("source_ref"), obj.get("source_ref"))
                tgt = alias_map.get(obj.get("target_ref"), obj.get("target_ref"))
                src_obj = by_id.get(obj.get("source_ref")) or by_id.get(src) or {}
                tgt_obj = by_id.get(obj.get("target_ref")) or by_id.get(tgt) or {}

                new_obj = dict(obj)
                new_obj["source_ref"] = src
                new_obj["target_ref"] = tgt

                if (
                    rtype in ("derived-from", "derived_from")
                    and src_obj.get("type") == "vulnerability"
                    and tgt_obj.get("type") in ("weakness", "attack-pattern")
                ):
                    new_obj["relationship_type"] = "has-weakness"
                    rewritten.append(new_obj)
                    continue

                rewritten.append(new_obj)
                continue

            rewritten.append(obj)

        return rewritten

    def _canonicalize_techniques_by_mitre(self, objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Canonicalize attack-pattern IDs using ATT&CK IDs (Txxxx) to avoid duplicate techniques.

        Strategy:
        - Resolve a canonical Technique already present in DB when possible.
        - Otherwise keep one canonical Technique inside the incoming bundle.
        - Rewrite all references to use the canonical ID and drop aliased duplicates.
        """
        def _is_cwe_attack_pattern(node: Dict[str, Any]) -> bool:
            cwe_id, _ = SkyfallNeo4jIngestor._build_descriptive_cwe_name(node)
            if cwe_id:
                return True
            name = str(node.get("name") or "").upper().strip()
            return name.startswith("CWE-")

        attack_patterns = [o for o in objects if o.get("type") == "attack-pattern" and o.get("id")]
        attack_patterns = [o for o in attack_patterns if not _is_cwe_attack_pattern(o)]
        if not attack_patterns:
            return objects

        def _extract_mitre_id(node: Dict[str, Any]) -> str | None:
            mids = SkyfallNeo4jIngestor._extract_attack_mitre_ids(node)
            return mids[0] if mids else None

        by_mitre: Dict[str, List[Dict[str, Any]]] = {}
        for ap in attack_patterns:
            mid = _extract_mitre_id(ap)
            if mid:
                by_mitre.setdefault(mid, []).append(ap)

        if not by_mitre:
            return objects

        db_canonical_by_mitre: Dict[str, str] = {}
        with self.driver.session() as s:
            for mid in by_mitre.keys():
                rec = s.run("""
                MATCH (t:Technique)
                WHERE t.external_id = $mid OR t.x_mitre_id = $mid
                RETURN t.id AS id, t.external_id AS ext, t.x_source AS src
                ORDER BY CASE WHEN t.external_id = $mid THEN 0 ELSE 1 END,
                         CASE WHEN t.x_source IS NULL OR t.x_source = 'MITRE' THEN 0 ELSE 1 END,
                         t.id
                LIMIT 1
                """, mid=mid).single()
                if rec and rec.get("id"):
                    db_canonical_by_mitre[mid] = rec["id"]

        alias_map: Dict[str, str] = {}

        for mid, aps in by_mitre.items():
            # Keep canonical in-bundle candidate if no DB canonical exists.
            preferred_bundle = sorted(
                aps,
                key=lambda n: (
                    0 if (n.get("external_id") or "").upper() == mid else 1,
                    0 if (n.get("x_source") in (None, "", "MITRE")) else 1,
                    n.get("id"),
                ),
            )[0]["id"]

            canonical_id = db_canonical_by_mitre.get(mid, preferred_bundle)
            for ap in aps:
                if ap["id"] != canonical_id:
                    alias_map[ap["id"]] = canonical_id

        if not alias_map:
            return objects

        rewritten: List[Dict[str, Any]] = []
        for obj in objects:
            if obj.get("type") == "relationship":
                new_obj = dict(obj)
                src = alias_map.get(new_obj.get("source_ref"), new_obj.get("source_ref"))
                tgt = alias_map.get(new_obj.get("target_ref"), new_obj.get("target_ref"))
                if src == tgt:
                    continue
                new_obj["source_ref"] = src
                new_obj["target_ref"] = tgt
                rewritten.append(new_obj)
                continue

            oid = obj.get("id")
            if oid in alias_map:
                continue

            new_obj = dict(obj)
            if new_obj.get("type") == "sighting":
                if new_obj.get("sighting_of_ref") in alias_map:
                    new_obj["sighting_of_ref"] = alias_map[new_obj["sighting_of_ref"]]
                refs = new_obj.get("where_sighted_refs") or []
                if isinstance(refs, list):
                    new_obj["where_sighted_refs"] = [alias_map.get(r, r) for r in refs]
            elif new_obj.get("type") in ("note", "report"):
                refs = new_obj.get("object_refs") or []
                if isinstance(refs, list):
                    new_obj["object_refs"] = [alias_map.get(r, r) for r in refs]

            rewritten.append(new_obj)

        return rewritten

    def ingest_bundle(self, bundle_dict: Dict[str, Any]):
        """Procesa el bundle dividiendo en Nodos y Relaciones."""
        objects = bundle_dict.get("objects", [])
        if not objects: return

        objects = self._normalize_weakness_objects(objects)
        objects = self._canonicalize_techniques_by_mitre(objects)
        objects = self._consolidate_ioc_nodes(objects)

        # Deduplicar por id para evitar conflictos en MERGE cuando el bundle
        # repite objetos (p.ej. bundles CVE con attack-pattern duplicado)
        seen_ids: Dict[str, Any] = {}
        for o in objects:
            oid = o.get("id")
            if oid and oid not in seen_ids:
                seen_ids[oid] = o
        objects = list(seen_ids.values())

        nodes = [o for o in objects if o["type"] != "relationship"]
        rels = [o for o in objects if o["type"] == "relationship"]

        with self.driver.session() as session:
            # 1. Upsert de Nodos (Enriquecimiento)
            session.execute_write(self._merge_nodes, nodes)
            # 1a. Normalizar nombres legibles de nodos críticos (CVE/CWE)
            session.execute_write(self._normalize_display_names, nodes)
            # 1b. Ensure report nodes have meaningful names based on referenced IOCs
            session.execute_write(self._name_reports, nodes)
            # 2. Normalizar nombres de Location del bundle (antes de crear relaciones)
            session.execute_write(self._normalize_location_names, nodes)
            # 3. Upsert de Relaciones explícitas STIX
            session.execute_write(self._merge_rels, rels)
            # 3b. Mantener cadena CWE -> ATT&CK Technique (Txxxx)
            session.execute_write(self._link_cwe_to_mitre_techniques, nodes, rels)
            # 4. Aristas implícitas: sighting_of_ref, where_sighted_refs, object_refs
            session.execute_write(self._merge_implicit_rels, nodes)
            # 5. Materializar nodos País canónicos y vincular IOCs
            session.execute_write(self._materialize_country_nodes, nodes)
            # 6. Deduplicar nodos Location con mismo country code
            session.execute_write(self._dedup_locations)
            # 7. Materializar nodos Campaign por pulso OTX
            session.execute_write(self._materialize_otx_campaign_nodes, nodes)
            # 8. Materializar nodos Infrastructure por ASN
            session.execute_write(self._materialize_asn_nodes, nodes)
            # 9. Correlación por tags OTX compartidos
            session.execute_write(self._correlate_otx_tags, nodes)
            # 9b. Correlate IOCs with pre-loaded MITRE techniques using ATT&CK IDs
            session.execute_write(self._correlate_ioc_exhibits_with_mitre, nodes)
            # 10. Correlación con MITRE y Geopolítica (C01-C23+)
            session.execute_write(self._run_autocorrelation, nodes)
            # 11. Correlación Vulnerabilidades ↔ IOCs / Malware / ThreatActors
            session.execute_write(self._correlate_vulnerabilities, nodes)
            # 12. Cadenas de infección: INDICATES + bridge CWE→CVE + cadena completa
            session.execute_write(self._correlate_infection_chains, nodes)

    @staticmethod
    def _merge_nodes(tx, nodes):
        # Un único label semántico por tipo STIX
        LABEL: Dict[str, str] = {
            "ipv4-addr":         "IP",
            "ipv6-addr":         "IP",
            "domain-name":       "Domain",
            "url":               "URL",
            "email-addr":        "Email",
            "file":              "File",
            "network-traffic":   "NetworkTraffic",
            "indicator":         "Indicator",
            "malware":           "Malware",
            "attack-pattern":    "Technique",
            "weakness":          "Technique",
            "tool":              "Tool",
            "threat-actor":      "ThreatActor",
            "intrusion-set":     "IntrusionSet",
            "campaign":          "Campaign",
            "infrastructure":    "Infrastructure",
            "vulnerability":     "Vulnerability",
            "course-of-action":  "Mitigation",
            "location":          "Location",
            "identity":          "Identity",
            "report":            "Report",
            "note":              "Note",
            "observed-data":     "ObservedData",
            "sighting":          "Sighting",
            "relationship":      "Relationship",
            "software":          "Software",
            "x-software":        "Software",
        }

        for node in nodes:
            stix_id = node.get("id")
            stix_type = node.get("type")
            label = LABEL.get(stix_type, stix_type.replace("-", "_").capitalize())

            props = {}
            for k, v in node.items():
                if k in ("id", "type") or v is None:
                    continue

                if k in ("x_cvss_score", "x_epss_score", "x_epss_percentile"):
                    v = SkyfallNeo4jIngestor._coerce_float(v)

                flat = SkyfallNeo4jIngestor._flatten(v)
                if flat is not None:
                    props[k] = flat

            # Normalize CWE technique naming to a descriptive format.
            if stix_type in ("attack-pattern", "weakness"):
                cwe_id, cwe_display_name = SkyfallNeo4jIngestor._build_descriptive_cwe_name(node)
                if cwe_id:
                    props["name"] = cwe_display_name
                    props["x_cwe_id"] = cwe_id
                    props["x_mitre_id"] = props.get("x_mitre_id") or cwe_id
                    props["external_id"] = props.get("external_id") or cwe_id
                else:
                    mitre_ids = SkyfallNeo4jIngestor._extract_attack_mitre_ids(node)
                    if mitre_ids:
                        props["x_mitre_id"] = props.get("x_mitre_id") or mitre_ids[0]
                        props["external_id"] = props.get("external_id") or mitre_ids[0]
                        props["name"] = props.get("name") or mitre_ids[0]

            # Normalize CVE vulnerability naming to a descriptive format.
            if stix_type == "vulnerability":
                cve_id, cve_display_name = SkyfallNeo4jIngestor._build_descriptive_cve_name(node)
                if cve_id:
                    props["name"] = cve_display_name
                    props["x_cve_id"] = cve_id
                    props["external_id"] = props.get("external_id") or cve_id

            try:
                query = f"""
                MERGE (n:{label} {{id: $id}})
                SET n.type = $type, n += $props, n.last_enriched = datetime()
                WITH n
                WHERE n.name IS NULL AND n.value IS NOT NULL
                SET n.name = n.value
                """
                tx.run(query, id=stix_id, type=stix_type, props=props)
            except Exception as e:
                log.warning(f"[merge_nodes] Error en nodo {stix_id} ({stix_type}): {e}")

    @staticmethod
    def _normalize_display_names(tx, nodes):
        """Ensure human-readable names for key entities, even for pre-existing nodes."""
        for node in nodes:
            ntype = node.get("type")
            nid = node.get("id")
            if not nid:
                continue

            if ntype == "vulnerability":
                tx.run("""
                MATCH (v:Vulnerability {id: $id})
                WITH v,
                     coalesce(v.x_cve_id,
                              v.external_id,
                              replace(toUpper(v.id), 'VULNERABILITY--', '')) AS cve
                SET v.x_cve_id = cve,
                    v.external_id = coalesce(v.external_id, cve),
                    v.name = CASE
                        WHEN v.name IS NULL OR trim(v.name) = '' THEN cve
                        WHEN toUpper(v.name) STARTS WITH cve THEN v.name
                        ELSE cve + ' - ' + v.name
                    END,
                    v.last_enriched = datetime()
                """, id=nid)

            elif ntype == "attack-pattern":
                tx.run("""
                MATCH (t:Technique {id: $id})
                WITH t,
                     coalesce(t.x_cwe_id,
                              CASE WHEN t.external_id STARTS WITH 'CWE-' THEN t.external_id ELSE NULL END,
                              CASE WHEN toUpper(t.name) STARTS WITH 'CWE-' THEN split(toUpper(t.name), ':')[0] ELSE NULL END) AS cwe
                WHERE cwe IS NOT NULL
                SET t.x_cwe_id = cwe,
                    t.external_id = coalesce(t.external_id, cwe),
                    t.name = CASE
                        WHEN t.name IS NULL OR trim(t.name) = '' THEN cwe
                        WHEN toUpper(t.name) STARTS WITH cwe THEN t.name
                        ELSE cwe + ' - ' + t.name
                    END,
                    t.last_enriched = datetime()
                """, id=nid)

    @staticmethod
    def _merge_rels(tx, rels):
        for rel in rels:
            # relationship_type: located-at -> LOCATED_AT
            rel_type = rel["relationship_type"].upper().replace("-", "_")

            # Almacenar todas las propiedades escalares en la arista
            edge_props = {k: SkyfallNeo4jIngestor._flatten(v)
                          for k, v in rel.items()
                          if k not in ["id", "type", "relationship_type",
                                       "source_ref", "target_ref"] and v is not None}

            query = f"""
            MATCH (a {{id: $source_ref}})
            MATCH (b {{id: $target_ref}})
            MERGE (a)-[r:{rel_type} {{id: $id}}]->(b)
            SET r += $props
            """
            tx.run(query,
                   id=rel["id"],
                   source_ref=rel["source_ref"],
                   target_ref=rel["target_ref"],
                   props=edge_props)

    @staticmethod
    def _link_cwe_to_mitre_techniques(tx, nodes, rels=None):
        """Preserve full chain Vulnerability -> CWE -> ATT&CK Technique.

        For every CWE-like attack-pattern in the bundle, ensure a relationship
        from that CWE node to the ATT&CK technique(s) referenced as Txxxx.
        """
        _MITRE_NS = uuid.UUID("f92dd8ed-1424-4fd2-bf0a-7a7be4d17cdf")

        def _canonical_mitre_node_id(mid: str) -> str:
            return "attack-pattern--" + str(uuid.uuid5(_MITRE_NS, f"mitre:{mid}"))

        by_id: Dict[str, Dict[str, Any]] = {n.get("id"): n for n in nodes if n.get("id")}
        explicit_mid_by_cwe: Dict[str, set[str]] = {}

        for rel in (rels or []):
            if rel.get("type") != "relationship":
                continue
            rtype = (rel.get("relationship_type") or "").lower().replace("_", "-")
            if rtype not in ("related-to", "uses", "leverages", "maps-to", "mapped-to"):
                continue

            src_id = rel.get("source_ref")
            tgt_id = rel.get("target_ref")
            src_node = by_id.get(src_id) or {}
            tgt_node = by_id.get(tgt_id) or {}
            if src_node.get("type") != "attack-pattern":
                continue

            src_cwe_id, _ = SkyfallNeo4jIngestor._build_descriptive_cwe_name(src_node)
            if not src_cwe_id:
                continue

            mids = SkyfallNeo4jIngestor._extract_attack_mitre_ids(tgt_node)
            if not mids and isinstance(tgt_id, str):
                mids = re.findall(r"T\d{4}(?:\.\d{3})?", tgt_id.upper())

            if mids:
                explicit_mid_by_cwe.setdefault(src_id, set()).update(mids)

        for node in nodes:
            if node.get("type") != "attack-pattern":
                continue

            cwe_id, _ = SkyfallNeo4jIngestor._build_descriptive_cwe_name(node)
            if not cwe_id:
                continue

            source_id = node.get("id")
            if not source_id:
                continue

            mitre_ids: set[str] = set(SkyfallNeo4jIngestor._extract_attack_mitre_ids(node))
            mitre_ids.update(explicit_mid_by_cwe.get(source_id, set()))
            mitre_ids.update(SkyfallNeo4jIngestor._mitre_ids_from_cwe(cwe_id))

            for mid in sorted(mitre_ids):
                rec = tx.run("""
                MATCH (t:Technique)
                                WHERE t.id <> $source_id
                                    AND (
                                        t.external_id = $mid
                                        OR (
                                                t.x_mitre_id = $mid
                                                AND (t.external_id IS NULL OR NOT t.external_id STARTS WITH 'CWE-')
                                        )
                                    )
                RETURN t.id AS id
                                ORDER BY CASE WHEN t.external_id = $mid THEN 0 ELSE 1 END,
                                                 CASE WHEN coalesce(t.x_source, '') = 'MITRE' THEN 0 ELSE 1 END,
                                                 t.id
                LIMIT 1
                                """, mid=mid, source_id=source_id).single()

                target_id = rec["id"] if rec and rec.get("id") else _canonical_mitre_node_id(mid)

                tx.run("""
                MERGE (t:Technique {id: $tid})
                ON CREATE SET t.type = 'attack-pattern',
                              t.name = $mid,
                              t.external_id = $mid,
                              t.x_mitre_id = $mid,
                              t.x_source = 'MITRE',
                              t.last_enriched = datetime()
                ON MATCH SET  t.external_id = coalesce(t.external_id, $mid),
                              t.x_mitre_id = coalesce(t.x_mitre_id, $mid),
                              t.last_enriched = datetime()
                """, tid=target_id, mid=mid)

                tx.run("""
                MATCH (cwe:Technique {id: $cwe_id})
                MATCH (mitre:Technique {id: $mid_id})
                WHERE cwe.id <> mitre.id
                MERGE (cwe)-[r:RELATED_TO {id: $cwe_id + '_to_' + $mid_id}]->(mitre)
                SET r.correlation = 'C-CWE01_cwe_maps_to_mitre',
                    r.confidence = 85,
                    r.x_cwe_id = $cwe_code,
                    r.x_mitre_id = $mid,
                    r.x_source = 'Skyfall-autocorr'
                """, cwe_id=source_id, mid_id=target_id, cwe_code=cwe_id, mid=mid)

    @staticmethod
    def _merge_implicit_rels(tx, nodes):
        """Crea aristas desde campos de referencia que no son 'relationship' STIX:
        sighting.sighting_of_ref, sighting.where_sighted_refs, note.object_refs."""
        for node in nodes:
            ntype = node.get("type")
            nid = node.get("id")

            if ntype == "sighting":
                # sighting -[SIGHTING_OF]-> indicator
                ref = node.get("sighting_of_ref")
                if ref:
                    tx.run("""
                    MATCH (s {id: $sid})
                    MATCH (t {id: $tid})
                    MERGE (s)-[r:SIGHTING_OF {id: $sid + '_sof_' + $tid}]->(t)
                    SET r.x_source = $src
                    """, sid=nid, tid=ref, src=node.get("x_source", ""))

                # sighting -[SIGHTED_BY]-> identity
                for wref in node.get("where_sighted_refs", []):
                    tx.run("""
                    MATCH (s {id: $sid})
                    MATCH (t {id: $tid})
                    MERGE (s)-[r:SIGHTED_BY {id: $sid + '_sb_' + $tid}]->(t)
                    """, sid=nid, tid=wref)

            elif ntype == "note":
                # note -[REFERENCES]-> objeto
                for oref in node.get("object_refs", []):
                    tx.run("""
                    MATCH (n {id: $nid})
                    MATCH (t {id: $tid})
                    MERGE (n)-[r:REFERENCES {id: $nid + '_ref_' + $tid}]->(t)
                    SET r.x_source = $src
                    """, nid=nid, tid=oref, src=node.get("x_source", ""))

            elif ntype == "indicator":
                # created_by_ref
                cbr = node.get("created_by_ref")
                if cbr:
                    tx.run("""
                    MATCH (i {id: $iid})
                    MATCH (t {id: $tid})
                    MERGE (i)-[r:CREATED_BY {id: $iid + '_cb_' + $tid}]->(t)
                    """, iid=nid, tid=cbr)

    @staticmethod
    def _name_reports(tx, nodes):
        """Assign deterministic names to unnamed report nodes, prioritizing linked IP/domain values."""
        for node in nodes:
            if node.get("type") != "report":
                continue
            if node.get("name"):
                continue
            rid = node.get("id")
            if not rid:
                continue
            tx.run("""
            MATCH (r:Report {id: $rid})
            OPTIONAL MATCH (r)-[:REFERENCES]->(ip:IP)
            OPTIONAL MATCH (r)-[:REFERENCES]->(d:Domain)
            WITH r, ip, d,
                 coalesce(ip.value, d.value, right($rid, 8)) AS ref_value
            SET r.name = 'IOC report ' + ref_value,
                r.last_enriched = datetime()
            """, rid=rid)

    @staticmethod
    def _normalize_location_names(tx, nodes):
        """Normaliza nombres de Location del bundle: 'Germany (DE)' → 'Germany'."""
        import re
        for node in nodes:
            if node.get("type") != "location" or not node.get("country"):
                continue
            name = node.get("name", "")
            # Elimina sufijos tipo " (DE)", " (US)", etc.
            clean_name = re.sub(r'\s*\([A-Z]{2}\)\s*$', '', name).strip()
            if clean_name and clean_name != name:
                tx.run("""
                MATCH (loc:Location {id: $id})
                SET loc.name = $name
                """, id=node["id"], name=clean_name)

    @staticmethod
    def _dedup_locations(tx):
        """Consolida nodos Location duplicados con el mismo country code.
        Elige el canónico (preferencia: Skyfall-autocorr > sin paréntesis > nombre más corto),
        redirige todas sus relaciones entrantes y borra los duplicados."""
        records = tx.run("""
        MATCH (loc:Location)
        WHERE loc.country IS NOT NULL
        WITH loc.country AS cc, collect(loc) AS locs
        WHERE size(locs) > 1
        RETURN cc, locs
        """).data()

        REL_TYPES = ["TARGETS", "ORIGINATES_FROM", "OBSERVED_IN",
                     "LOCATED_IN", "LOCATED_AT", "SAME_AS", "CONSISTS_OF"]

        for row in records:
            locs = row["locs"]

            def _score(l):
                src = l.get("x_source") or ""
                name = l.get("name") or ""
                if src == "Skyfall-autocorr":  return (0, len(name))
                if "(" not in name:            return (1, len(name))
                return (2, len(name))

            canonical_node = min(locs, key=_score)
            canonical_id   = canonical_node["id"]
            dup_ids = [l["id"] for l in locs if l["id"] != canonical_id]

            # Actualizar nombre del canónico al más limpio (sin paréntesis)
            best_name = min((l.get("name") or "" for l in locs), key=len)
            tx.run("MATCH (loc:Location {id: $id}) SET loc.name = $name",
                   id=canonical_id, name=best_name)

            for dup_id in dup_ids:
                for rel_type in REL_TYPES:
                    tx.run(f"""
                    MATCH (src)-[r:{rel_type}]->(dup:Location {{id: $dup_id}})
                    MATCH (can:Location {{id: $can_id}})
                    MERGE (src)-[nr:{rel_type}]->(can)
                    ON CREATE SET nr = properties(r)
                    ON MATCH  SET nr += properties(r)
                    """, dup_id=dup_id, can_id=canonical_id)
                # Borrar duplicado y sus relaciones residuales
                tx.run("MATCH (loc:Location {id: $id}) DETACH DELETE loc",
                       id=dup_id)

    @staticmethod
    def _materialize_country_nodes(tx, nodes):
        """Crea nodos Location por código de país si no existen y los vincula a IOCs.

        Fuentes de países:
          - indicator.x_vt_country          → país de geolocalización (VT)
          - indicator.x_abuseipdb_country_code → país de geolocalización (AbuseIPDB)
          - indicator.x_crowdsec_target_countries → dict {CC: reporter_count}
        """
        # Nombres legibles por código ISO-3166-alpha2
        COUNTRY_NAMES = {
            "AF":"Afghanistan","AL":"Albania","DZ":"Algeria","AD":"Andorra","AO":"Angola",
            "AR":"Argentina","AM":"Armenia","AU":"Australia","AT":"Austria","AZ":"Azerbaijan",
            "BS":"Bahamas","BH":"Bahrain","BD":"Bangladesh","BY":"Belarus","BE":"Belgium",
            "BZ":"Belize","BJ":"Benin","BT":"Bhutan","BO":"Bolivia","BA":"Bosnia and Herzegovina",
            "BW":"Botswana","BR":"Brazil","BN":"Brunei","BG":"Bulgaria","BF":"Burkina Faso",
            "BI":"Burundi","CV":"Cabo Verde","KH":"Cambodia","CM":"Cameroon","CA":"Canada",
            "CF":"Central African Republic","TD":"Chad","CL":"Chile","CN":"China","CO":"Colombia",
            "KM":"Comoros","CD":"Congo (DRC)","CG":"Congo","CR":"Costa Rica","HR":"Croatia",
            "CU":"Cuba","CY":"Cyprus","CZ":"Czech Republic","DK":"Denmark","DJ":"Djibouti",
            "DO":"Dominican Republic","EC":"Ecuador","EG":"Egypt","SV":"El Salvador",
            "GQ":"Equatorial Guinea","ER":"Eritrea","EE":"Estonia","SZ":"Eswatini","ET":"Ethiopia",
            "FJ":"Fiji","FI":"Finland","FR":"France","GA":"Gabon","GM":"Gambia","GE":"Georgia",
            "DE":"Germany","GH":"Ghana","GR":"Greece","GT":"Guatemala","GN":"Guinea","GW":"Guinea-Bissau",
            "GY":"Guyana","HT":"Haiti","HN":"Honduras","HU":"Hungary","IN":"India","ID":"Indonesia",
            "IR":"Iran","IQ":"Iraq","IE":"Ireland","IL":"Israel","IT":"Italy","JM":"Jamaica",
            "JP":"Japan","JO":"Jordan","KZ":"Kazakhstan","KE":"Kenya","KP":"North Korea",
            "KR":"South Korea","KW":"Kuwait","KG":"Kyrgyzstan","LA":"Laos","LV":"Latvia",
            "LB":"Lebanon","LS":"Lesotho","LR":"Liberia","LY":"Libya","LI":"Liechtenstein",
            "LT":"Lithuania","LU":"Luxembourg","MG":"Madagascar","MW":"Malawi","MY":"Malaysia",
            "MV":"Maldives","ML":"Mali","MT":"Malta","MR":"Mauritania","MX":"Mexico","MD":"Moldova",
            "MC":"Monaco","MN":"Mongolia","ME":"Montenegro","MA":"Morocco","MZ":"Mozambique",
            "MM":"Myanmar","NA":"Namibia","NP":"Nepal","NL":"Netherlands","NZ":"New Zealand",
            "NI":"Nicaragua","NE":"Niger","NG":"Nigeria","MK":"North Macedonia","NO":"Norway",
            "OM":"Oman","PK":"Pakistan","PA":"Panama","PG":"Papua New Guinea","PY":"Paraguay",
            "PE":"Peru","PH":"Philippines","PL":"Poland","PT":"Portugal","QA":"Qatar",
            "RO":"Romania","RU":"Russia","RW":"Rwanda","SA":"Saudi Arabia","SN":"Senegal",
            "RS":"Serbia","SL":"Sierra Leone","SG":"Singapore","SK":"Slovakia","SI":"Slovenia",
            "SO":"Somalia","ZA":"South Africa","SS":"South Sudan","ES":"Spain","LK":"Sri Lanka",
            "SD":"Sudan","SR":"Suriname","SE":"Sweden","CH":"Switzerland","SY":"Syria",
            "TW":"Taiwan","TJ":"Tajikistan","TZ":"Tanzania","TH":"Thailand","TL":"Timor-Leste",
            "TG":"Togo","TT":"Trinidad and Tobago","TN":"Tunisia","TR":"Turkey","TM":"Turkmenistan",
            "UG":"Uganda","UA":"Ukraine","AE":"United Arab Emirates","GB":"United Kingdom",
            "US":"United States","UY":"Uruguay","UZ":"Uzbekistan","VE":"Venezuela","VN":"Vietnam",
            "YE":"Yemen","ZM":"Zambia","ZW":"Zimbabwe",
        }

        _GEO_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

        def _country_id(cc: str) -> str:
            return "location--" + str(uuid.uuid5(_GEO_NS, f"country:{cc.upper()}"))

        def ensure_country(tx, cc: str):
            cc = cc.upper()
            canonical_name = COUNTRY_NAMES.get(cc, cc)
            canonical_id   = _country_id(cc)
            # Si ya existe un Location con ese country, reutilizarlo en vez de crear otro.
            # Prioridad: nodo con id canónico (uuid5) > cualquiera con ese country code.
            existing = tx.run("""
            MATCH (loc:Location {country: $cc})
            RETURN loc.id AS lid
            ORDER BY CASE WHEN loc.id = $cid THEN 0 ELSE 1 END
            LIMIT 1
            """, cc=cc, cid=canonical_id).single()

            if existing:
                use_id = existing["lid"]
                # Normaliza el nombre del nodo existente al canónico
                tx.run("""
                MATCH (loc:Location {id: $id})
                SET loc.name = $name, loc.last_enriched = datetime()
                """, id=use_id, name=canonical_name)
                return use_id

            # No existe: crear nodo canónico
            tx.run("""
            MERGE (loc:Location {id: $id})
            ON CREATE SET loc.type     = 'location',
                          loc.name     = $name,
                          loc.country  = $cc,
                          loc.x_source = 'Skyfall-autocorr',
                          loc.last_enriched = datetime()
            ON MATCH SET  loc.name = $name, loc.last_enriched = datetime()
            """, id=canonical_id, name=canonical_name, cc=cc)
            return canonical_id

        # Tipos de nodo que pueden tener geo directa (SCOs OTX o indicators IntelOwl)
        GEO_TYPES = {"indicator", "ipv4-addr", "ipv6-addr", "domain-name"}

        for node in nodes:
            if node.get("type") not in GEO_TYPES:
                continue

            ioc_id = node["id"]

            # ── Países de origen: campos IntelOwl + campo OTX directo ─────────
            origin_ccs = set()
            for field in ("x_vt_country", "x_abuseipdb_country_code", "country_code"):
                cc = node.get(field)
                if cc:
                    origin_ccs.add(cc.upper())

            for cc in origin_ccs:
                loc_id = ensure_country(tx, cc)
                # indicator -[ORIGINATES_FROM]-> Location
                tx.run("""
                MATCH (ioc {id: $ioc_id})
                MATCH (loc:Location {id: $loc_id})
                MERGE (ioc)-[r:ORIGINATES_FROM {id: $ioc_id + '_of_' + $loc_id}]->(loc)
                SET r.correlation = 'C20_origin', r.confidence = 80
                """, ioc_id=ioc_id, loc_id=loc_id)

                # ipv4-addr referenciada por el indicator también
                tx.run("""
                MATCH (ioc {id: $ioc_id})-[:BASED_ON|based_on]->(ip:IP)
                MATCH (loc:Location {id: $loc_id})
                MERGE (ip)-[r:ORIGINATES_FROM {id: ip.id + '_of_' + $loc_id}]->(loc)
                SET r.correlation = 'C20_origin', r.confidence = 80
                """, ioc_id=ioc_id, loc_id=loc_id)

            # ── Países objetivo (Crowdsec target_countries) ───────────────────
            target_raw = node.get("x_crowdsec_target_countries")
            if target_raw:
                try:
                    target_dict = json.loads(target_raw) if isinstance(target_raw, str) else target_raw
                except Exception:
                    target_dict = {}

                for cc, reporter_count in target_dict.items():
                    loc_id = ensure_country(tx, cc)

                    # indicator -[TARGETS]-> Location
                    tx.run("""
                    MATCH (ioc {id: $ioc_id})
                    MATCH (loc:Location {id: $loc_id})
                    MERGE (ioc)-[r:TARGETS {id: $ioc_id + '_tgt_' + $loc_id}]->(loc)
                    SET r.correlation      = 'C21_target',
                        r.confidence       = 70,
                        r.x_reporter_count = $cnt,
                        r.x_source         = 'Crowdsec'
                    """, ioc_id=ioc_id, loc_id=loc_id, cnt=reporter_count)

                    # attack-pattern (mismo MITRE) -[TARGETS]-> Location
                    # Vincula técnicas ya en el grafo que fueron usadas por este IOC
                    tx.run("""
                    MATCH (ioc {id: $ioc_id})-[:BASED_ON|based_on]->(ip)
                    MATCH (ip)-[:EXHIBITS]->(ap:Technique)
                    MATCH (loc:Location {id: $loc_id})
                    MERGE (ap)-[r:OBSERVED_IN {id: ap.id + '_oi_' + $loc_id}]->(loc)
                    SET r.correlation      = 'C22_technique_geo',
                        r.confidence       = 55,
                        r.x_reporter_count = $cnt,
                        r.x_source         = 'Crowdsec'
                    """, ioc_id=ioc_id, loc_id=loc_id, cnt=reporter_count)

                    # También vía relación EXHIBITS directa indicator → attack-pattern
                    tx.run("""
                    MATCH (ioc {id: $ioc_id})-[:EXHIBITS]->(ap:Technique)
                    MATCH (loc:Location {id: $loc_id})
                    MERGE (ap)-[r:OBSERVED_IN {id: ap.id + '_oi_' + $loc_id}]->(loc)
                    SET r.correlation      = 'C22_technique_geo',
                        r.confidence       = 55,
                        r.x_reporter_count = $cnt,
                        r.x_source         = 'Crowdsec'
                    """, ioc_id=ioc_id, loc_id=loc_id, cnt=reporter_count)

    @staticmethod
    def _materialize_otx_campaign_nodes(tx, nodes):
        """Crea un nodo Campaign STIX por cada pulso OTX único y vincula todos sus IOCs.

        C-OTX01: todos los IOCs de un mismo pulso comparten una Campaign y se
        relacionan entre sí como RELATED_TO con confianza media.
        """
        _CAM_NS = uuid.UUID("12345678-1234-5678-1234-567812345678")

        # Agrupar nodos por pulse_id
        pulses: Dict[str, List[str]] = {}
        pulse_meta: Dict[str, Dict] = {}
        for node in nodes:
            pid = node.get("x_otx_pulse_id")
            if not pid:
                continue
            pulses.setdefault(pid, []).append(node["id"])
            if pid not in pulse_meta:
                pulse_meta[pid] = {
                    "name":  node.get("x_otx_pulse", pid),
                    "tags":  json.dumps(node.get("x_otx_tags") or []),
                }

        for pid, ioc_ids in pulses.items():
            campaign_id = "campaign--" + str(uuid.uuid5(_CAM_NS, f"otx-pulse-{pid}"))
            meta = pulse_meta[pid]
            # Upsert Campaign
            tx.run("""
            MERGE (c:Campaign {id: $id})
            ON CREATE SET c.type = 'campaign',
                          c.name = $name,
                          c.x_otx_pulse_id = $pid,
                          c.x_otx_tags = $tags,
                          c.x_source = 'OTX',
                          c.last_enriched = datetime()
            ON MATCH  SET c.last_enriched = datetime()
            """, id=campaign_id, name=meta["name"], pid=pid, tags=meta["tags"])

            # Vincular cada IOC a la Campaign
            for ioc_id in ioc_ids:
                tx.run("""
                MATCH (ioc {id: $ioc_id})
                MATCH (c:Campaign {id: $cid})
                MERGE (ioc)-[r:PART_OF {id: $ioc_id + '_po_' + $cid}]->(c)
                SET r.correlation = 'C-OTX01_pulse', r.x_source = 'OTX'
                """, ioc_id=ioc_id, cid=campaign_id)

            # Entre IOCs del mismo pulso: RELATED_TO (evitar M×N para pulsos grandes)
            if len(ioc_ids) <= 50:
                for i, a in enumerate(ioc_ids):
                    for b in ioc_ids[i + 1:]:
                        tx.run("""
                        MATCH (a {id: $a})
                        MATCH (b {id: $b})
                        MERGE (a)-[r:RELATED_TO {id: $a + '_rt_' + $b}]->(b)
                        SET r.correlation = 'C-OTX01_co_pulse',
                            r.confidence  = 55,
                            r.x_source    = 'OTX'
                        """, a=a, b=b)

    @staticmethod
    def _materialize_asn_nodes(tx, nodes):
        """Crea un nodo Infrastructure por cada ASN único y vincula IOCs.

        C-OTX02: IOCs alojados en la misma infraestructura (mismo ASN) se
        correlacionan a través del nodo Infrastructure.
        """
        _ASN_NS = uuid.UUID("87654321-4321-8765-4321-876543218765")

        seen_asn: Dict[str, str] = {}  # asn_raw -> infra_id

        def _normalize_asn(value: str) -> str:
            v = value.strip().upper()
            v = v.replace("AS", "")
            if v.endswith(".0"):
                v = v[:-2]
            return v

        for node in nodes:
            asn_val = node.get("asn")
            if asn_val is None:
                continue
            asn_raw = _normalize_asn(str(asn_val))
            if not asn_raw or asn_raw in ("0", "0.0", "None", "null", ""):
                continue
            ioc_id = node["id"]

            if asn_raw not in seen_asn:
                infra_id = "infrastructure--" + str(uuid.uuid5(_ASN_NS, f"asn:{asn_raw}"))

                existing = tx.run("""
                MATCH (inf:Infrastructure)
                WHERE inf.asn = $asn
                   OR toUpper(replace(coalesce(inf.name,''), 'AS', '')) = $asn
                   OR toUpper(coalesce(inf.x_asn,'')) = $asn
                RETURN inf.id AS id
                ORDER BY CASE WHEN inf.id = $cid THEN 0 ELSE 1 END
                LIMIT 1
                """, asn=asn_raw, cid=infra_id).single()

                if existing:
                    infra_id = existing["id"]

                seen_asn[asn_raw] = infra_id
                tx.run("""
                MERGE (inf:Infrastructure {id: $id})
                ON CREATE SET inf.type = 'infrastructure',
                              inf.name = $asn,
                              inf.asn = $asn,
                              inf.x_asn = $asn,
                              inf.infrastructure_types = '["hosting-provider"]',
                              inf.x_source = 'OTX',
                              inf.last_enriched = datetime()
                ON MATCH  SET inf.last_enriched = datetime(),
                              inf.asn = coalesce(inf.asn, $asn),
                              inf.x_asn = coalesce(inf.x_asn, $asn)
                """, id=infra_id, asn=asn_raw)
            else:
                infra_id = seen_asn[asn_raw]

            tx.run("""
            MATCH (ioc {id: $ioc_id})
            MATCH (inf:Infrastructure {id: $infra_id})
            MERGE (ioc)-[r:HOSTED_BY {id: $ioc_id + '_hb_' + $infra_id}]->(inf)
            SET r.correlation = 'C-OTX02_asn', r.confidence = 70, r.x_source = 'OTX'
            """, ioc_id=ioc_id, infra_id=infra_id)

    @staticmethod
    def _correlate_otx_tags(tx, nodes):
        """Correlaciona IOCs que comparten tags OTX significativos.

        C-OTX03: Si dos IOCs de distintos pulsos comparten un tag específico
        se crea una arista SHARES_TAG en el grafo.
        Solo para tags de alta señal (no genéricos).
        """
        NOISE_TAGS = {
            "malware", "phishing", "spam", "botnet", "exploit",
            "malicious", "suspicious", "threat", "ioc", "indicator",
            "infrastructure", "c2", "c&c", "attack",
        }

        # index: tag -> list of ioc_ids del bundle actual
        tag_index: Dict[str, List[str]] = {}
        for node in nodes:
            if node.get("type") not in ("ipv4-addr", "domain-name", "indicator"):
                continue
            tags = node.get("x_otx_tags") or []
            if isinstance(tags, str):
                try:
                    tags = json.loads(tags)
                except Exception:
                    tags = []
            for tag in tags:
                t = tag.lower().strip()
                if t and t not in NOISE_TAGS and len(t) > 3:
                    tag_index.setdefault(t, []).append(node["id"])

        for tag, ioc_ids in tag_index.items():
            if len(ioc_ids) < 2:
                continue
            for i, a in enumerate(ioc_ids):
                for b in ioc_ids[i + 1:]:
                    tx.run("""
                    MATCH (a {id: $a})
                    MATCH (b {id: $b})
                    MERGE (a)-[r:SHARES_TAG {id: $a + '_st_' + $b + '_' + $tag}]->(b)
                    SET r.correlation = 'C-OTX03_tag',
                        r.tag         = $tag,
                        r.confidence  = 45,
                        r.x_source    = 'OTX'
                    """, a=a, b=b, tag=tag)

    @staticmethod
    def _correlate_ioc_exhibits_with_mitre(tx, nodes):
        """Create EXHIBITS relations from IOCs to already populated MITRE ATT&CK techniques."""
        for node in nodes:
            if node.get("type") not in ("indicator", "ipv4-addr", "ipv6-addr", "domain-name"):
                continue
            ioc_id = node.get("id")
            if not ioc_id:
                continue

            raw_ids: List[str] = []
            for field in ("x_mitre_id", "x_mitre_ids", "mitre_attack_ids", "attack_ids"):
                value = node.get(field)
                if isinstance(value, str):
                    raw_ids.extend(re.findall(r"T\d{4}(?:\.\d{3})?", value.upper()))
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            raw_ids.extend(re.findall(r"T\d{4}(?:\.\d{3})?", item.upper()))

            tags = node.get("x_otx_tags")
            if isinstance(tags, str):
                try:
                    tags = json.loads(tags)
                except Exception:
                    tags = []
            if isinstance(tags, list):
                for tag in tags:
                    if isinstance(tag, str):
                        raw_ids.extend(re.findall(r"T\d{4}(?:\.\d{3})?", tag.upper()))

            for mid in sorted(set(raw_ids)):
                tx.run("""
                MATCH (ioc {id: $iid})
                MATCH (tech:Technique)
                WHERE tech.external_id = $mid OR tech.x_mitre_id = $mid
                MERGE (ioc)-[r:EXHIBITS {id: $iid + '_exh_' + tech.id}]->(tech)
                SET r.correlation = 'C-MITRE01_ioc_exhibits_mitre',
                    r.confidence  = 75,
                    r.x_mitre_id  = $mid,
                    r.x_source    = coalesce(r.x_source, 'Skyfall-autocorr')
                """, iid=ioc_id, mid=mid)

    @staticmethod
    def _run_autocorrelation(tx, nodes):
        """Lógica de correlación profunda (C01-C23)."""
        for node in nodes:
            # CORRELACIÓN C02: Attack Pattern con MITRE ID → vincular al nodo MITRE oficial
            if node.get("type") == "attack-pattern" and node.get("x_mitre_id"):
                tx.run("""
                MATCH (new:Technique {id: $id})
                MATCH (mitre:Technique)
                WHERE mitre.external_id = new.x_mitre_id AND mitre.id <> new.id
                MERGE (new)-[r:SAME_AS {confidence: 100, correlation: 'C02_mitre'}]->(mitre)
                """, id=node["id"])

            # CORRELACIÓN C19: Geo-Clustering — IOCs al mismo país
            # Funciona tanto con Locations del bundle como con las materializadas (C20/C21)
            if node.get("type") == "location" and node.get("country"):
                tx.run("""
                MATCH (loc:Location {id: $id})
                MATCH (obj)
                WHERE (obj.x_vt_country = loc.country
                    OR obj.x_abuseipdb_country_code = loc.country
                    OR obj.country_code = loc.country)
                AND NOT obj:Location
                MERGE (obj)-[r:LOCATED_IN {id: obj.id + '_li_' + $id}]->(loc)
                SET r.confidence = 45, r.correlation = 'C19_geo'
                """, id=node["id"])

            # CORRELACIÓN C05: Deduplicación por valor de IP
            if node.get("type") == "ipv4-addr" and node.get("value"):
                tx.run("""
                MATCH (ip:IP {id: $id})
                MATCH (existing:IP {value: ip.value})
                WHERE ip.id <> existing.id
                MERGE (ip)-[r:SAME_AS {confidence: 100, correlation: 'C05_dedup'}]->(existing)
                """, id=node["id"])

            # CORRELACIÓN C06: Deduplicación por valor de dominio
            if node.get("type") == "domain-name" and node.get("value"):
                tx.run("""
                MATCH (dn:Domain {id: $id})
                MATCH (existing:Domain {value: dn.value})
                WHERE dn.id <> existing.id
                MERGE (dn)-[r:SAME_AS {confidence: 100, correlation: 'C06_dedup_domain'}]->(existing)
                """, id=node["id"])

            # CORRELACIÓN C23: Técnicas MITRE usadas por un IOC → países de origen del IOC
            # Para cada attack-pattern vinculado al IOC, crear OBSERVED_IN → Location de origen
            if node.get("type") == "ipv4-addr":
                tx.run("""
                MATCH (ip:IP {id: $id})-[:EXHIBITS]->(ap:Technique)
                MATCH (ip)-[:LOCATED_IN|ORIGINATES_FROM]->(loc:Location)
                MERGE (ap)-[r:OBSERVED_IN {id: ap.id + '_oi_' + loc.id}]->(loc)
                SET r.confidence = 60, r.correlation = 'C23_technique_origin'
                """, id=node["id"])

    @staticmethod
    def _correlate_vulnerabilities(tx, nodes):
        """Correlaciones profundas para bundles CVE/KEV.

        C-CVE01  Vulnerability → Malware que ya existe en el grafo (mismo nombre).
        C-CVE02  Vulnerability → ThreatActor / IntrusionSet que usa técnicas
                 relacionadas con las CWE del bundle.
        C-CVE03  Vulnerability → Indicator (IoC) que exhibe la misma técnica CWE.
        C-CVE04  Software referenciado en el bundle ← IOCs conocidos que atacan ese
                 software (via campo x_targeted_app o name coincidente).
        C-CVE05  Vulnerability → Campaign que contiene indicadores con la técnica.
        C-CVE06  Malware del bundle ↔ Malware ya en grafo con mismo nombre.
        C-CVE07  Vulnerability ← IOC marcado con el CVE-ID en sus referencias.
        C-CVE08  Vulnerability → Técnicas MITRE ATT&CK relacionadas con la CWE
                 ya presentes en el grafo.
        C-CVE09  Sighting automático: si hay IOCs en el grafo que exhiben las
                 CWEs del bundle, vincularlos como observed-data.
        C-CVE10  Software del bundle → Location de los IOCs que lo atacan.
        """
        for node in nodes:
            ntype = node.get("type")
            nid   = node.get("id")

            # ── C-CVE01: Malware del bundle ↔ Malware existente en el grafo ──
            if ntype == "malware":
                name = (node.get("name") or "").strip()
                if name:
                    # Vincular con malware ya en grafo con nombre idéntico (case-insensitive)
                    tx.run("""
                    MATCH (new:Malware {id: $id})
                    MATCH (existing:Malware)
                    WHERE toLower(existing.name) = toLower($name)
                      AND existing.id <> $id
                    MERGE (new)-[r:SAME_AS {id: $id + '_sa_' + existing.id}]->(existing)
                    SET r.confidence = 90, r.correlation = 'C-CVE01_malware_dedup'
                    """, id=nid, name=name)

            # ── C-CVE06: Deduplicación de Software por nombre/CPE ──
            if ntype == "software":
                name = (node.get("name") or "").strip()
                cpe  = (node.get("cpe")  or "").strip()
                if name:
                    tx.run("""
                    MATCH (new:Software {id: $id})
                    MATCH (existing:Software)
                    WHERE toLower(existing.name) = toLower($name)
                      AND existing.id <> $id
                    MERGE (new)-[r:SAME_AS {id: $id + '_sa_' + existing.id}]->(existing)
                    SET r.confidence = 90, r.correlation = 'C-CVE06_software_dedup'
                    """, id=nid, name=name)

            # ── Bloques de correlación centrados en Vulnerability ──
            if ntype != "vulnerability":
                continue

            cve_name = (node.get("name") or "").strip()   # e.g. "CVE-2025-68613"
            cvss    = node.get("x_cvss_score")

            # Collect bundle CWE nodes and also map via relationships already ingested.
            cwe_ids = [
                o["id"] for o in nodes
                if o.get("type") == "attack-pattern" and o.get("name", "").startswith("CWE-")
            ]

            rel_cwe_ids = tx.run("""
            MATCH (v:Vulnerability {id: $vid})-[:HAS_WEAKNESS|RELATED_TO]->(t:Technique)
            WHERE t.name STARTS WITH 'CWE-' OR t.external_id STARTS WITH 'CWE-'
            RETURN collect(DISTINCT t.id) AS ids
            """, vid=nid).single()
            if rel_cwe_ids and rel_cwe_ids.get("ids"):
                cwe_ids.extend(rel_cwe_ids["ids"])
            cwe_ids = list(set(cwe_ids))

            # Recopilar IDs de Software del bundle que este CVE apunta
            sw_ids = [o["id"] for o in nodes if o.get("type") == "software"]

            # Auto-link CVE to software by product/vendor hints when explicit rel is missing.
            tx.run("""
            MATCH (v:Vulnerability {id: $vid})
            MATCH (sw:Software)
            WHERE (
                (v.x_vendor IS NOT NULL AND toLower(sw.name) CONTAINS toLower(v.x_vendor)) OR
                (v.x_product IS NOT NULL AND toLower(sw.name) CONTAINS toLower(v.x_product)) OR
                (v.description IS NOT NULL AND sw.cpe IS NOT NULL AND toLower(v.description) CONTAINS toLower(sw.cpe))
            )
            MERGE (v)-[r:TARGETS {id: $vid + '_targets_' + sw.id}]->(sw)
            SET r.confidence = 60,
                r.correlation = 'C-CVE00_auto_product_match',
                r.x_source = 'Skyfall-autocorr'
            """, vid=nid)

            # ── C-CVE02: CVE → ThreatActor / IntrusionSet que usa las técnicas CWE ──
            for cwe_id in cwe_ids:
                tx.run("""
                MATCH (vuln:Vulnerability {id: $vid})
                MATCH (cwe:Technique {id: $cweid})
                MATCH (actor)-[:USES]->(cwe)
                WHERE actor:ThreatActor OR actor:IntrusionSet
                MERGE (actor)-[r:EXPLOITS {id: actor.id + '_exp_' + $vid}]->(vuln)
                SET r.confidence  = 65,
                    r.correlation = 'C-CVE02_actor_via_cwe',
                    r.x_source    = 'Skyfall-autocorr'
                """, vid=nid, cweid=cwe_id)

            # ── C-CVE03: CVE → Indicators que exhiben la misma CWE ──
            for cwe_id in cwe_ids:
                tx.run("""
                MATCH (vuln:Vulnerability {id: $vid})
                MATCH (ind:Indicator)-[:EXHIBITS]->(cwe:Technique {id: $cweid})
                MERGE (ind)-[r:RELATED_TO {id: ind.id + '_rt_' + $vid}]->(vuln)
                SET r.confidence  = 60,
                    r.correlation = 'C-CVE03_ioc_shares_cwe',
                    r.x_source    = 'Skyfall-autocorr'
                """, vid=nid, cweid=cwe_id)

            # ── C-CVE04: Software del bundle ← IOCs que lo atacan por nombre ──
            for sw_id in sw_ids:
                tx.run("""
                MATCH (sw:Software {id: $swid})
                MATCH (ioc)
                WHERE (ioc:IP OR ioc:Domain OR ioc:URL OR ioc:Indicator)
                  AND (toLower(ioc.x_targeted_app) CONTAINS toLower(sw.name)
                    OR toLower(ioc.x_app)          CONTAINS toLower(sw.name))
                MERGE (ioc)-[r:TARGETS {id: ioc.id + '_tgt_' + $swid}]->(sw)
                SET r.confidence  = 70,
                    r.correlation = 'C-CVE04_ioc_targets_sw',
                    r.x_source    = 'Skyfall-autocorr'
                """, swid=sw_id)

            # ── C-CVE04b: CVE → Software → IOCs (cadena inversa) ──
            for sw_id in sw_ids:
                tx.run("""
                MATCH (vuln:Vulnerability {id: $vid})
                MATCH (sw:Software {id: $swid})
                MATCH (ioc)-[:TARGETS]->(sw)
                WHERE ioc:IP OR ioc:Domain OR ioc:Indicator
                MERGE (ioc)-[r:RELATED_TO {id: ioc.id + '_rt_vuln_' + $vid}]->(vuln)
                SET r.confidence  = 55,
                    r.correlation = 'C-CVE04b_ioc_related_cve',
                    r.x_source    = 'Skyfall-autocorr'
                """, vid=nid, swid=sw_id)

            # ── C-CVE05: CVE → Campaigns que contienen IOCs con las CWEs ──
            for cwe_id in cwe_ids:
                tx.run("""
                MATCH (vuln:Vulnerability {id: $vid})
                MATCH (ind)-[:EXHIBITS]->(cwe:Technique {id: $cweid})
                MATCH (ind)-[:PART_OF]->(camp:Campaign)
                MERGE (camp)-[r:EXPLOITS {id: camp.id + '_exp_' + $vid}]->(vuln)
                SET r.confidence  = 60,
                    r.correlation = 'C-CVE05_campaign_exploits_cve',
                    r.x_source    = 'Skyfall-autocorr'
                """, vid=nid, cweid=cwe_id)

            # ── C-CVE07: CVE ← IOCs cuyo campo references contiene el CVE-ID ──
            if cve_name:
                tx.run("""
                MATCH (vuln:Vulnerability {id: $vid})
                MATCH (ioc)
                WHERE (ioc:IP OR ioc:Domain OR ioc:Indicator OR ioc:Malware)
                  AND (ioc.x_cve_refs CONTAINS $cve_name
                    OR ioc.x_references CONTAINS $cve_name
                    OR ioc.description  CONTAINS $cve_name)
                MERGE (ioc)-[r:RELATED_TO {id: ioc.id + '_rt_cve_' + $vid}]->(vuln)
                SET r.confidence  = 75,
                    r.correlation = 'C-CVE07_ioc_references_cve',
                    r.x_source    = 'Skyfall-autocorr'
                """, vid=nid, cve_name=cve_name)

            # ── C-CVE08: CVE → Técnicas MITRE ATT&CK relacionadas con CWEs ──
            for cwe_id in cwe_ids:
                cwe_name = next((o.get("name", "") for o in nodes
                                 if o.get("id") == cwe_id), "")
                cwe_code = SkyfallNeo4jIngestor._extract_cwe_id(cwe_name)
                mitre_ids = SkyfallNeo4jIngestor._mitre_ids_from_cwe(cwe_code or cwe_name)
                for mitre_id in mitre_ids:
                    tx.run("""
                    MATCH (vuln:Vulnerability {id: $vid})
                    MATCH (tech:Technique)
                    WHERE tech.x_mitre_id = $mid OR tech.external_id = $mid
                    MERGE (vuln)-[r:RELATED_TO {id: $vid + '_rt_' + tech.id}]->(tech)
                    SET r.confidence  = 55,
                        r.correlation = 'C-CVE08_cve_mitre_technique',
                        r.x_source    = 'Skyfall-autocorr'
                    """, vid=nid, mid=mitre_id)

            # ── C-CVE09: Sighting automático — IOCs con CWE → observed-data ──
            for cwe_id in cwe_ids:
                tx.run("""
                MATCH (vuln:Vulnerability {id: $vid})
                MATCH (cwe:Technique {id: $cweid})
                MATCH (ioc)-[:EXHIBITS]->(cwe)
                WHERE ioc:IP OR ioc:Domain OR ioc:Indicator
                MERGE (vuln)-[r:SIGHTED_WITH {id: $vid + '_sw_' + ioc.id}]->(ioc)
                SET r.confidence  = 50,
                    r.correlation = 'C-CVE09_vuln_sighted_with_ioc',
                    r.x_source    = 'Skyfall-autocorr'
                """, vid=nid, cweid=cwe_id)

            # ── C-CVE10: Software del bundle → Locations de IOCs que lo atacan ──
            for sw_id in sw_ids:
                tx.run("""
                MATCH (sw:Software {id: $swid})
                MATCH (ioc)-[:TARGETS]->(sw)
                MATCH (ioc)-[:ORIGINATES_FROM|LOCATED_IN]->(loc:Location)
                MERGE (sw)-[r:TARGETED_FROM {id: sw.id + '_tf_' + loc.id}]->(loc)
                SET r.confidence  = 55,
                    r.correlation = 'C-CVE10_sw_targeted_from_geo',
                    r.x_source    = 'Skyfall-autocorr'
                """, swid=sw_id)

            # ── C-CVE11: CVSS crítico → vincular con IntrusionSets de alto perfil ──
            #  Si el CVE tiene CVSS >= 9.0, buscar IntrusionSets APT en el grafo
            if cvss is not None:
                try:
                    score = float(cvss)
                except (TypeError, ValueError):
                    score = 0.0
                if score >= 9.0:
                    for sw_id in sw_ids:
                        tx.run("""
                        MATCH (vuln:Vulnerability {id: $vid})
                        MATCH (sw:Software {id: $swid})
                        MATCH (iset:IntrusionSet)
                        WHERE iset.sophistication IN ['advanced', 'expert', 'innovator']
                           OR iset.resource_level IN ['government', 'nation-state']
                        MERGE (iset)-[r:LIKELY_EXPLOITS {id: iset.id + '_le_' + $vid}]->(vuln)
                        SET r.confidence  = 40,
                            r.correlation = 'C-CVE11_apt_critical_cve',
                            r.x_cvss      = $cvss,
                            r.x_source    = 'Skyfall-autocorr'
                        """, vid=nid, swid=sw_id, cvss=score)


    @staticmethod
    def _correlate_infection_chains(tx, nodes):
        """Cadenas de infección completas y correlación CVE↔CVE por CWE compartida.

        C-CHAIN01  Indicator -[INDICATES]-> Malware
                   Si el pattern del indicator contiene el nombre del malware
                   o hay un malware en el bundle, auto-crear relación INDICATES.
        C-CHAIN02  Indicator -[INDICATES]-> Vulnerability
                   Si el pattern del indicator contiene un CVE-ID o el indicator
                   describe escaneos activos contra software afectado por el CVE.
        C-CHAIN03  Vulnerability -[RELATED_TO]-> Vulnerability
                   Dos CVEs que comparten la misma CWE se vinculan automáticamente.
                   Es el «puente CWE» que une vulnerabilidades del mismo tipo.
        C-CHAIN04  Cadena completa: IP/Domain → Malware → Vulnerability → Software
                   Materializa la arista directa IOC -[PART_OF_CHAIN]-> Software
                   para que la consulta estrella del TFG funcione en un salto.
        C-CHAIN05  Indicator que indica Malware → hereda relación EXPLOITS del malware
                   Indicator -[EXPLOITS]-> Vulnerability (shortcut para visualización).
        C-CHAIN06  Indicator -[SCANS_FOR]-> Vulnerability
                   Si la descripción/pattern del indicator menciona «scan» + CVE-ID,
                   se crea la relación semántica de reconocimiento activo.
        """

        # Índices locales del bundle para búsquedas rápidas
        malware_nodes = [
            o for o in nodes if o.get("type") == "malware"
        ]
        vuln_nodes = [
            o for o in nodes if o.get("type") == "vulnerability"
        ]
        sw_nodes = [
            o for o in nodes if o.get("type") == "software"
        ]
        cwe_nodes = [
            o for o in nodes
            if o.get("type") == "attack-pattern"
            and (o.get("name", "") or "").startswith("CWE-")
        ]

        # ── C-CHAIN01: Indicator → INDICATES → Malware ──────────────────────
        for ind in nodes:
            if ind.get("type") != "indicator":
                continue
            ind_id      = ind["id"]
            pattern     = (ind.get("pattern") or "").lower()
            description = (ind.get("description") or "").lower()
            text        = pattern + " " + description

            # a) Malware del mismo bundle cuyo nombre aparece en el pattern
            for mal in malware_nodes:
                mal_name = (mal.get("name") or "").lower()
                if mal_name and mal_name in text:
                    tx.run("""
                    MATCH (ind:Indicator {id: $iid})
                    MATCH (mal:Malware   {id: $mid})
                    MERGE (ind)-[r:INDICATES {id: $iid + '_ind_' + $mid}]->(mal)
                    SET r.confidence  = 85,
                        r.correlation = 'C-CHAIN01_indicator_indicates_malware',
                        r.x_source    = 'Skyfall-autocorr'
                    """, iid=ind_id, mid=mal["id"])

            # b) Malware YA en el grafo cuyo nombre aparece en el pattern
            tx.run("""
            MATCH (ind:Indicator {id: $iid})
            MATCH (mal:Malware)
            WHERE ind.id <> mal.id
              AND toLower(ind.pattern)     CONTAINS toLower(mal.name)
               OR toLower(ind.description) CONTAINS toLower(mal.name)
            MERGE (ind)-[r:INDICATES {id: ind.id + '_ind_' + mal.id}]->(mal)
            SET r.confidence  = 75,
                r.correlation = 'C-CHAIN01b_indicator_indicates_known_malware',
                r.x_source    = 'Skyfall-autocorr'
            """, iid=ind_id)

        # ── C-CHAIN02 + C-CHAIN06: Indicator → INDICATES / SCANS_FOR → Vulnerability ──
        for ind in nodes:
            if ind.get("type") != "indicator":
                continue
            ind_id      = ind["id"]
            pattern     = (ind.get("pattern") or "").lower()
            description = (ind.get("description") or "").lower()
            text        = pattern + " " + description
            is_scan     = any(kw in text for kw in ("scan", "probe", "crawl", "reconnaissance", "greynoise"))

            # a) Vulnerabilidades del mismo bundle
            for vuln in vuln_nodes:
                cve_name = (vuln.get("name") or "").lower()
                if cve_name and cve_name in text:
                    rel_type = "SCANS_FOR" if is_scan else "INDICATES"
                    corr     = "C-CHAIN06_scanner" if is_scan else "C-CHAIN02_indicator_indicates_vuln"
                    tx.run(f"""
                    MATCH (ind:Indicator    {{id: $iid}})
                    MATCH (vuln:Vulnerability {{id: $vid}})
                    MERGE (ind)-[r:{rel_type} {{id: $iid + '_{rel_type}_' + $vid}}]->(vuln)
                    SET r.confidence  = $conf,
                        r.correlation = $corr,
                        r.x_source    = 'Skyfall-autocorr'
                    """, iid=ind_id, vid=vuln["id"],
                         conf=80 if is_scan else 75, corr=corr)

            # b) Vulnerabilidades YA en el grafo
            tx.run("""
            MATCH (ind:Indicator {id: $iid})
            MATCH (vuln:Vulnerability)
            WHERE (toLower(ind.pattern)     CONTAINS toLower(vuln.name)
               OR  toLower(ind.description) CONTAINS toLower(vuln.name))
            MERGE (ind)-[r:INDICATES {id: ind.id + '_ind_vuln_' + vuln.id}]->(vuln)
            SET r.confidence  = 70,
                r.correlation = 'C-CHAIN02b_indicator_indicates_known_vuln',
                r.x_source    = 'Skyfall-autocorr'
            """, iid=ind_id)

        # ── C-CHAIN03: Bridge CWE — CVE ↔ CVE por debilidad compartida ────────
        # Para cada CWE del bundle, vincular la vulnerability del bundle con
        # TODAS las vulnerabilities del grafo que también apuntan a esa CWE.
        for cwe in cwe_nodes:
            cwe_id   = cwe["id"]
            cwe_name = cwe.get("name", "")
            for vuln in vuln_nodes:
                # Otras vulnerabilities en el grafo que tienen la misma CWE
                tx.run("""
                MATCH (new_vuln:Vulnerability {id: $vid})
                MATCH (new_vuln)-[:HAS_WEAKNESS]->(cwe:Technique {id: $cweid})
                MATCH (other_vuln:Vulnerability)-[:HAS_WEAKNESS]->(cwe)
                WHERE other_vuln.id <> $vid
                MERGE (new_vuln)-[r:RELATED_TO {
                    id: $vid + '_cwebridge_' + other_vuln.id
                }]->(other_vuln)
                SET r.confidence  = 70,
                    r.correlation = 'C-CHAIN03_cwe_bridge',
                    r.x_cwe       = $cwe_name,
                    r.x_source    = 'Skyfall-autocorr'
                """, vid=vuln["id"], cweid=cwe_id, cwe_name=cwe_name)

                # También buscar por nombre de CWE en propiedades (bundles que no
                # usaron relación explícita HAS_WEAKNESS sino campo x_cwe_name)
                tx.run("""
                MATCH (new_vuln:Vulnerability {id: $vid})
                MATCH (other_vuln:Vulnerability)
                WHERE other_vuln.id <> $vid
                  AND (other_vuln.x_cwe_name = $cwe_name
                    OR other_vuln.x_cwe      = $cwe_name
                    OR other_vuln.description CONTAINS $cwe_name)
                MERGE (new_vuln)-[r:RELATED_TO {
                    id: $vid + '_cweprop_' + other_vuln.id
                }]->(other_vuln)
                SET r.confidence  = 60,
                    r.correlation = 'C-CHAIN03b_cwe_property_bridge',
                    r.x_cwe       = $cwe_name,
                    r.x_source    = 'Skyfall-autocorr'
                """, vid=vuln["id"], cwe_name=cwe_name)

        # ── C-CHAIN04: Cadena completa IOC → Malware → Vulnerability → Software ──
        # Shortcut directo para la consulta estrella del TFG:
        # MATCH (ioc)-[:INDICATES]->(m:Malware)-[:EXPLOITS]->(v:Vulnerability)
        #       -[:TARGETS]->(s:Software) RETURN ioc,m,v,s
        # También materializa el edge directo IOC -[PART_OF_CHAIN]-> Software
        for vuln in vuln_nodes:
            for sw in sw_nodes:
                # Edge directo vulnerability → software si targets existe en bundle
                tx.run("""
                MATCH (vuln:Vulnerability {id: $vid})
                MATCH (sw:Software {id: $swid})
                MERGE (vuln)-[r:TARGETS {id: $vid + '_tgt_' + $swid}]->(sw)
                SET r.confidence  = 95,
                    r.correlation = 'C-CHAIN04_vuln_targets_sw',
                    r.x_source    = 'bundle'
                """, vid=vuln["id"], swid=sw["id"])

        # Shortcut IOC → Software (saltando la cadena intermedia)
        for vuln in vuln_nodes:
            for sw in sw_nodes:
                tx.run("""
                MATCH (vuln:Vulnerability {id: $vid})
                MATCH (sw:Software {id: $swid})
                MATCH (ioc)-[:INDICATES]->(mal:Malware)-[:EXPLOITS]->(vuln)
                MERGE (ioc)-[r:PART_OF_CHAIN {
                    id: ioc.id + '_chain_' + $swid
                }]->(sw)
                SET r.confidence  = 80,
                    r.correlation = 'C-CHAIN04_shortcut_ioc_to_sw',
                    r.x_vuln      = $vid,
                    r.x_source    = 'Skyfall-autocorr'
                """, vid=vuln["id"], swid=sw["id"])

        # ── C-CHAIN05: Indicator hereda EXPLOITS del malware que indica ──────────
        # Indicator -[INDICATES]-> Malware -[EXPLOITS]-> Vulnerability
        # => Indicator -[EXPLOITS]-> Vulnerability (shortcut)
        tx.run("""
        MATCH (ind:Indicator)-[:INDICATES]->(mal:Malware)-[:EXPLOITS]->(vuln:Vulnerability)
        MERGE (ind)-[r:EXPLOITS {
            id: ind.id + '_exp_inherited_' + vuln.id
        }]->(vuln)
        SET r.confidence  = 75,
            r.correlation = 'C-CHAIN05_indicator_inherits_exploits',
            r.x_via       = mal.id,
            r.x_source    = 'Skyfall-autocorr'
        """)


# ──────────────────────────────────────────────────────────────────────
#  CONSUMIDOR KAFKA
# ──────────────────────────────────────────────────────────────────────

def run_consumer():
    ingestor = SkyfallNeo4jIngestor()
    
    c = Consumer({
        'bootstrap.servers': KAFKA_BROKER,
        'group.id': KAFKA_GROUP_ID,
        'auto.offset.reset': 'earliest'
    })
    c.subscribe(KAFKA_TOPICS)

    log.info(f"[*] Consumer Neo4j iniciado. Escuchando topics: {KAFKA_TOPICS}")

    try:
        while True:
            msg = c.poll(1.0)
            if msg is None: continue
            if msg.error():
                log.error(f"Kafka error: {msg.error()}")
                continue

            try:
                # El mensaje puede venir como JSON string o bytes
                raw_data = json.loads(msg.value().decode('utf-8'))
                
                # Soportamos tanto el objeto STIX directo como el wrapper del cliente
                bundle = raw_data.get("stix_bundle") if "stix_bundle" in raw_data else raw_data
                
                if bundle and bundle.get("type") == "bundle":
                    log.info(f"[+] Procesando bundle {bundle.get('id')}...")
                    ingestor.ingest_bundle(bundle)
                else:
                    log.warning("[-] Mensaje recibido no es un bundle STIX válido.")

            except Exception as e:
                log.error(f"Error procesando mensaje: {e}", exc_info=True)

    except KeyboardInterrupt:
        pass
    finally:
        c.close()

if __name__ == "__main__":
    run_consumer()