import argparse
import csv
import io

import stix2
import taxii2client
import tqdm

DEFAULT_TACTIC_FIELDS=[
    "mitre_tactic",
    "mitre_tactic_name",
    "mitre_tactic_shortname",
    "mitre_tactic_url",
    "mitre_tactic_description"
]

DEFAULT_TECHNIQUES_FIELDS=[
    "mitre_technique",
    "mitre_technique_name",
    "mitre_techinque_url",
    "mitre_technique_description",
    "mitre_tactics"
]

def build_taxii_source(collection_name):
    """Downloads latest Enterprise or Mobile ATT&CK content from MITRE TAXII Server."""
    # Establish TAXII2 Collection instance for Enterprise ATT&CK collection
    collection_map = {
        "enterprise_attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
        "mobile_attack": "2f669986-b40b-4423-b720-4396ca6a462b"
    }
    collection_url = "https://cti-taxii.mitre.org/stix/collections/" + collection_map[collection_name] + "/"
    collection = taxii2client.Collection(collection_url)
    taxii_ds = stix2.TAXIICollectionSource(collection)

    # Create an in-memory source (to prevent multiple web requests)
    return stix2.MemorySource(stix_data=taxii_ds.query())


def get_all_techniques(src, source_name):
    """Filters data source by attack-pattern which extracts all ATT&CK Techniques"""
    filters = [
        stix2.Filter("type", "=", "attack-pattern"),
        stix2.Filter("external_references.source_name", "=", source_name),
    ]
    results = src.query(filters)
    return remove_deprecated(results)

def get_all_tactics(src, source_name):
    """Filters data source by x-mitre-tactic which extracts all ATT&CK Tactics"""
    filters = [
        stix2.Filter("type", "=", "x-mitre-tactic"),
        stix2.Filter("external_references.source_name", "=", source_name)
    ]
    results = src.query(filters)
    return remove_deprecated(results)

def grab_external_field(fieldname, stix_object, source_name):
    """Grab external field from STIX2 object"""
    for external_reference in stix_object.get("external_references", []):
        if external_reference.get("source_name") == source_name:
            return external_reference.get(fieldname)

def grab_kill_chain_phases(stix_object, source_name):
    """Grab Tatic references"""
    kill_chain_phases = []
    for kill_chain_phase in stix_object.get("kill_chain_phases", []):
        if kill_chain_phase.get("kill_chain_name") == source_name:
            kill_chain_phases.append(kill_chain_phase.get("phase_name"))
    return "|".join(kill_chain_phases)

def remove_deprecated(stix_objects):
    """Will remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )

def remove_crlf(a_string):
    """ Remove CRLF from string """
    return a_string.replace("\n"," ").replace("\r", "").replace("\t", " ")


def extract_tactics(ds, source_name, fieldnames=DEFAULT_TACTIC_FIELDS):
    """ Extracts the list of Tactics with main information"""
    all_tactics = get_all_tactics(ds, source_name)
    writable_results = []

    for tactic in all_tactics:
        row_data = (
            grab_external_field("external_id", tactic, source_name),
            tactic.get("name"),
            tactic.get("x_mitre_shortname"),
            grab_external_field("url", tactic, source_name),
            remove_crlf(tactic.get("description")),
        )

        writable_results.append(dict(zip(fieldnames, row_data)))

    return writable_results


def extract_techniques(ds, source_name, fieldnames=DEFAULT_TECHNIQUES_FIELDS):
    """ Extracts the list of Tactics with main information"""
    all_techniques = get_all_techniques(ds, source_name)
    writable_results = []

    for technique in all_techniques:
        row_data = (
            grab_external_field("external_id", technique, source_name),
            technique.get("name"),
            grab_external_field("url", technique, source_name),
            remove_crlf(technique.get("description")),
            grab_kill_chain_phases(technique, source_name)
        )

        writable_results.append(dict(zip(fieldnames, row_data)))

    return writable_results


def arg_parse():
    """Function to handle script arguments."""
    parser = argparse.ArgumentParser(description="Fetches the current ATT&CK content expressed as STIX2 and creates spreadsheet mapping Techniques with Mitigations, Groups or Software.")
    parser.add_argument("-d", "--domain", type=str, required=True, choices=["enterprise_attack", "mobile_attack"], help="Which ATT&CK domain to use (Enterprise, Mobile).")
    parser.add_argument("-p", "--file-prefix", type=str, required=False, help="Save CSV file with a different filename prefix.")
    return parser


def main(args):
    data_source = build_taxii_source(args.domain)

    source_map = {
        "enterprise_attack": "mitre-attack",
        "mobile_attack": "mitre-mobile-attack",
    }
    source_name = source_map[args.domain]

    # Extracting Tactics
    tactics_row = extract_tactics(data_source, source_name)
    tactics_filename = (args.file_prefix or "mitre") + "-" "tactics.csv"
    with io.open(tactics_filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=DEFAULT_TACTIC_FIELDS)
        writer.writeheader()
        writer.writerows(tactics_row)

    # Extracting Techniques
    techniques_rows = extract_techniques(data_source, source_name)
    techniques_filename = (args.file_prefix or "mitre") + "-" "techniques.csv"
    with io.open(techniques_filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=DEFAULT_TECHNIQUES_FIELDS)
        writer.writeheader()
        writer.writerows(techniques_rows)

if __name__ == "__main__":
    parser = arg_parse()
    args = parser.parse_args()
    main(args)
