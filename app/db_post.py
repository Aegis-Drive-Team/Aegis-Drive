import os
from datetime import datetime
from typing import Optional, Sequence
from dotenv import load_dotenv
from supabase import create_client

# Load .env so we can pull in DATABASE_URL
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
DEFAULT_ORG_ID = os.getenv("DEFAULT_ORG_ID") 

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY not set in .env")

if not DEFAULT_ORG_ID:
    raise RuntimeError("DEFAULT_ORG_ID variable not set in .env")



try:
    _supabase_client = None

    def get_supabase():
        global _supabase_client
        if _supabase_client is None:
            _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        return _supabase_client

    def get_connection():
        return get_supabase()
except RuntimeError as e:
    print(e)


# ---------------------- IP REPORTS ----------------------

def create_ip_report(ip: str, category: str, description: Optional[str],
                     source: Optional[str], reporter_id: Optional[str],
                     public: bool = True, org_id: Optional[str] = None) -> str:

    if org_id is None:
        org_id = DEFAULT_ORG_ID

    try:
        response = get_supabase().table('ip_reports').insert({
            'ip': ip,
            'category': category,
            'description': description,
            'source': source,
            'reporter_id': reporter_id,
            'public': public,
            'org_id': org_id,
        }).execute()

        return str(response.data[0]['id']) if response.data else ""
    except Exception as e:
        raise RuntimeError(f"Failed to create IP report: {e}")





def get_reports_for_ip(ip: str, role: str = "user", limit: int = 50) -> list[dict]:
    try:
        query = get_supabase().table('ip_reports').select('*').eq('ip', ip)

        if role != "admin":
            query = query.eq('public', True)

        response = query.order('created_at', desc=True).limit(limit).execute()
        return response.data if response.data else []
    except Exception as e:
        raise RuntimeError(f"Failed to get reports: {e}")




# ---------------------- ENRICHMENT ----------------------

def upsert_enrichment_from_abuseipdb(ip: str,
                                     abuse_score_0_to_100: Optional[float],
                                     evidence: Optional[dict] = None,
                                     calibrated: bool = False,
                                     org_id: Optional[str] = None) -> None:
    """Update or insert an enrichment record for an IP."""
    evidence = evidence or {}

    if org_id is None:
        org_id = DEFAULT_ORG_ID
    
    norm = None
    conf = None
    if abuse_score_0_to_100 is not None:
        norm = max(0.0, min(1.0, abuse_score_0_to_100 / 100.0))
        conf = norm if not calibrated else None
    
    try:
        # Check if record exists
        response = get_supabase().table('ip_enrichment').select('ip').eq('ip', ip).execute()
        
        if response.data:
            # Update
            get_supabase().table('ip_enrichment').update({
                'raw_abuseipdb': abuse_score_0_to_100,
                'norm_abuseipdb': norm,
                'confidence': conf,
                'evidence': evidence,
                'last_refreshed': datetime.now().isoformat(),
            }).eq('ip', ip).execute()
        else:
            # Insert
            get_supabase().table('ip_enrichment').insert({
                'ip': ip,
                'raw_abuseipdb': abuse_score_0_to_100,
                'norm_abuseipdb': norm,
                'confidence': conf,
                'evidence': evidence,
                'last_refreshed': datetime.now().isoformat(),
                'org_id': org_id,
            }).execute()
    except Exception as e:
        raise RuntimeError(f"Failed to upsert enrichment: {e}")



def get_enrichment(ip: str) -> Optional[dict]:
    """
    Returns enrichment details for an IP (if it exists).
    Mostly used to verify upserts are working.
    """
    try:
        response = get_supabase().table('ip_enrichment').select('*').eq('ip', ip).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        raise RuntimeError(f"Failed to get enrichment: {e}")

# ---------------------- MALWARE ARTIFACTS ----------------------
def upsert_malware_artifact(sha256: str,
                            sha1: Optional[str] = None,
                            md5: Optional[str] = None,
                            file_type: Optional[str] = None,
                            signature: Optional[str] = None,
                            tags: Optional[Sequence[str]] = None,
                            first_seen: Optional[datetime] = None,
                            last_seen: Optional[datetime] = None,
                            source: str = "malwarebazaar",
                            metadata: Optional[dict] = None) -> str:
    """Upsert malware artifact. Returns the artifact UUID."""
    tags_list = list(tags) if tags else None
    metadata_dict = metadata or {}  # ← Just keep as dict, no json.dumps()
    
    try:
        response = get_supabase().table('malware_artifact').select('id').eq('sha256', sha256).execute()
        
        if response.data:
            # Update
            get_supabase().table('malware_artifact').update({
                'sha1': sha1,
                'md5': md5,
                'file_type': file_type,
                'signature': signature,
                'tags': tags_list,
                'last_seen': last_seen.isoformat() if last_seen else None,
                'source': source,
                'metadata': metadata_dict,  # ← Pass dict directly
            }).eq('sha256', sha256).execute()
            return str(response.data[0]['id'])
        else:
            # Insert
            response = get_supabase().table('malware_artifact').insert({
                'sha256': sha256,
                'sha1': sha1,
                'md5': md5,
                'file_type': file_type,
                'signature': signature,
                'tags': tags_list,
                'first_seen': first_seen.isoformat() if first_seen else None,
                'last_seen': last_seen.isoformat() if last_seen else None,
                'source': source,
                'metadata': metadata_dict,  # ← Pass dict directly
            }).execute()
            return str(response.data[0]['id'])
    except Exception as e:
        raise RuntimeError(f"Failed to upsert malware artifact: {e}")


# ---------------------- IP ↔ ARTIFACT LINK ----------------------
def link_ip_to_artifact(ip: str, artifact_id: str,
                        relation: str, note: Optional[str] = None) -> str:
    """Link an IP to a malware artifact. Returns link UUID."""
    try:
        response = get_supabase().table('ip_artifact_link').insert({
            'ip': ip,
            'artifact_id': artifact_id,
            'relation': relation,
            'note': note,
        }).execute()
        
        return str(response.data[0]['id']) if response.data else ""
    except Exception as e:
        raise RuntimeError(f"Failed to link IP to artifact: {e}")