"""
VeraPDF Analiz Sistemi için Merkezi Veri Modelleri.

Bu dosya, projenin farklı modülleri (parser, analyzer, reporter) arasında
tutarlı bir veri yapısı sağlamak için kullanılan tüm `dataclass`'ları içerir.
Modellerin tek bir yerde tanımlanması, veri bütünlüğünü garanti eder ve
sistemin bakımını kolaylaştırır.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ========================================================================
# HAM VERİ MODELLERİ (Raw Data Models)
# - Bu modeller, `xml_parser` tarafından doğrudan XML'den çıkarılan veriyi temsil eder.
# ========================================================================

@dataclass
class RawErrorData:
    """Tek bir kural ihlalinin, XML'den ayrıştırılmış ham verilerini temsil eder."""
    rule_id: str
    specification: str
    clause: str
    test_number: str
    object_type: str
    tags: List[str]
    description: str
    test_expression: str
    error_message: str
    context: str
    failed_checks: int
    profile: str
    issn: Optional[str] = None
    openalexid: Optional[str] = None
    xml_file_path: Optional[str] = None


@dataclass
class ArticleComplianceData:
    """
    Tek bir makaleye ait tüm ham hata verilerini ve işleme bilgilerini
    bir arada tutar. `xml_parser`'ın çıktısı bu nesnedir.
    """
    issn: str
    openalexid: str
    analysis_timestamp: str
    raw_errors: List[RawErrorData] = field(default_factory=list)
    xml_files_processed: List[str] = field(default_factory=list)
    processing_warnings: List[str] = field(default_factory=list)


# ========================================================================
# İŞLENMİŞ VERİ MODELLERİ (Processed Data Models)
# - Bu modeller, `compliance_analyzer` tarafından ham verilerin
#   konfigürasyon kurallarıyla zenginleştirilmesiyle oluşturulur.
# ========================================================================

@dataclass
class ProcessedError:
    """
    Ham hata verisinin, kural tanımlarıyla zenginleştirilmiş halidir.
    Analiz ve raporlama bu model üzerinden yapılır.
    """
    rule_id: str
    profile: str
    description: str
    iso_reference: str
    preservation_risk: str
    accessibility_impact: str
    intervention_priority: int
    affects_2069_readability: bool
    affects_current_access: bool
    category_key: str
    failed_checks: int
    is_mapped_rule: bool
    # Orijinal ham veriden gelen diğer tanımlayıcı alanlar
    issn: str
    openalexid: str
    object_type: str
    tags: List[str]
    error_message: str
    context: str


@dataclass
class ComplianceAnalysis:
    """
    Tek bir makale için tamamlanmış, kapsamlı analiz sonuçlarını içerir.
    `compliance_analyzer`'ın ana çıktısıdır.
    """
    # Kimlik Bilgileri
    issn: str
    openalexid: str
    analysis_timestamp: str
    
    # Uyumluluk Durumu
    pdfa_compliant: bool
    pdfua_compliant: bool
    pdfa_compliance_percentage: float
    pdfua_compliance_percentage: float
    
    # Risk ve Öncelik Skorları
    preservation_risk_score: float
    accessibility_impact_score: float
    intervention_priority: int
    readable_in_2069: bool
    current_accessibility_status: str
    
    # Hata Detayları
    total_errors_found: int
    processed_errors: List[ProcessedError] = field(default_factory=list)
    error_categories: Dict[str, int] = field(default_factory=dict)
    unmapped_rules: List[str] = field(default_factory=list)
    processing_warnings: List[str] = field(default_factory=list)