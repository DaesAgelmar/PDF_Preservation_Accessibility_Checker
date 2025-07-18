"""
VeraPDF Ham Verileri için Uyumluluk Analiz ve Raporlama Motoru.

Bu modül, `xml_parser` tarafından üretilen ham verileri alır, `ConfigurationManager`
aracılığıyla yüklenen kurallar ve skorlama ağırlıklarıyla bu verileri analiz eder.
Sonuç olarak, detaylı CSV ve özet raporlar oluşturur.

Pipeline'daki 2. Aşamadır: (1. Aşama: Parsing -> 2. Aşama: Analysis)
"""
import csv
import json
import logging
import statistics
from pathlib import Path
from collections import Counter, defaultdict
from dataclasses import asdict
from typing import List, Dict, Optional, Any


from tqdm import tqdm

# Merkezi modüllerden importlar
try:
    from configuration_manager import ConfigurationManager
    from data_models import (
        ArticleComplianceData, ComplianceAnalysis, ProcessedError, RawErrorData
    )
except ImportError as e:
    print(
        f"HATA: Gerekli modül bulunamadı: {e}. Lütfen tüm proje dosyalarının "
        "doğru dizinde olduğundan emin olun."
    )
    exit(1)


class ComplianceAnalyzer:
    """
    Ham verileri, yapılandırılmış kurallara göre analiz edip raporlar.
    """

    def __init__(self, config_manager: ConfigurationManager, output_dir: Path):
        """
        Analyzer'ı başlatır.

        Args:
            config_manager: Önceden başlatılmış ConfigurationManager nesnesi.
            output_dir: Tüm raporların ve çıktıların kaydedileceği dizin.
        """
        self.config_manager = config_manager
        self.output_dir = output_dir
        self.logger = self._setup_logging()

        # Raporlama için kullanılacak ayarları al
        self.settings = self.config_manager.settings
        self.unmapped_rules_global = Counter()

        self.logger.info("Compliance Analyzer başarıyla başlatıldı.")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "reports").mkdir(exist_ok=True)

    def _setup_logging(self) -> logging.Logger:
        """Sınıf için loglama nesnesi oluşturur."""
        logger = logging.getLogger("ComplianceAnalyzer")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "[Analyzer] %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def _process_raw_error(self, raw_error: RawErrorData) -> ProcessedError:
        """Ham hatayı, kural tanımıyla zenginleştirerek ProcessedError'a çevirir."""
        rule_def = self.config_manager.get_rule_definition(
            raw_error.rule_id, raw_error.profile
        )

        if rule_def:
            return ProcessedError(
                rule_id=raw_error.rule_id,
                profile=raw_error.profile,
                description=rule_def.description,
                iso_reference=f"{rule_def.iso_standard}, clause {rule_def.iso_clause}",
                preservation_risk=rule_def.preservation_risk,
                accessibility_impact=rule_def.accessibility_impact,
                intervention_priority=rule_def.intervention_priority,
                affects_2069_readability=rule_def.affects_2069_readability,
                affects_current_access=rule_def.affects_current_access,
                category_key=f"{raw_error.object_type}.{raw_error.tags[0] if raw_error.tags else 'general'}",
                failed_checks=raw_error.failed_checks,
                is_mapped_rule=True,
                issn=raw_error.issn,
                openalexid=raw_error.openalexid,
                object_type=raw_error.object_type,
                tags=raw_error.tags,
                error_message=raw_error.error_message,
                context=raw_error.context
            )

        # Kural haritalanmamışsa (unmapped) varsayılan değerler ata
        self.unmapped_rules_global[raw_error.rule_id] += raw_error.failed_checks
        return ProcessedError(
            rule_id=raw_error.rule_id,
            profile=raw_error.profile,
            description=f"[UNMAPPED] {raw_error.description}",
            iso_reference="N/A",
            preservation_risk="unmapped",
            accessibility_impact="unmapped",
            intervention_priority=1,
            affects_2069_readability=False,
            affects_current_access=False,
            category_key=f"{raw_error.object_type}.unmapped",
            failed_checks=raw_error.failed_checks,
            is_mapped_rule=False,
            issn=raw_error.issn,
            openalexid=raw_error.openalexid,
            object_type=raw_error.object_type,
            tags=raw_error.tags,
            error_message=raw_error.error_message,
            context=raw_error.context
        )

    def _calculate_scores(self, analysis: ComplianceAnalysis):
        """Yardımcı skorlama fonksiyonlarını çağırır."""
        weights = self.settings.get("preservation_risk_weights", {})
        analysis.preservation_risk_score = sum(
            e.failed_checks * weights.get(e.preservation_risk, 1)
            for e in analysis.processed_errors if e.profile == "PDF/A-2U"
        )

        weights = self.settings.get("accessibility_impact_weights", {})
        analysis.accessibility_impact_score = sum(
            e.failed_checks * weights.get(e.accessibility_impact, 1)
            for e in analysis.processed_errors if e.profile == "PDF/UA-1"
        )

    def _determine_priority_and_status(self, analysis: ComplianceAnalysis):
        """Müdahale önceliğini ve erişilebilirlik durumunu belirler."""
        thresholds = self.settings.get("intervention_priority_thresholds", {})
        critical_count = sum(e.failed_checks for e in analysis.processed_errors if e.preservation_risk == 'critical')
        blocking_count = sum(e.failed_checks for e in analysis.processed_errors if e.accessibility_impact == 'blocking')
        high_count = sum(e.failed_checks for e in analysis.processed_errors if e.preservation_risk == 'high')
        major_count = sum(e.failed_checks for e in analysis.processed_errors if e.accessibility_impact == 'major')

        if critical_count >= thresholds.get("critical_errors_for_priority_5", 1) or \
           blocking_count >= thresholds.get("blocking_errors_for_priority_5", 1):
            analysis.intervention_priority = 5
        elif high_count >= thresholds.get("high_errors_for_priority_4", 2) or \
             major_count >= thresholds.get("major_errors_for_priority_4", 2):
            analysis.intervention_priority = 4
        # ... diğer öncelik seviyeleri eklenebilir
        else:
            analysis.intervention_priority = 1 # Varsayılan

        analysis.readable_in_2069 = not any(e.affects_2069_readability for e in analysis.processed_errors)
        if blocking_count > 0:
            analysis.current_accessibility_status = "inaccessible"
        elif major_count > 0:
            analysis.current_accessibility_status = "partial"
        else:
            analysis.current_accessibility_status = "accessible"

    def analyze_single_article(self, article_data: ArticleComplianceData) -> ComplianceAnalysis:
        """Tek bir makalenin ham verisini analiz eder."""
        processed_errors = [self._process_raw_error(err) for err in article_data.raw_errors]
        
        pdfa_errors = [e for e in processed_errors if e.profile == 'PDF/A-2U']
        pdfua_errors = [e for e in processed_errors if e.profile == 'PDF/UA-1']
        
        total_pdfa_rules = self.config_manager.get_total_rules_count('PDF/A-2U')
        total_pdfua_rules = self.config_manager.get_total_rules_count('PDF/UA-1')
        
        pdfa_failed_rules = len(set(e.rule_id for e in pdfa_errors))
        pdfua_failed_rules = len(set(e.rule_id for e in pdfua_errors))

        analysis = ComplianceAnalysis(
            issn=article_data.issn,
            openalexid=article_data.openalexid,
            analysis_timestamp=article_data.analysis_timestamp,
            pdfa_compliant=not pdfa_errors,
            pdfua_compliant=not pdfua_errors,
            pdfa_compliance_percentage=100 * (total_pdfa_rules - pdfa_failed_rules) / total_pdfa_rules if total_pdfa_rules else 100.0,
            pdfua_compliance_percentage=100 * (total_pdfua_rules - pdfua_failed_rules) / total_pdfua_rules if total_pdfua_rules else 100.0,
            preservation_risk_score=0.0,
            accessibility_impact_score=0.0,
            intervention_priority=1,
            readable_in_2069=True,
            current_accessibility_status="accessible",
            total_errors_found=sum(e.failed_checks for e in processed_errors),
            processed_errors=processed_errors,
            error_categories=Counter(e.category_key for e in processed_errors),
            unmapped_rules=list(set(e.rule_id for e in processed_errors if not e.is_mapped_rule)),
            processing_warnings=article_data.processing_warnings
        )
        
        self._calculate_scores(analysis)
        self._determine_priority_and_status(analysis)

        return analysis

    def batch_analyze_articles(self, articles_data: List[ArticleComplianceData]) -> list[ComplianceAnalysis]:
        """Verilen tüm makaleleri toplu halde analiz eder."""
        self.logger.info(f"{len(articles_data)} adet makale için analiz başlatılıyor...")
        
        results = [
            self.analyze_single_article(article)
            for article in tqdm(articles_data, desc="Makaleler Analiz Ediliyor")
        ]
        
        self.logger.info(f"Analiz tamamlandı! {len(results)} makale işlendi.")
        return results

    def generate_all_reports(self, analyses: List[ComplianceAnalysis]):
        """Tüm analiz sonuçlarını kullanarak çeşitli raporlar oluşturur."""
        if not analyses:
            self.logger.warning("Rapor oluşturmak için analiz sonucu bulunamadı.")
            return

        self.logger.info("Tüm raporlar oluşturuluyor...")
        
        # Raporlama seçeneklerini konfigürasyondan kontrol et
        if self.settings.get("reporting_options", {}).get("create_research_summary"):
            self._export_summary_report(analyses)
        
        if self.settings.get("reporting_options", {}).get("export_formats"):
            formats = self.settings["reporting_options"]["export_formats"]
            if "csv" in formats:
                self._export_detailed_csv(analyses)

        self.logger.info(f"Raporlar '{self.output_dir}' dizinine kaydedildi.")

    def _export_summary_report(self, analyses: List[ComplianceAnalysis]):
        """Analiz sonuçlarının özetini bir metin dosyasına yazar."""
        summary_path = self.output_dir / "reports" / "analysis_summary.txt"
        
        total_articles = len(analyses)
        pdfa_compliant_count = sum(1 for a in analyses if a.pdfa_compliant)
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("VeraPDF Analiz Özeti\n")
            f.write("="*25 + "\n")
            f.write(f"Toplam Analiz Edilen Makale: {total_articles}\n")
            f.write(f"PDF/A Uyumlu Makale Sayısı: {pdfa_compliant_count}\n")
            f.write(f"PDF/A Uyumluluk Oranı: {100 * pdfa_compliant_count / total_articles:.2f}%\n")
        
        self.logger.info(f"Özet raporu oluşturuldu: {summary_path}")

    def _export_detailed_csv(self, analyses: List[ComplianceAnalysis]):
        """Tüm işlenmiş hataların detaylı bir CSV dosyasını oluşturur."""
        csv_path = self.output_dir / "processed_errors_detail.csv"
        
        # asdict kullanarak dataclass'ı sözlüğe çevir ve başlıkları al
        if not analyses or not analyses[0].processed_errors:
            self.logger.warning("CSV oluşturmak için işlenmiş hata bulunamadı.")
            return

        headers = asdict(analyses[0].processed_errors[0]).keys()
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for analysis in analyses:
                for error in analysis.processed_errors:
                    writer.writerow(asdict(error))

        self.logger.info(f"Detaylı CSV raporu oluşturuldu: {csv_path}")


if __name__ == '__main__':
    import argparse

    cli_parser = argparse.ArgumentParser(
        description="VeraPDF ham verilerini analiz eder ve raporlar oluşturur."
    )
    cli_parser.add_argument(
        "--config-dir", type=Path, required=True,
        help="JSON konfigürasyon dosyalarını içeren dizin."
    )
    cli_parser.add_argument(
        "--input-file", type=Path, required=True,
        help="`xml_parser.py` tarafından oluşturulan `raw_extracted_data.json` dosyası."
    )
    cli_parser.add_argument(
        "--output-dir", type=Path, default=Path("analysis_results"),
        help="Analiz raporlarının kaydedileceği dizin."
    )
    args = cli_parser.parse_args()

    # 1. Konfigürasyonu yükle
    config = ConfigurationManager(config_dir=args.config_dir)

    # 2. Ham veriyi dosyadan oku
    logging.info(f"Ham veri '{args.input_file}' dosyasından okunuyor...")
    try:
        with open(args.input_file, 'r', encoding='utf-8') as f:
            raw_data_list = json.load(f)
        
        # JSON sözlüklerini tekrar ArticleComplianceData nesnelerine çevir
        articles_to_analyze = [ArticleComplianceData(**data) for data in raw_data_list]
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Girdi dosyası okunamadı: {e}")
        exit(1)

    # 3. Analiz motorunu başlat ve çalıştır
    analyzer = ComplianceAnalyzer(config_manager=config, output_dir=args.output_dir)
    analysis_results = analyzer.batch_analyze_articles(articles_to_analyze)

    # 4. Raporları oluştur
    analyzer.generate_all_reports(analysis_results)

    print(f"\n✅ Analiz ve raporlama tamamlandı. Çıktılar '{args.output_dir}' dizininde.")