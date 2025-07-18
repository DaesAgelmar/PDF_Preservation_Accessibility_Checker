"""
VeraPDF Uyumluluk Analiz Pipeline'ı - Ana Yönetici Betiği

Bu betik, projenin ana giriş noktasıdır ve tüm analiz sürecini yönetir.
Aşağıdaki adımları sırasıyla uygular:
1. Gerekli konfigürasyonları yükler.
2. Belirtilen dizindeki XML dosyalarını paralel olarak ayrıştırır (parsing).
3. Ayrıştırılmış ham verileri analiz eder.
4. Analiz sonuçlarından kapsamlı raporlar oluşturur.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from dataclasses import asdict

# Proje modüllerini import et
try:
    from configuration_manager import ConfigurationManager
    from xml_parser import VeraPDFXMLParser
    from compliance_analyzer import ComplianceAnalyzer
    from data_models import ArticleComplianceData
except ImportError as e:
    print(
        f"HATA: Gerekli bir modül bulunamadı: {e}. Lütfen tüm proje "
        "dosyalarının doğru dizinde olduğundan ve sanal ortamınızın "
        "aktif olduğundan emin olun."
    )
    sys.exit(1)


def setup_global_logging(log_level: str = 'INFO'):
    """Tüm uygulama için temel loglama ayarlarını yapar."""
    logging.basicConfig(
        level=log_level.upper(),
        format='[%(asctime)s] [%(name)-20s] [%(levelname)-8s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        stream=sys.stdout
    )
    logging.getLogger("VeraPDFXMLParser").setLevel(log_level.upper())
    logging.getLogger("ComplianceAnalyzer").setLevel(log_level.upper())
    logging.getLogger("ConfigurationManager").setLevel(log_level.upper())


def main():
    """Ana iş akışını yöneten fonksiyon."""
    # 1. Komut Satırı Argümanlarını Tanımla ve Al
    parser = argparse.ArgumentParser(
        description="VeraPDF analiz pipeline'ını uçtan uca çalıştırır.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--config-dir", type=Path, default=Path("config"),
        help="JSON konfigürasyon dosyalarını içeren dizin.\n(Varsayılan: ./config)"
    )
    parser.add_argument(
        "--input-dir", type=Path, required=True,
        help="Analiz edilecek veraPDF XML dosyalarını içeren ana dizin."
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("analysis_results"),
        help="Tüm çıktıların ve raporların kaydedileceği dizin.\n(Varsayılan: ./analysis_results)"
    )
    parser.add_argument(
        "--workers", type=int, default=None,
        help="XML ayrıştırma için kullanılacak paralel işlemci sayısı.\n(Varsayılan: tüm çekirdekler)"
    )
    parser.add_argument(
        "--skip-parsing", action="store_true",
        help="Eğer 'raw_extracted_data.json' zaten varsa, XML ayrıştırma adımını atla."
    )
    parser.add_argument(
        '--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO',
        help='Tüm proje için loglama seviyesini ayarla.'
    )
    args = parser.parse_args()

    # Genel loglama ve çıktı dizini kurulumu
    setup_global_logging(args.log_level)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger("main")
    logger.info("=" * 50)
    logger.info("VeraPDF ANALİZ PİPELİNE'I BAŞLATILIYOR")
    logger.info("=" * 50)

    # 2. Konfigürasyonu Yükle
    logger.info(f"'{args.config_dir}' dizininden konfigürasyon yükleniyor...")
    config = ConfigurationManager(config_dir=args.config_dir)

    # 3. XML Ayrıştırma (Parsing) Adımı
    raw_data_path = args.output_dir / "raw_extracted_data.json"
    articles_data = []

    if args.skip_parsing and raw_data_path.exists():
        logger.info(f"XML ayrıştırma adımı atlanıyor. Mevcut veri kullanılıyor: {raw_data_path}")
        try:
            with open(raw_data_path, 'r', encoding='utf-8') as f:
                raw_data_list = json.load(f)
            # JSON sözlüklerini tekrar ArticleComplianceData nesnelerine çevir
            articles_data = [ArticleComplianceData(**data) for data in raw_data_list]
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Mevcut ham veri dosyası ({raw_data_path}) okunamadı. Hata: {e}")
            logger.info("Lütfen --skip-parsing bayrağını kaldırarak yeniden ayrıştırma yapın.")
            sys.exit(1)
    else:
        logger.info("=== AŞAMA 1: XML VERİ ÇIKARIMI BAŞLATILIYOR ===")
        parser = VeraPDFXMLParser(log_level=args.log_level)
        articles_data = parser.batch_parse_articles(
            input_dir=args.input_dir,
            workers=args.workers
        )
        if articles_data:
            logger.info(f"Ayrıştırma tamamlandı. Ham veri '{raw_data_path}' dosyasına kaydediliyor...")
            serializable_data = [asdict(article) for article in articles_data]
            with open(raw_data_path, 'w', encoding='utf-8') as f:
                json.dump(serializable_data, f, indent=2, ensure_ascii=False)
        else:
            logger.error("XML ayrıştırma sonucunda hiçbir veri elde edilemedi. İşlem durduruluyor.")
            sys.exit(1)

    # 4. Uyumluluk Analizi Adımı
    logger.info("=== AŞAMA 2: UYUMLULUK ANALİZİ BAŞLATILIYOR ===")
    analyzer = ComplianceAnalyzer(config_manager=config, output_dir=args.output_dir)
    analysis_results = analyzer.batch_analyze_articles(articles_data)

    # 5. Raporlama Adımı
    logger.info("=== AŞAMA 3: RAPOR OLUŞTURMA BAŞLATILIYOR ===")
    analyzer.generate_all_reports(analysis_results)

    logger.info("=" * 50)
    logger.info("PIPELINE BAŞARIYLA TAMAMLANDI!")
    logger.info(f"Tüm çıktılar '{args.output_dir}' dizininde bulunabilir.")
    logger.info("=" * 50)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nKullanıcı tarafından işlem iptal edildi.")
        sys.exit(0)
    except Exception as e:
        logging.getLogger("main").error(f"Beklenmedik bir hata oluştu: {e}", exc_info=True)
        sys.exit(1)