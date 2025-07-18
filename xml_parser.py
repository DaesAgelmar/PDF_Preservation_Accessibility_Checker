"""
VeraPDF XML Raporları için Yüksek Performanslı Paralel Ayrıştırıcı (Parser).

Bu modül, veraPDF tarafından oluşturulan XML formatındaki doğrulama raporlarını
paralel olarak işleyerek ham hata verilerini çıkarmakla sorumludur.

Merkezi veri modellerini `data_models` modülünden import eder.
"""

import argparse
import json
import logging
import multiprocessing
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from tqdm import tqdm

# Merkezi veri modelleri projenin 'data_models.py' dosyasından alınıyor.
try:
    from data_models import ArticleComplianceData, RawErrorData
except ImportError:
    print(
        "HATA: 'data_models.py' dosyası bulunamadı. Lütfen dosyanın "
        "aynı dizinde veya Python path içinde olduğundan emin olun."
    )
    exit(1)


def _parse_article_worker(task: Tuple[str, str, Path, Path]) -> ArticleComplianceData:
    """
    Multiprocessing Pool için tek bir makalenin XML'lerini işler.

    Args:
        task: İşlenecek görevi içeren bir tuple.
            Format: (issn, openalexid, ua_xml_path, pdfa_xml_path)

    Returns:
        Ayrıştırma sonuçlarını içeren veri nesnesi.
    """
    issn, openalexid, ua_xml_path, pdfa_xml_path = task
    # Her process kendi parser nesnesini oluşturur ve daha az log üretir.
    parser = VeraPDFXMLParser(log_level="ERROR")

    return parser.parse_article_xml_pair(
        issn=issn,
        openalexid=openalexid,
        ua_xml_path=ua_xml_path,
        pdfa_xml_path=pdfa_xml_path
    )


class VeraPDFXMLParser:
    """
    VeraPDF XML dosyalarını ayrıştırmak için ana sınıf.

    Bu sınıf, XML dosyalarını bulma, eşleştirme ve içlerindeki ham verileri
    `ArticleComplianceData` modeline dönüştürme mantığını içerir.
    """

    def __init__(self, log_level: str = "INFO"):
        """
        Parser'ı başlatır ve logger'ı ayarlar.

        Args:
            log_level: Loglama seviyesi ('INFO', 'DEBUG', 'WARNING', 'ERROR').
        """
        self.logger = self._setup_logging(log_level)
        self.parse_errors: List[str] = []

    def _setup_logging(self, log_level: str) -> logging.Logger:
        """Sınıf için loglama nesnesi oluşturur."""
        logger = logging.getLogger(f"VeraPDFXMLParser-{id(self)}")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "[XML Parser] %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(log_level.upper())
        return logger

    def _extract_ids_from_path(self, xml_path: Path) -> Tuple[Optional[str], Optional[str]]:
        """
        Verilen bir dosya yolundan ISSN ve OpenAlexID'yi çıkarır.

        Args:
            xml_path: XML dosyasının yolu.

        Returns:
            (ISSN, OpenAlexID) veya hata durumunda (None, None).
        """
        try:
            issn = xml_path.parent.name
            # Dosya adından '_UA1' veya '_2U' gibi son ekleri kaldır
            openalexid = xml_path.stem.rsplit('_', 1)[0]
            return issn, openalexid
        except IndexError:
            self.logger.warning(
                f"ID'ler çıkarılamadı, beklenmeyen dosya adı formatı: {xml_path.name}"
            )
            return None, None

    def find_xml_pairs(self, input_dir: Path) -> List[Tuple[str, str, Path, Path]]:
        """
        Verilen dizindeki tüm XML dosyalarını tarar ve bunları ISSN/OpenAlexID'ye
        göre eşleştirerek işlenecek görev listesini oluşturur.

        Args:
            input_dir: Taranacak ana dizin.

        Returns:
            Paralel işleme için görev listesi.
        """
        self.logger.info(f"'{input_dir}' dizininde XML çiftleri aranıyor...")

        article_map: Dict[str, Dict[str, Path]] = {}

        for xml_file in input_dir.rglob("*.xml"):
            issn, openalexid = self._extract_ids_from_path(xml_file)
            if not issn or not openalexid:
                continue

            article_key = f"{issn}-{openalexid}"

            if article_key not in article_map:
                article_map[article_key] = {}

            if "_UA1" in xml_file.name:
                article_map[article_key]['ua'] = xml_file
            elif "_2U" in xml_file.name:
                article_map[article_key]['pdfa'] = xml_file

        tasks = []
        for key, paths in article_map.items():
            issn, openalexid = key.split('-', 1)
            if 'ua' in paths and 'pdfa' in paths:
                tasks.append((issn, openalexid, paths['ua'], paths['pdfa']))
            else:
                self.logger.warning(
                    f"Eksik dosya: {openalexid} için {list(paths.keys())} bulundu."
                )

        self.logger.info(f"{len(tasks)} adet işlenecek makale çifti bulundu.")
        return tasks

    def _parse_single_xml(self, xml_path: Path, profile: str) -> List[RawErrorData]:
        """Tek bir XML dosyasını ayrıştırır ve hata listesini döndürür."""
        errors: List[RawErrorData] = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            issn, openalexid = self._extract_ids_from_path(xml_path)

            for rule_element in root.findall(".//rule[@status='failed']"):
                spec = rule_element.get("specification", "N/A")
                clause = rule_element.get("clause", "N/A")
                test_num = rule_element.get("testNumber", "N/A")

                check_element = rule_element.find(".//check[@status='failed']")
                error_message = check_element.findtext(
                    "errorMessage", "No message"
                ) if check_element else "N/A"
                context = check_element.findtext(
                    "context", "No context"
                ) if check_element else "N/A"

                # `RawErrorData` oluşturma bloğu okunabilirlik için formatlandı.
                error = RawErrorData(
                    rule_id=f"{spec}.{clause}.{test_num}",
                    specification=spec,
                    clause=clause,
                    test_number=test_num,
                    object_type=rule_element.findtext("object", "Unknown"),
                    tags=[
                        tag.strip()
                        for tag in rule_element.get("tags", "").split(",")
                        if tag.strip()
                    ],
                    description=rule_element.findtext("description", "No description"),
                    test_expression=rule_element.findtext("test", "No test expression"),
                    error_message=error_message,
                    context=context,
                    failed_checks=int(rule_element.get("failedChecks", "1")),
                    profile=profile,
                    issn=issn,
                    openalexid=openalexid,
                    xml_file_path=str(xml_path)
                )
                errors.append(error)

        except ET.ParseError as e:
            self.parse_errors.append(f"Bozuk XML dosyası: {xml_path}: {e}")
            self.logger.error(f"XML ayrıştırma hatası: {xml_path}", exc_info=True)
        except FileNotFoundError:
            self.parse_errors.append(f"Dosya bulunamadı: {xml_path}")
            self.logger.error(f"XML dosyası mevcut değil: {xml_path}")

        return errors

    def parse_article_xml_pair(
        self, issn: str, openalexid: str, ua_xml_path: Path, pdfa_xml_path: Path
    ) -> ArticleComplianceData:
        """Tek bir makalenin PDF/UA ve PDF/A XML'lerini ayrıştırır."""
        article_data = ArticleComplianceData(
            issn=issn,
            openalexid=openalexid,
            analysis_timestamp=datetime.now().isoformat(),
        )

        ua_errors = self._parse_single_xml(ua_xml_path, "PDF/UA-1")
        article_data.raw_errors.extend(ua_errors)
        article_data.xml_files_processed.append(str(ua_xml_path))

        pdfa_errors = self._parse_single_xml(pdfa_xml_path, "PDF/A-2U")
        article_data.raw_errors.extend(pdfa_errors)
        article_data.xml_files_processed.append(str(pdfa_xml_path))

        return article_data

    def batch_parse_articles(
        self, input_dir: Path, workers: Optional[int] = None
    ) -> List[ArticleComplianceData]:
        """
        Bir dizindeki tüm makale XML'lerini paralel olarak işler.

        Args:
            input_dir: Taranacak ana dizin.
            workers: Kullanılacak işlemci çekirdeği sayısı.
                     None ise, sistemdeki tüm çekirdekler kullanılır.

        Returns:
            Tüm makaleler için ayrıştırılmış veri listesi.
        """
        tasks = self.find_xml_pairs(input_dir)
        if not tasks:
            self.logger.warning("İşlenecek XML dosyası bulunamadı.")
            return []

        results: List[ArticleComplianceData] = []

        with multiprocessing.Pool(processes=workers) as pool:
            with tqdm(total=len(tasks), desc="XML Dosyaları Ayrıştırılıyor") as pbar:
                for result in pool.imap_unordered(_parse_article_worker, tasks):
                    if result:
                        results.append(result)
                    pbar.update(1)

        self.logger.info(
            f"Ayrıştırma tamamlandı! {len(results)} makale başarıyla işlendi."
        )
        if self.parse_errors:
            self.logger.warning(
                f"{len(self.parse_errors)} ayrıştırma hatasıyla karşılaşıldı. "
                "Detaylar için logları inceleyin."
            )
        return results


if __name__ == "__main__":
    # Komut satırından çalıştırıldığında programın ana giriş noktası.
    cli_parser = argparse.ArgumentParser(
        description="VeraPDF XML dosyalarını paralel olarak ayrıştırır."
    )
    cli_parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="İşlenecek XML dosyalarını içeren ana dizin."
    )
    cli_parser.add_argument(
        "--output-file",
        type=Path,
        default=Path("raw_extracted_data.json"),
        help="Çıktı olarak yazılacak JSON dosyasının adı."
    )
    cli_parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Kullanılacak paralel işlemci sayısı (varsayılan: tüm çekirdekler)."
    )
    cli_parser.add_argument(
        "--log-level",
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Loglama seviyesini ayarla.'
    )
    args = cli_parser.parse_args()

    main_parser = VeraPDFXMLParser(log_level=args.log_level)

    all_articles_data = main_parser.batch_parse_articles(
        input_dir=args.input_dir,
        workers=args.workers
    )

    if all_articles_data:
        # Dataclass listesini serileştirilebilir bir formata dönüştür
        serializable_data = [article.__dict__ for article in all_articles_data]

        with open(args.output_file, "w", encoding="utf-8") as f:
            json.dump(serializable_data, f, indent=2, ensure_ascii=False)

        print(
            f"\n✅ Başarılı! {len(all_articles_data)} makalenin verisi "
            f"'{args.output_file}' dosyasına yazıldı."
        )
    else:
        print("\n❌ Hiçbir veri işlenmedi veya kaydedilmedi.")