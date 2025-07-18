"""
VeraPDF Analiz Sistemi için Gelişmiş Konfigürasyon Yöneticisi.

Bu modül, analiz süreci için gerekli olan tüm ayarları, kuralları ve parametreleri,
sorumlulukların ayrılması prensibine göre yapılandırılmış birden çok JSON dosyasından
yüklemek ve yönetmekle sorumludur.

Bu yapı, aşağıdaki avantajları sağlar:
- Yönetilebilirlik: Her ayar grubu kendi mantıksal dosyasında yer alır.
- Sağlamlık: Bir konfigürasyon dosyasındaki hata, diğerlerini etkilemez.
- Ekip Çalışması: Farklı rollerdeki ekip üyeleri (araştırmacı, geliştirici)
  kendi ayar dosyaları üzerinde güvenle çalışabilir.
- Genişletilebilirlik: Yeni ayar grupları sisteme kolayca eklenebilir.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

# Proje içindeki veri modellerinin tek bir yerden import edildiği varsayılır.
# from .models import RuleDefinition

# --- GEÇİCİ MODEL TANIMI (Normalde models.py'den gelmeli) ---
from dataclasses import dataclass

@dataclass
class RuleDefinition:
    """Tek bir doğrulama kuralının tüm özelliklerini içeren veri modeli."""
    rule_id: str
    specification: str
    clause: str
    test_number: str
    object_type: str
    tags: List[str]
    description: str
    iso_standard: str
    iso_clause: str
    preservation_risk: str
    accessibility_impact: str
    affects_2069_readability: bool
    affects_current_access: bool
    intervention_priority: int
    profile: str
# --- GEÇİCİ MODEL TANIMI SONU ---


class ConfigurationManager:
    """
    Sistemin tüm konfigürasyonunu yönetir.

    Ayarları ve kuralları, `config` dizini altındaki özel JSON dosyalarından
    yükler ve uygulama içinde tutarlı bir şekilde erişilebilir kılar.

    Attributes:
        config_dir (Path): Kök konfigürasyon dizininin yolu.
        logger (logging.Logger): Sınıf içi loglama nesnesi.
        settings (Dict[str, Any]): Tüm JSON dosyalarından birleştirilmiş ayarlar.
        pdfa_rules (Dict[str, RuleDefinition]): Yüklenmiş PDF/A-2U kuralları.
        pdfua_rules (Dict[str, RuleDefinition]): Yüklenmiş PDF/UA-1 kuralları.
    """

    # Yüklenecek ayar dosyalarının listesi. Sıralama önemli değildir.
    _SETTINGS_FILES = [
        "1_project.json",
        "2_scoring.json",
        "3_analysis_flow.json",
        "4_reporting.json",
        "5_technical.json",
        "6_extensions.json",
    ]

    def __init__(self, config_dir: Path):
        """
        ConfigurationManager'ı başlatır ve tüm konfigürasyon dosyalarını yükler.

        Args:
            config_dir (Path): Konfigürasyon dosyalarını içeren ana dizin.
        """
        self.config_dir = Path(config_dir)
        self.logger = self._setup_logging()

        self.logger.info(f"'{self.config_dir}' dizininden konfigürasyon yükleniyor.")

        # 1. Adım: Tüm ayar dosyalarını yükle ve birleştir.
        self.settings: Dict[str, Any] = {}
        self._load_and_merge_settings()

        # 2. Adım: Kural tanımlarını yükle.
        rules_path = self.config_dir / "rules"
        self.pdfa_rules = self._load_rules_from_json(
            rules_path / "pdfa_2u_rules.json", "PDF/A-2U"
        )
        self.pdfua_rules = self._load_rules_from_json(
            rules_path / "pdfua_1_rules.json", "PDF/UA-1"
        )
        self.logger.info("Konfigürasyon yöneticisi başarıyla başlatıldı.")

    def _setup_logging(self) -> logging.Logger:
        """Sınıf için özel bir logger nesnesi oluşturur."""
        logger = logging.getLogger("ConfigurationManager")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "[ConfigManager] %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def _load_json_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Tek bir JSON dosyasını güvenli bir şekilde yükler.

        Dosya bulunamazsa veya JSON formatı bozuksa, loglama yapar ve
        boş bir sözlük döndürür.

        Args:
            file_path (Path): Yüklenecek JSON dosyasının tam yolu.

        Returns:
            Dict[str, Any]: JSON dosyasının içeriği veya hata durumunda boş sözlük.
        """
        if not file_path.is_file():
            self.logger.warning(f"Ayar dosyası bulunamadı: {file_path}")
            return {}
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.logger.debug(f"'{file_path.name}' başarıyla yüklendi.")
                return data
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON format hatası: {file_path}. Hata: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"'{file_path.name}' yüklenirken beklenmedik bir hata oluştu: {e}")
            return {}

    def _load_and_merge_settings(self) -> None:
        """
        Tüm ayar dosyalarını yükler ve `self.settings` içinde birleştirir.
        """
        self.logger.info(f"{len(self._SETTINGS_FILES)} adet ayar dosyası birleştiriliyor...")
        for filename in self._SETTINGS_FILES:
            file_path = self.config_dir / filename
            data = self._load_json_file(file_path)
            # Anahtarların çakışmaması için basit bir update yeterlidir.
            self.settings.update(data)
        self.logger.info("Ayar dosyaları başarıyla birleştirildi.")


    def _load_rules_from_json(
        self, file_path: Path, profile: str
    ) -> Dict[str, RuleDefinition]:
        """
        Verilen JSON kural dosyasını yükler ve RuleDefinition nesnelerine çevirir.

        Args:
            file_path (Path): Yüklenecek kural dosyasının tam yolu.
            profile (str): Yüklenecek kuralların profili (örn. 'PDF/A-2U').

        Returns:
            Dict[str, RuleDefinition]: Kural ID'si ile eşleştirilmiş kural nesneleri.
        """
        rules_data = self._load_json_file(file_path)
        if not rules_data:
            return {}

        # JSON yapısındaki kök anahtarı (örn: 'pdfa_2u_rules') dinamik olarak bul
        root_key = next((key for key in rules_data if key.endswith('_rules')), None)
        if not root_key or 'rules' not in rules_data[root_key]:
            self.logger.error(f"'{file_path.name}' dosyasında beklenen '..._rules' yapısı bulunamadı.")
            return {}

        rules_list = rules_data[root_key]['rules']
        rules_dict: Dict[str, RuleDefinition] = {}
        for i, rule_json in enumerate(rules_list):
            try:
                # Kural nesnesini oluşturmadan önce profilin doğru olduğundan emin ol
                if rule_json.get("profile") != profile:
                    self.logger.warning(
                        f"Atlanıyor: '{file_path.name}' içindeki kural {i} "
                        f"beklenen profille ('{profile}') eşleşmiyor."
                    )
                    continue

                rule = RuleDefinition(**rule_json)
                rules_dict[rule.rule_id] = rule
            except TypeError as e:
                self.logger.error(
                    f"Kural nesnesi oluşturulamadı. '{file_path.name}', kural #{i+1}. "
                    f"Eksik veya yanlış anahtar olabilir. Hata: {e}"
                )
            except Exception as e:
                self.logger.error(
                    f"'{file_path.name}' dosyasındaki kural {i+1} işlenirken hata oluştu: {e}"
                )

        self.logger.info(
            f"'{file_path.name}' dosyasından {len(rules_dict)} adet "
            f"'{profile}' kuralı yüklendi."
        )
        return rules_dict


    # --- PUBLIC API METOTLARI ---

    def get_setting(self, key: str, default: Any = None) -> Any:
        """
        Birleştirilmiş ayarlardan bir değeri güvenli bir şekilde alır.

        Args:
            key (str): Alınacak ayarın anahtarı.
            default (Any, optional): Anahtar bulunamazsa döndürülecek varsayılan değer.
                                     Defaults to None.

        Returns:
            Any: Ayarın değeri veya varsayılan değer.
        """
        return self.settings.get(key, default)

    def get_rule_definition(self, rule_id: str, profile: str) -> Optional[RuleDefinition]:
        """
        Belirtilen profile ve kural ID'sine göre kural tanımını döndürür.

        Args:
            rule_id (str): Aranacak kuralın ID'si.
            profile (str): Kuralın ait olduğu profil ('PDF/A-2U' veya 'PDF/UA-1').

        Returns:
            Optional[RuleDefinition]: Kural bulunursa nesnesini, yoksa None döndürür.
        """
        if profile == "PDF/A-2U":
            return self.pdfa_rules.get(rule_id)
        if profile == "PDF/UA-1":
            return self.pdfua_rules.get(rule_id)

        self.logger.warning(f"Bilinmeyen profil istendi: {profile}")
        return None

    def get_total_rules_count(self, profile: str) -> int:
        """
        Belirtilen profil için yüklenmiş toplam kural sayısını verir.

        Args:
            profile (str): Profil adı.

        Returns:
            int: O profile ait toplam kural sayısı.
        """
        if profile == "PDF/A-2U":
            return len(self.pdfa_rules)
        if profile == "PDF/UA-1":
            return len(self.pdfua_rules)
        return 0


if __name__ == "__main__":
    # Bu bölüm, modülün doğrudan çalıştırıldığında nasıl kullanılacağını
    # gösteren bir örnek ve basit bir test işlevi görür.

    print("--- ConfigurationManager Test Başlatılıyor ---")

    # Geçici bir konfigürasyon yapısı oluştur
    test_config_dir = Path("./temp_config_test")
    test_config_dir.mkdir(exist_ok=True)
    (test_config_dir / "rules").mkdir(exist_ok=True)

    # Örnek dosyaları yaz
    (test_config_dir / "1_project.json").write_text(
        '{"metadata": {"author": "Test Yazar"}}', encoding="utf-8"
    )
    (test_config_dir / "2_scoring.json").write_text(
        '{"preservation_risk_weights": {"critical": 100}}', encoding="utf-8"
    )
    (test_config_dir / "rules" / "pdfa_2u_rules.json").write_text(
        """
        {
          "pdfa_2u_rules": {
            "rules": [
              {
                "rule_id": "ISO_19005_2.6.1.2.1",
                "specification": "ISO_19005_2", "clause": "6.1.2",
                "test_number": "1", "object_type": "CosDocument",
                "tags": ["syntax", "header"],
                "description": "Dosya başlığı deseni hatalı.",
                "iso_standard": "ISO 19005-2:2011", "iso_clause": "6.1.2",
                "preservation_risk": "critical", "accessibility_impact": "blocking",
                "affects_2069_readability": true, "affects_current_access": true,
                "intervention_priority": 5, "profile": "PDF/A-2U"
              }
            ]
          }
        }
        """, encoding="utf-8"
    )

    try:
        # Sınıfı başlat
        config_manager = ConfigurationManager(config_dir=test_config_dir)

        # Ayarları test et
        print("\n--- Ayar Testleri ---")
        author = config_manager.get_setting("metadata", {}).get("author")
        print(f"Proje Yazarı: {author}")
        weights = config_manager.get_setting("preservation_risk_weights")
        print(f"Risk Ağırlıkları: {weights}")
        non_existent = config_manager.get_setting("olmayan_ayar", "Varsayılan Değer")
        print(f"Olmayan Ayar: {non_existent}")

        # Kuralları test et
        print("\n--- Kural Testleri ---")
        rule = config_manager.get_rule_definition("ISO_19005_2.6.1.2.1", "PDF/A-2U")
        if rule:
            print(f"Bulunan Kural ID: {rule.rule_id}")
            print(f"Kural Açıklaması: {rule.description}")
        else:
            print("Kural bulunamadı!")

        print(f"Toplam PDF/A-2U kural sayısı: {config_manager.get_total_rules_count('PDF/A-2U')}")
        print(f"Toplam PDF/UA-1 kural sayısı: {config_manager.get_total_rules_count('PDF/UA-1')}")

    except Exception as e:
        print(f"Test sırasında bir hata oluştu: {e}")
    finally:
        # Geçici test dosyalarını ve dizinleri temizle
        import shutil
        shutil.rmtree(test_config_dir)
        print("\n--- Test Tamamlandı ve Geçici Dosyalar Silindi ---")