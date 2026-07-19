import json
from datetime import datetime, timezone

from capra.layer2.nvd.cache import NvdCache


def test_nvd_cache_hit_miss_and_corrupt(tmp_path):
    cache = NvdCache(tmp_path, ttl_seconds=60)
    assert cache.read("CVE-2024-1234").status == "miss"
    cache.write("CVE-2024-1234", {"vulnerabilities": []}, datetime.now(timezone.utc))
    assert cache.read("CVE-2024-1234").status == "hit"
    cache.path_for("CVE-2024-1234").write_text("not json")
    corrupt = cache.read("CVE-2024-1234")
    assert corrupt.status == "corrupt"
    assert corrupt.warning


def test_nvd_cache_uses_safe_validated_filename(tmp_path):
    cache = NvdCache(tmp_path)
    try:
        cache.path_for("../../secret")
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe CVE ID accepted")
