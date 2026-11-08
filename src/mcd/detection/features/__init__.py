from mcd.core.enums import Domain
from mcd.detection.features.auth import AuthFeatures
from mcd.detection.features.base import FeatureExtractor
from mcd.detection.features.config import ConfigFeatures
from mcd.detection.features.network import NetworkFeatures

EXTRACTORS: dict[Domain, type[FeatureExtractor]] = {
    Domain.NETWORK: NetworkFeatures,
    Domain.AUTH: AuthFeatures,
    Domain.CONFIG: ConfigFeatures,
}

__all__ = ["FeatureExtractor", "NetworkFeatures", "AuthFeatures", "ConfigFeatures", "EXTRACTORS"]
