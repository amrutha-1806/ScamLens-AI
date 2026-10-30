"""
Feature Extraction Orchestrator for SCAMLENS AI
Combines TF-IDF word features, TF-IDF char features, text statistical features, scam indicators, and URL lexical features into a sparse feature matrix.
Follows Scikit-learn BaseEstimator and TransformerMixin interfaces to prevent data leakage.
"""

import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix, issparse
from typing import List, Union, Dict, Any
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler

from src.config import TFIDF_WORD_CONFIG, TFIDF_CHAR_CONFIG
from src.features.text_features import extract_text_statistical_features, URL_REGEX
from src.features.url_features import extract_url_lexical_features
from src.utils.logger import get_logger

logger = get_logger("FeatureExtractor")


class FeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Unified Feature Extraction Pipeline for SCAMLENS AI.
    Integrates:
      1. Word TF-IDF Vectorizer
      2. Character TF-IDF Vectorizer
      3. Text Statistical & Scam Indicator Features
      4. URL Lexical & Structural Features
      5. MaxAbsScaler for numerical features (sparse matrix compatible)
    """

    def __init__(self):
        # Configure Word TF-IDF Vectorizer
        word_cfg = TFIDF_WORD_CONFIG.copy()
        ngram_word = tuple(word_cfg.pop("ngram_range", [1, 2]))
        max_feat_word = word_cfg.pop("max_features", 5000)
        
        self.word_vectorizer = TfidfVectorizer(
            ngram_range=ngram_word,
            max_features=max_feat_word,
            **word_cfg
        )

        # Configure Character TF-IDF Vectorizer
        char_cfg = TFIDF_CHAR_CONFIG.copy()
        ngram_char = tuple(char_cfg.pop("ngram_range", [3, 5]))
        max_feat_char = char_cfg.pop("max_features", 5000)
        
        self.char_vectorizer = TfidfVectorizer(
            analyzer="char",
            ngram_range=ngram_char,
            max_features=max_feat_char,
            **char_cfg
        )

        # Scaler for numeric dense features (preserves sparsity & works with sparse matrices)
        self.scaler = MaxAbsScaler()
        self.is_fitted = False
        self.dense_feature_names_: List[str] = []

    def _extract_dense_features(self, raw_texts: List[str]) -> np.ndarray:
        """Helper to extract dense statistical, indicator, and URL features for a batch of texts."""
        dense_rows = []
        
        for text in raw_texts:
            text_str = str(text) if text is not None else ""
            stat_feats = extract_text_statistical_features(text_str)
            
            # If URL is present in text or if input itself is a URL, extract URL features
            urls = URL_REGEX.findall(text_str)
            target_url = urls[0] if urls else (text_str if text_str.startswith(("http://", "https://")) else "")
            url_feats = extract_url_lexical_features(target_url)

            combined_dict = {**stat_feats, **url_feats}

            if not self.dense_feature_names_:
                self.dense_feature_names_ = list(combined_dict.keys())

            dense_rows.append([combined_dict[k] for k in self.dense_feature_names_])

        if not dense_rows:
            return np.zeros((0, len(self.dense_feature_names_)))
            
        return np.array(dense_rows, dtype=np.float64)

    def _preprocess_input(self, X: Union[str, List[str], pd.Series, np.ndarray]) -> List[str]:
        """Convert input X into a clean list of text strings."""
        if isinstance(X, str):
            return [X]
        elif isinstance(X, pd.Series):
            return X.fillna("").astype(str).tolist()
        elif isinstance(X, np.ndarray):
            return X.astype(str).tolist()
        elif isinstance(X, (list, tuple)):
            return [str(item) if item is not None else "" for item in X]
        else:
            return [str(X)]

    def fit(self, X: Union[str, List[str], pd.Series, np.ndarray], y=None):
        """
        Fit vectorizers and scalers ONLY on training data.
        Prevents data leakage across train/test splits.
        """
        texts = self._preprocess_input(X)
        logger.info(f"Fitting FeatureExtractor on {len(texts)} samples...")

        n_samples = len(texts)
        if n_samples < 3:
            self.word_vectorizer.min_df = 1
            self.word_vectorizer.max_df = 1.0
            self.char_vectorizer.min_df = 1
            self.char_vectorizer.max_df = 1.0

        # 1. Fit Word TF-IDF
        self.word_vectorizer.fit(texts)

        # 2. Fit Char TF-IDF
        self.char_vectorizer.fit(texts)

        # 3. Extract & Fit Scaler on Dense Numerical Features
        dense_matrix = self._extract_dense_features(texts)
        self.scaler.fit(dense_matrix)

        self.is_fitted = True
        logger.info(f"FeatureExtractor successfully fitted. Total feature count: {len(self.get_feature_names_out())}")
        return self

    def transform(self, X: Union[str, List[str], pd.Series, np.ndarray]) -> csr_matrix:
        """
        Transform raw text messages into a unified sparse feature matrix using fitted components.
        """
        if not self.is_fitted:
            raise RuntimeError("FeatureExtractor must be fitted using fit() before calling transform()!")

        texts = self._preprocess_input(X)

        # 1. Transform Word TF-IDF (sparse)
        X_word_sparse = self.word_vectorizer.transform(texts)

        # 2. Transform Char TF-IDF (sparse)
        X_char_sparse = self.char_vectorizer.transform(texts)

        # 3. Extract & Scale Dense Features
        dense_matrix = self._extract_dense_features(texts)
        dense_scaled = self.scaler.transform(dense_matrix)
        X_dense_sparse = csr_matrix(dense_scaled)

        # 4. Stack into a single memory-efficient sparse CSR matrix
        X_combined = hstack([X_word_sparse, X_char_sparse, X_dense_sparse], format="csr")

        return X_combined

    def fit_transform(self, X: Union[str, List[str], pd.Series, np.ndarray], y=None) -> csr_matrix:
        """Fit to data, then transform it."""
        return self.fit(X, y).transform(X)

    def get_feature_names_out(self) -> List[str]:
        """
        Return the list of all feature names across word TF-IDF, char TF-IDF, and dense features.
        """
        if not self.is_fitted:
            raise RuntimeError("FeatureExtractor must be fitted to get feature names!")

        word_names = [f"word_tfidf__{name}" for name in self.word_vectorizer.get_feature_names_out()]
        char_names = [f"char_tfidf__{name}" for name in self.char_vectorizer.get_feature_names_out()]
        dense_names = [f"dense_stat__{name}" for name in self.dense_feature_names_]

        return word_names + char_names + dense_names
