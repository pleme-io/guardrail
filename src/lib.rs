pub mod biometric;
pub mod cache;
pub mod config;
pub mod engine;
pub mod hook;
pub mod journal;
pub mod model;
pub mod testing;

// Re-export hayai types that guardrail consumers use
pub use hayai::engine::{
    ChainedNormalizer, IdentityNormalizer, Normalizer, NullPrefilter, PathNormalizer, Prefilter,
};
pub use hayai::cache::{CacheStore, FixedFingerprinter, Fingerprinter, MemCache};

// Re-export domain types
pub use cache::{FsCache, FsFingerprinter};
pub use config::{DefaultsProvider, DirectoryProvider, MockProvider, RuleProvider};
pub use engine::{
    NixStoreNormalizer, PrefixPrefilter, ProductionNormalizer, RegexEngine, RuleEngine,
    SqlCommentStripper,
};
pub use model::{Category, Decision, GuardrailConfig, ParseEnumError, Rule, RuleBuilder, Severity};
