//! Registre persistant minimal de Forge.
//!
//! Le registre utilise uniquement `std`: un fichier JSON par candidat et un
//! fichier binaire par clé brute. Les remplacements passent par un fichier
//! temporaire, `sync_all` puis `rename`, sous verrou intra-processus. Cela retire
//! `sled` et sa chaîne de dépendances du chemin actif sans sacrifier la
//! persistance ni l'ordre déterministe d'itération.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::candidate::CandidateId;
use crate::error::{ForgeError, Result};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GenerationRecord {
    pub candidate_id: CandidateId,
    pub source_code: String,
    pub objectives: Vec<f64>,
    pub generation: u64,
    pub parent_ids: Vec<CandidateId>,
}

#[derive(Clone)]
pub struct AlgorithmRegistry {
    root: Arc<PathBuf>,
    write_lock: Arc<Mutex<()>>,
}

impl AlgorithmRegistry {
    /// Initialise ou ouvre le répertoire de stockage persistant.
    pub fn open(path: &str) -> Result<Self> {
        let root = PathBuf::from(path);
        fs::create_dir_all(&root).map_err(|e| {
            ForgeError::Evaluation(format!("Échec de l'ouverture du registre Forge: {e}"))
        })?;
        Ok(Self {
            root: Arc::new(root),
            write_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Commit de manière atomique et synchrone un candidat validé sur le disque.
    pub fn commit_candidate(&self, record: &GenerationRecord) -> Result<()> {
        let payload = serde_json::to_vec(record).map_err(|e| {
            ForgeError::Evaluation(format!("Erreur de sérialisation du registre: {e}"))
        })?;
        self.atomic_write(&self.candidate_path(record.candidate_id), &payload)
    }

    /// Extrait le profil complet d'un ancêtre par son identifiant.
    pub fn get_candidate_record(&self, id: CandidateId) -> Result<Option<GenerationRecord>> {
        let path = self.candidate_path(id);
        match fs::read(&path) {
            Ok(bytes) => {
                let record = serde_json::from_slice(&bytes).map_err(|e| {
                    ForgeError::Evaluation(format!("Données de registre corrompues: {e}"))
                })?;
                Ok(Some(record))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ForgeError::Evaluation(format!(
                "Erreur d'accès au registre Forge: {error}"
            ))),
        }
    }

    /// Parcourt tous les enregistrements candidats dans l'ordre de leur nom de
    /// fichier, donc dans l'ordre croissant de `CandidateId`.
    pub fn iter(&self) -> impl Iterator<Item = Result<GenerationRecord>> {
        let mut paths = match fs::read_dir(self.root.as_ref()) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| is_candidate_path(path))
                .collect::<Vec<_>>(),
            Err(error) => {
                return vec![Err(ForgeError::Evaluation(format!(
                    "Erreur d'itération du registre Forge: {error}"
                )))]
                .into_iter();
            }
        };
        paths.sort();
        paths
            .into_iter()
            .map(|path| {
                let bytes = fs::read(&path).map_err(|e| {
                    ForgeError::Evaluation(format!("Lecture registre {}: {e}", path.display()))
                })?;
                serde_json::from_slice(&bytes).map_err(|e| {
                    ForgeError::Evaluation(format!("Désérialisation {}: {e}", path.display()))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Commit brut (clé + payload arbitraire) pour le checkpointing moteur.
    pub fn commit_raw(&self, key: &[u8], payload: &[u8]) -> Result<()> {
        self.atomic_write(&self.raw_path(key), payload)
    }

    /// Récupère un payload brut par clé.
    pub fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match fs::read(self.raw_path(key)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ForgeError::Evaluation(format!(
                "Erreur get_raw du registre Forge: {error}"
            ))),
        }
    }

    /// Nombre total d'enregistrements persistés (candidats + clés brutes).
    pub fn len(&self) -> usize {
        fs::read_dir(self.root.as_ref())
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| {
                        let name = entry.file_name();
                        let name = name.to_string_lossy();
                        (name.starts_with("candidate-") && name.ends_with(".json"))
                            || (name.starts_with("raw-") && name.ends_with(".bin"))
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn candidate_path(&self, id: CandidateId) -> PathBuf {
        self.root.join(format!("candidate-{id:016x}.json"))
    }

    fn raw_path(&self, key: &[u8]) -> PathBuf {
        self.root.join(format!("raw-{}.bin", hex_encode(key)))
    }

    fn atomic_write(&self, destination: &Path, payload: &[u8]) -> Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| ForgeError::Evaluation("Verrou du registre Forge empoisonné".into()))?;
        let file_name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ForgeError::Evaluation("Nom de fichier de registre invalide".into()))?;
        let temporary = self
            .root
            .join(format!(".{file_name}.tmp-{}", std::process::id()));

        let write_result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(payload)?;
            file.sync_all()?;
            fs::rename(&temporary, destination)?;
            sync_directory(self.root.as_ref())?;
            Ok(())
        })();

        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary);
            return Err(ForgeError::Evaluation(format!(
                "Échec commit atomique du registre Forge: {error}"
            )));
        }
        Ok(())
    }
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn is_candidate_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("candidate-") && name.ends_with(".json"))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> String {
        format!("/tmp/forge_registry_v4_{}_{}", std::process::id(), name)
    }

    #[test]
    fn test_commit_and_get() {
        let path = tmp_path("commit");
        let _ = std::fs::remove_dir_all(&path);
        let reg = AlgorithmRegistry::open(&path).expect("open");

        let record = GenerationRecord {
            candidate_id: 42,
            source_code: "fn main() {}".into(),
            objectives: vec![1.0, 2.0],
            generation: 3,
            parent_ids: vec![10, 11],
        };

        reg.commit_candidate(&record).expect("commit");
        let fetched = reg.get_candidate_record(42).expect("get").expect("found");
        assert_eq!(fetched.candidate_id, 42);
        assert_eq!(fetched.generation, 3);
        assert_eq!(fetched.parent_ids, vec![10, 11]);

        let reopened = AlgorithmRegistry::open(&path).expect("reopen");
        assert_eq!(
            reopened
                .get_candidate_record(42)
                .expect("get")
                .expect("found")
                .source_code,
            "fn main() {}"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_iter_and_empty() {
        let path = tmp_path("iter");
        let _ = std::fs::remove_dir_all(&path);
        let reg = AlgorithmRegistry::open(&path).expect("open");
        assert!(reg.is_empty());

        for i in 0..5 {
            reg.commit_candidate(&GenerationRecord {
                candidate_id: i,
                source_code: format!("v{i}"),
                objectives: vec![i as f64],
                generation: i,
                parent_ids: if i == 0 { vec![] } else { vec![i - 1] },
            })
            .unwrap();
        }

        assert_eq!(reg.len(), 5);
        let all: Vec<_> = reg.iter().collect::<Result<Vec<_>>>().expect("iter");
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].candidate_id, 0);
        assert_eq!(all[4].candidate_id, 4);

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn raw_payload_roundtrips_and_survives_reopen() {
        let path = tmp_path("raw");
        let _ = std::fs::remove_dir_all(&path);
        let reg = AlgorithmRegistry::open(&path).expect("open");
        reg.commit_raw(b"checkpoint/latest", b"sealed-state")
            .expect("commit raw");
        assert_eq!(
            reg.get_raw(b"checkpoint/latest").unwrap(),
            Some(b"sealed-state".to_vec())
        );

        let reopened = AlgorithmRegistry::open(&path).expect("reopen");
        assert_eq!(
            reopened.get_raw(b"checkpoint/latest").unwrap(),
            Some(b"sealed-state".to_vec())
        );
        let _ = std::fs::remove_dir_all(&path);
    }
}
