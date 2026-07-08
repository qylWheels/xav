#pragma once

#include <leveldb/db.h>

// FIXME: Only for tests.
#define XAV_EXACT_HASH_DB \
    "/home/comma/projs/xav-db/malware_database/malware-bazaar-sha256.db"

class LevelDbRef {
public:
    static leveldb::DB* get_leveldb_ref() {
        static leveldb::DB* db = nullptr;

        // Lazy initialization.
        if (db == nullptr) {
            leveldb::Status status =
                leveldb::DB::Open(leveldb::Options{}, XAV_EXACT_HASH_DB, &db);
            if (!status.ok()) {
                perror("leveldb::DB::Open");
                exit(1);
            }
        }

        return db;
    }

private:
    LevelDbRef();
    ~LevelDbRef();
    LevelDbRef(const LevelDbRef&) = delete;
    LevelDbRef& operator=(const LevelDbRef&) = delete;
    LevelDbRef(LevelDbRef&&) = delete;
    LevelDbRef& operator=(LevelDbRef&&) = delete;
};
