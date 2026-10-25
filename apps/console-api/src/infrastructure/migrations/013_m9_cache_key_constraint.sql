-- PostgreSQL's POSIX repetition bounds stop at 255. Keep the already-applied
-- migration checksum and retain the API's 256-character cache-key contract.
ALTER TABLE toolbox_operations DROP CONSTRAINT toolbox_operations_cache_key_check;
ALTER TABLE toolbox_operations ADD CONSTRAINT toolbox_operations_cache_key_check
 CHECK(length(cache_key) BETWEEN 1 AND 256 AND cache_key ~ '^[A-Za-z0-9_.:-]+$' AND cache_key NOT IN('.','..'));
