<?php

namespace Tests\Support\Concurrency;

use PDO;

final class SchemaBaseline
{
    /** @return array<string, list<array<string, mixed>>> */
    public static function snapshot(PDO $connection): array
    {
        // Compare schema only: sequence positions, application rows and fixture ownership are not schema.
        $queries = [
            'tables' => "SELECT c.relname AS table_name, c.relpersistence AS persistence, c.relrowsecurity AS row_security FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND c.relname NOT IN ('migrations','concurrency_run') ORDER BY c.relname",
            'columns' => "SELECT c.relname AS table_name, a.attnum AS position, a.attname AS column_name, format_type(a.atttypid,a.atttypmod) AS type, a.attnotnull AS not_null, pg_get_expr(d.adbin,d.adrelid) AS default_value FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND c.relkind='r' AND c.relname NOT IN ('migrations','concurrency_run') AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum",
            'constraints' => "SELECT c.relname AS table_name, k.conname AS name, k.contype AS type, pg_get_constraintdef(k.oid) AS definition FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname NOT IN ('migrations','concurrency_run') ORDER BY c.relname,k.conname",
            'indexes' => "SELECT t.relname AS table_name, c.relname AS name, i.indisvalid AS valid, i.indisready AS ready, pg_get_indexdef(c.oid) AS definition FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public' AND t.relname NOT IN ('migrations','concurrency_run') ORDER BY t.relname,c.relname",
            'sequences' => "SELECT sequencename AS name, data_type::text AS type, start_value, min_value, max_value, increment_by, cycle, cache_size FROM pg_sequences WHERE schemaname='public' AND sequencename <> 'migrations_id_seq' ORDER BY sequencename",
        ];
        $snapshot = [];
        foreach ($queries as $category => $query) {
            $snapshot[$category] = $connection->query($query)->fetchAll(PDO::FETCH_ASSOC);
        }

        return $snapshot;
    }
}
