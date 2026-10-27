<?php
/**
 * ThreatContext-app — API entrypoint
 *
 * Serves the data-ingestion API of the ThreatContext pipeline
 * (CVE -> IOC). Mounted from ./php_scripts into /var/www/html
 * in the php:8.3-apache container (container port 80).
 *
 * Endpoints (path after the host):
 *   POST /cve-entry      -> INSERT INTO tab_cve
 *   POST /exploit-entry  -> INSERT INTO tab_exploit
 *   POST /sample-entry   -> INSERT INTO tab_sample
 *
 * Request body: JSON. Response: JSON.
 *
 * Container-internal hostname of the API (as seen by the front
 * tier / other containers): http://threatcontext-app:80/...
 * If the front tier proxies to it, expose/map the port as needed.
 */

declare(strict_types=1);

/* ============================================================
 * Configuration — ThreatContext-db connection
 * (matches docker-compose service name & credentials)
 * ============================================================ */
const DB_DSN  = 'pgsql:host=database_tier;port=5432;dbname=threatcontext_db';
const DB_USER = 'threatcontext-user';
const DB_PASS = 'Pilote123456+';

/* ============================================================
 * Helpers
 * ============================================================ */
function json_response(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

function fail(int $status, string $message): void
{
    json_response($status, ['ok' => false, 'error' => $message]);
}

function get_json_body(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') {
        fail(400, 'Empty request body; expected JSON.');
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        fail(400, 'Invalid JSON body.');
    }
    return $data;
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        try {
            $pdo = new PDO(DB_DSN, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
        } catch (PDOException $e) {
            fail(503, 'Database connection failed: ' . $e->getMessage());
        }
    }
    return $pdo;
}

function require_fields(array $data, array $fields): void
{
    $missing = [];
    foreach ($fields as $f) {
        if (!isset($data[$f]) || $data[$f] === '' || $data[$f] === null) {
            $missing[] = $f;
        }
    }
    if ($missing) {
        fail(422, 'Missing required field(s): ' . implode(', ', $missing));
    }
}

/* ============================================================
 * Request routing
 * ============================================================ */
$method = $_SERVER['REQUEST_METHOD'];
$path   = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
// Accept both /cve-entry and /index.php/cve-entry (no rewrite needed)
if (str_starts_with($path, '/index.php')) {
    $path = substr($path, strlen('/index.php'));
}
$path   = rtrim($path, '/');

// Only POST is meaningful for ingestion endpoints (for now).
if ($method !== 'POST') {
    fail(405, 'Method not allowed. Use POST.');
}

switch ($path) {

    /* --------------------------------------------------------
     * POST /cve-entry  -> tab_cve
     * Expected JSON:
     *   { "cve_id": "...", "exploit_id": 1, "ioc_id": 1,
     *     "platform": "linux_web", "cve_source": "..." }
     * date_added / date_modified default to today.
     * cve_source is optional; defaults to 'unprovided' in DB.
     * -------------------------------------------------------- */
    case '/cve-entry':
        $data = get_json_body();
        require_fields($data, ['cve_id', 'platform']);
        // exploit_id / ioc_id nullable since seed.sql gives them DEFAULT 0
        $exploit_id = isset($data['exploit_id']) ? (int) $data['exploit_id'] : 0;
        $ioc_id     = isset($data['ioc_id'])     ? (int) $data['ioc_id']     : 0;
        $cve_source = $data['cve_source'] ?? 'unprovided';

        $stmt = db()->prepare(
            'INSERT INTO tab_cve (cve_id, exploit_id, ioc_id, platform, cve_source)
        VALUES (:cve_id, :exploit_id, :ioc_id, :platform, :cve_source)
        RETURNING id, cve_id, exploit_id, ioc_id, platform, cve_source, date_added, date_modified'
        );
        try {
            $stmt->execute([
                ':cve_id'     => $data['cve_id'],
                ':exploit_id' => $exploit_id,
                ':ioc_id'     => $ioc_id,
                ':platform'   => $data['platform'],
                ':cve_source' => $cve_source,
            ]);
        } catch (PDOException $e) {
            if ($e->getCode() === '23505') { // unique_violation
                fail(409, 'Duplicate cve_id: ' . $data['cve_id']);
            }
            fail(500, 'Insert failed: ' . $e->getMessage());
        }

        json_response(201, ['ok' => true, 'created' => $stmt->fetch()]);
        break;

        /* --------------------------------------------------------
         * POST /exploit-entry  -> tab_exploit
         * Expected JSON:
         *   { "exploit_id": 1, "exploit_type": "...",
         *     "exploit_content": "...", "exploit_source": "..." }
         * exploit_source is optional; defaults to 'unprovided' in DB.
         * -------------------------------------------------------- */
        case '/exploit-entry':
            $data = get_json_body();
            require_fields($data, ['exploit_id', 'exploit_type', 'exploit_content']);
            $exploit_source = $data['exploit_source'] ?? 'unprovided';

            $stmt = db()->prepare(
                'INSERT INTO tab_exploit (exploit_id, exploit_type, exploit_content, exploit_source)
            VALUES (:exploit_id, :exploit_type, :exploit_content, :exploit_source)
            RETURNING id, exploit_id, exploit_type, exploit_source, date_added, date_modified'
            );
            try {
                $stmt->execute([
                    ':exploit_id'      => (int) $data['exploit_id'],
                               ':exploit_type'    => $data['exploit_type'],
                               ':exploit_content' => $data['exploit_content'],
                               ':exploit_source'  => $exploit_source,
                ]);
            } catch (PDOException $e) {
                if ($e->getCode() === '23505') {
                    fail(409, 'Duplicate exploit_id: ' . $data['exploit_id']);
                }
                fail(500, 'Insert failed: ' . $e->getMessage());
            }

            json_response(201, ['ok' => true, 'created' => $stmt->fetch()]);
            break;

            /* --------------------------------------------------------
             * POST /sample-entry  -> tab_sample
             * Expected JSON:
             *   { "platform": "linux_web", "title": "...",
             *     "sample_content": "...",
             *     "point_of_interest": { ... },   // optional
             *     "sample_source": "..." }        // optional, default 'unprovided'
             * -------------------------------------------------------- */
            case '/sample-entry':
                $data = get_json_body();
                require_fields($data, ['platform', 'title', 'sample_content']);
                $sample_source = $data['sample_source'] ?? 'unprovided';

                $poi = $data['point_of_interest'] ?? null;
                if ($poi !== null && !is_array($poi)) {
                    fail(422, 'point_of_interest must be a JSON object.');
                }

                $stmt = db()->prepare(
                    'INSERT INTO tab_sample (platform, title, point_of_interest, sample_content, sample_source)
                VALUES (:platform, :title, CAST(:poi AS JSONB), :sample_content, :sample_source)
                RETURNING id, platform, title, sample_source, date_added, date_modified'
                );
                try {
                    $stmt->execute([
                        ':platform'       => $data['platform'],
                        ':title'          => $data['title'],
                        ':poi'            => $poi === null ? null : json_encode($poi),
                        ':sample_content' => $data['sample_content'],
                        ':sample_source'  => $sample_source,
                    ]);
                } catch (PDOException $e) {
                    if ($e->getCode() === '22P02') { // invalid_jsonb / syntax error
                        fail(422, 'point_of_interest is not valid JSON.');
                    }
                    fail(500, 'Insert failed: ' . $e->getMessage());
                }

                json_response(201, ['ok' => true, 'created' => $stmt->fetch()]);
                break;

            default:
                fail(404, 'Unknown endpoint: ' . $path);
}
