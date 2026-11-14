<?php
/**
 * ThreatContext-app — API entrypoint
 *
 * Core CVE -> IoC pipeline + data-ingestion API.
 * Mounted from ./volume_threatcontext-app_php into /var/www/html
 * in the php:8.3-apache container (container port 80).
 *
 * Endpoints (path after the host):
 *   POST /cve-entry      -> INSERT INTO tab_cve (new row; a cve_id may
 *                           span several rows, one per linked IoC)
 *   POST /exploit-entry  -> INSERT INTO tab_exploit (new row; use
 *                           /exploit-update to change an existing one)
 *   POST /sample-entry   -> INSERT INTO tab_sample
 *   POST /ioc-entry      -> INSERT INTO tab_ioc (manual ingestion; use
 *                           /ioc-update to change an existing one)
 *   POST /cve-update     -> partial UPDATE of one tab_cve row by internal id
 *   POST /exploit-update -> partial UPDATE of one tab_exploit row by internal id
 *   POST /sample-update  -> partial UPDATE of one tab_sample row by internal id
 *   POST /ioc-update     -> partial UPDATE of one tab_ioc row by internal id
 *   POST /ioc-request    -> full pipeline (steps 1-7):
 *                           CVE -> exploit + samples -> RAG build
 *                           -> ThreatContext-llm -> tab_ioc rows + one
 *                           tab_cve row per cve_id/ioc_id couple
 *   GET  /cve-consult     -> consult tab_cve (all records, or all rows
 *                           of one cve_id)
 *   GET  /exploit-consult -> consult tab_exploit (all records, or one by exploit_id)
 *   GET  /sample-consult  -> consult tab_sample (all records, or all by platform)
 *   GET  /ioc-consult     -> consult tab_ioc (all records, or one by ioc_id)
 *   DELETE /cve-delete     -> delete a tab_cve record by cve_id
 *   DELETE /exploit-delete -> delete a tab_exploit record by exploit_id
 *   DELETE /sample-delete  -> delete a tab_sample record by internal id
 *   DELETE /ioc-delete     -> delete a tab_ioc record by ioc_id
 *
 * /ioc-request body: {"request": "CVE-2026-109618"}
 *   (GET /index.php/ioc-request?request=CVE-... also accepted for tests)
 *
 * Request body: JSON. Response: JSON.
 */

declare(strict_types=1);

/* ============================================================
 * Configuration — ThreatContext-db (via compose environment)
 * ============================================================ */
const DB_DSN_DEFAULT  = 'pgsql:host=database_tier;port=5432;dbname=threatcontext_db';
const DB_USER_DEFAULT = 'threatcontext-user';
const DB_PASS_DEFAULT = '';

/* ============================================================
 * Configuration — ThreatContext-llm (Ollama)
 * compose service name; model created by post_start from Modelfile
 * ============================================================ */
const LLM_BASE_DEFAULT  = 'http://llm_tier:11434';
const LLM_MODEL_DEFAULT = 'threatcontext-analyst';

/* Structured-output schema: the LLM is constrained at decoding time
 * to answer with this exact shape. Empty ioc_found == negative answer. */
const IOC_ANSWER_SCHEMA = [
    'type' => 'object',
'properties' => [
    'ioc_found' => [
        'type' => 'array',
'items' => [
    'type' => 'object',
'properties' => [
    'ioc_type'    => ['type' => 'string'],
'ioc_content' => ['type' => 'string'],
],
'required' => ['ioc_type', 'ioc_content'],
],
    ],
],
'required' => ['ioc_found'],
];

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
            $pdo = new PDO(
                getenv('DB_DSN')  ?: DB_DSN_DEFAULT,
                           getenv('DB_USER') ?: DB_USER_DEFAULT,
                           getenv('DB_PASS') ?: DB_PASS_DEFAULT,
                           [
                               PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                           PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                           PDO::ATTR_EMULATE_PREPARES   => false,
                           ]
            );
        } catch (PDOException $e) {
            fail(503, 'Database connection failed: ' . $e->getMessage());
        }
    }
    return $pdo;
}

/* Next free identifier for a table: value just after the last stored
 * one (MAX + 1, or 1 on an empty table). Used when an entry arrives
 * without an id, from either the presentation tier or a remote
 * application posting straight to this API. The table and column
 * names only ever come from hard-coded call sites. */
function next_id(string $table, string $column): int
{
    $stmt  = db()->query("SELECT COALESCE(MAX({$column}), 0) + 1 FROM {$table}");
    return (int) $stmt->fetchColumn();
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

/* Internal id of the row to update (?id=...), shared by the
 * four *-update endpoints. */
function update_id_param(): int
{
    $row_id = $_GET['id'] ?? '';
    if (!ctype_digit((string) $row_id)) {
        fail(422, 'Missing or invalid parameter: id');
    }
    return (int) $row_id;
}

/* Partial update helper for the *-update endpoints: builds
 * "SET col = :col, ..." from the body keys present in $allowed,
 * adds date_modified = CURRENT_DATE, runs
 * UPDATE ... WHERE id = :id RETURNING ... and returns the updated
 * row, or null when no row matches the internal id. */
function apply_partial_update(string $table, array $allowed, array $data, int $row_id, string $returning): ?array
{
    $sets   = [];
    $params = [':id' => $row_id];
    foreach ($allowed as $col) {
        if (!array_key_exists($col, $data)) {
            continue;                       // partial: absent = unchanged
        }
        if ($col === 'exploit_id' || $col === 'ioc_id') {
            if ($data[$col] !== null && $data[$col] !== ''
                && !ctype_digit((string) $data[$col])) {
                fail(422, $col . ' must be a positive integer.');
            }
            $params[':' . $col] = ($data[$col] === null || $data[$col] === '')
                ? 0 : (int) $data[$col];
        } elseif ($col === 'point_of_interest') {
            if ($data[$col] !== null && !is_array($data[$col])) {
                fail(422, 'point_of_interest must be a JSON object.');
            }
            $sets[] = 'point_of_interest = CAST(:point_of_interest AS JSONB)';
            $params[':point_of_interest'] = $data[$col] === null
                ? null : json_encode($data[$col]);
            continue;
        } else {
            if (!is_string($data[$col]) || $data[$col] === '') {
                fail(422, $col . ' must be a non-empty string.');
            }
            $params[':' . $col] = $data[$col];
        }
        $sets[] = $col . ' = :' . $col;
    }
    if ($sets === []) {
        fail(422, 'No updatable field in the request body.');
    }
    $sets[] = 'date_modified = CURRENT_DATE';
    $stmt = db()->prepare(
        'UPDATE ' . $table . ' SET ' . implode(', ', $sets) . '
      WHERE id = :id
  RETURNING ' . $returning
    );
    try {
        $stmt->execute($params);
    } catch (PDOException $e) {
        if ($e->getCode() === '22P02') { // invalid text representation (JSONB)
            fail(422, 'Invalid value for one of the fields.');
        }
        fail(500, 'Update failed: ' . $e->getMessage());
    }
    $row = $stmt->fetch();
    return $row === false ? null : $row;
}

/* Recursively collect every string value of a decoded JSON structure
 * into $out (used to flatten tab_sample.point_of_interest JSONB
 * into the array of strings the RAG request expects). */
function flatten_string_values(array $data, array &$out): void
{
    foreach ($data as $v) {
        if (is_string($v)) {
            $out[] = $v;
        } elseif (is_array($v)) {
            flatten_string_values($v, $out);
        }
    }
}

/* ============================================================
 * LLM call — send the prepared RAG request to ThreatContext-llm
 * and return the validated ioc_found array (empty = negative).
 * ============================================================ */
function llm_ioc_guess(array $rag_request): array
{
    $llmBase  = getenv('LLM_BASE')  ?: LLM_BASE_DEFAULT;
    $llmModel = getenv('LLM_MODEL') ?: LLM_MODEL_DEFAULT;

    $payload = [
        'model'    => $llmModel,
        'stream'   => false,
        'think'    => false,           // qwen3: skip reasoning block
        'format'   => IOC_ANSWER_SCHEMA, // decoding-time JSON constraint
        'messages' => [
            [
                'role'    => 'user',
                // json_encode guarantees quotes/backslashes in exploit
                // content and samples survive as a single JSON string.
                'content' => json_encode($rag_request, JSON_UNESCAPED_SLASHES),
            ],
        ],
    ];

    $ch = curl_init($llmBase . '/api/chat');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_SLASHES),
                      CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
                      CURLOPT_RETURNTRANSFER => true,
                      CURLOPT_TIMEOUT        => 300, // local model + long context
    ]);
    $raw  = curl_exec($ch);
    $err  = curl_errno($ch);
    $http = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($err !== 0 || $raw === false) {
        fail(502, 'LLM request failed (curl error ' . $err . '). Is llm_tier running?');
    }
    $resp = json_decode($raw, true);
    if ($http !== 200 || !is_array($resp) || !isset($resp['message']['content'])) {
        fail(502, 'LLM error response: ' . substr((string) $raw, 0, 500));
    }

    // Constrained decoding should guarantee JSON — validate anyway.
    $answer = json_decode($resp['message']['content'], true, 512);
    if (!is_array($answer) || !isset($answer['ioc_found']) || !is_array($answer['ioc_found'])) {
        fail(502, 'LLM returned a malformed answer.');
    }

    $valid = [];
    foreach ($answer['ioc_found'] as $ioc) {
        if (is_array($ioc)
            && is_string($ioc['ioc_type'] ?? null)
            && is_string($ioc['ioc_content'] ?? null)
            && $ioc['ioc_content'] !== '') {
            $valid[] = [
                'ioc_type'    => $ioc['ioc_type'],
                'ioc_content' => $ioc['ioc_content'],
            ];
            }
    }
    return $valid;
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
$path = rtrim($path, '/');

switch ($path) {

    /* --------------------------------------------------------
     * POST /cve-entry  -> tab_cve
     * Expected JSON:
     *   { "cve_id": "...", "exploit_id": 1, "ioc_id": 1,
     *     "platform": "linux_web", "cve_source": "..." }
     * cve_source is optional; defaults to 'unprovided' in DB.
     * Every submission inserts a new row: a cve_id may span several
     * tab_cve rows (one per linked IoC, created by /ioc-request).
     * -------------------------------------------------------- */
    case '/cve-entry':
        if ($method !== 'POST') { fail(405, 'Use POST.'); }
        $data = get_json_body();
        require_fields($data, ['cve_id', 'platform']);
        // exploit_id / ioc_id nullable since seed.sql gives them DEFAULT 0
        $exploit_id = isset($data['exploit_id']) ? (int) $data['exploit_id'] : 0;
        $ioc_id     = isset($data['ioc_id'])     ? (int) $data['ioc_id']     : 0;
        $cve_source = $data['cve_source'] ?? 'unprovided';

        $insert = db()->prepare(
            'INSERT INTO tab_cve (cve_id, exploit_id, ioc_id, platform, cve_source)
        VALUES (:cve_id, :exploit_id, :ioc_id, :platform, :cve_source)
        RETURNING id, cve_id, exploit_id, ioc_id, platform, cve_source, date_added, date_modified'
        );
        $params = [
            ':cve_id'     => $data['cve_id'],
            ':exploit_id' => $exploit_id,
            ':ioc_id'     => $ioc_id,
            ':platform'   => $data['platform'],
            ':cve_source' => $cve_source,
        ];
        try {
            $insert->execute($params);
            json_response(201, ['ok' => true, 'created' => $insert->fetch()]);
        } catch (PDOException $e) {
            fail(500, 'Insert failed: ' . $e->getMessage());
        }
        break;

        /* --------------------------------------------------------
         * POST /exploit-entry  -> tab_exploit
         * Expected JSON:
         *   { "exploit_type": "...", "exploit_content": "...",
         *     "exploit_source": "..." }
         * exploit_id is optional: when absent, empty or null the next
         * free value (last stored + 1) is attributed automatically.
         * exploit_source is optional; defaults to 'unprovided' in DB.
         * Every submission inserts a new row; /exploit-update changes
         * an existing one (partial update by internal id).
         * -------------------------------------------------------- */
        case '/exploit-entry':
            if ($method !== 'POST') { fail(405, 'Use POST.'); }
            $data = get_json_body();
            require_fields($data, ['exploit_type', 'exploit_content']);
            // No exploit_id given: attribute the next free value.
            $exploit_id = (isset($data['exploit_id']) && $data['exploit_id'] !== '' && $data['exploit_id'] !== null)
                ? (int) $data['exploit_id']
                : next_id('tab_exploit', 'exploit_id');
            $exploit_source = $data['exploit_source'] ?? 'unprovided';

            $insert = db()->prepare(
                'INSERT INTO tab_exploit (exploit_id, exploit_type, exploit_content, exploit_source)
            VALUES (:exploit_id, :exploit_type, :exploit_content, :exploit_source)
            RETURNING id, exploit_id, exploit_type, exploit_source, date_added, date_modified'
            );
            $params = [
                ':exploit_id'      => $exploit_id,
                ':exploit_type'    => $data['exploit_type'],
                ':exploit_content' => $data['exploit_content'],
                ':exploit_source'  => $exploit_source,
            ];
            try {
                $insert->execute($params);
                json_response(201, ['ok' => true, 'created' => $insert->fetch()]);
            } catch (PDOException $e) {
                fail(500, 'Insert failed: ' . $e->getMessage());
            }
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
                if ($method !== 'POST') { fail(405, 'Use POST.'); }
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

                /* ========================================================
                 * POST /ioc-request — core CVE -> IoC pipeline
                 *
                 * Input:  {"request": "CVE-2026-109618"}
                 * Steps:
                 *   1. CVE registered in tab_cve?          -> else 404
                 *   2. Exploit linked in tab_exploit?      -> else 422
                 *   3. Samples for CVE platform in tab_sample? (may be empty)
                 *   4. RAG preparation (structured request)
                 *   5. Send to ThreatContext-llm (Ollama /api/chat)
                 *   6. Positive -> one tab_ioc row per IoC + one tab_cve row
                 *      per cve_id/ioc_id couple; Negative -> inform
                 *   7. Close connection (JSON response, exit)
                 * ======================================================== */
                case '/ioc-request':
                    // Input: POST body {"request": "..."} or GET ?request=...
                    if ($method === 'POST') {
                        $data   = get_json_body();
                        $cve_id = $data['request'] ?? '';
                    } elseif ($method === 'GET') {
                        $cve_id = $_GET['request'] ?? '';
                    } else {
                        fail(405, 'Use POST (or GET with ?request=).');
                    }
                    if ($cve_id === '' || !is_string($cve_id)) {
                        fail(422, 'Missing required field(s): request');
                    }

                    // ---- Step 1: is the CVE registered in tab_cve? ----
                    $stmt = db()->prepare('SELECT * FROM tab_cve WHERE cve_id = :cve_id');
                    $stmt->execute([':cve_id' => $cve_id]);
                    $cve = $stmt->fetch();
                    if ($cve === false) {
                        fail(404, 'Unknown CVE: ' . $cve_id);
                    }

                    // ---- Step 2: is an exploit linked via tab_exploit? ----
                    $stmt = db()->prepare(
                        'SELECT exploit_type, exploit_content
                        FROM tab_exploit
                        WHERE exploit_id = :exploit_id'
                    );
                    $stmt->execute([':exploit_id' => $cve['exploit_id']]);
                    $exploit = $stmt->fetch();
                    if ($exploit === false) {
                        fail(422, 'No exploit linked to ' . $cve_id . ' (exploit_id ' . $cve['exploit_id'] . ' not found in tab_exploit).');
                    }

                    // ---- Step 3: sample logs for the CVE's platform ----
                    // (absence of samples is allowed; sample array stays empty)
                    $stmt = db()->prepare(
                        'SELECT title, sample_content, point_of_interest
                        FROM tab_sample
                        WHERE platform = :platform
                        ORDER BY date_added DESC'
                    );
                    $stmt->execute([':platform' => $cve['platform']]);
                    $samples = $stmt->fetchAll();

                    // ---- Step 4: RAG preparation ----
                    // point_of_interest: flatten every string value of each
                    // sample's JSONB into one deduplicated array of strings.
                    $poi_strings  = [];
                    $sample_blobs = [];
                    foreach ($samples as $s) {
                        $sample_blobs[] = $s['sample_content'];
                        if ($s['point_of_interest'] !== null) {
                            $poi = json_decode((string) $s['point_of_interest'], true);
                            if (is_array($poi)) {
                                flatten_string_values($poi, $poi_strings);
                            }
                        }
                    }
                    $poi_strings = array_values(array_unique($poi_strings));

                    $rag_request = [
                        'request_type'     => 'ioc_guess',
                        'exploit_type'     => $exploit['exploit_type'],
                        'exploit_content'  => $exploit['exploit_content'],
                        'point_of_interest' => $poi_strings,
                        'sample'           => $sample_blobs,
                    ];

                    // ---- Steps 5 + 6: send to ThreatContext-llm, retrieve answer ----
                    $ioc_found = llm_ioc_guess($rag_request);

                    // ---- Step 6b: negative answer -> inform the user, store nothing ----
                    if (empty($ioc_found)) {
                        json_response(200, [
                            'ioc_found' => [],
                            'message'   => 'No IoC were found for ' . $cve_id,
                        ]);
                    }

                    // ---- Step 6c: positive answer -> store IoCs + CVE rows ----
                    // One tab_ioc row per IoC found by the LLM, each with
                    // its own ioc_id (next free value per row); ioc_type
                    // and ioc_content are plain tab_ioc columns. The CVE
                    // side is then rewritten in tab_cve: every previous
                    // row for this cve_id is replaced by one row per
                    // cve_id/ioc_id couple, carrying over the original
                    // exploit_id, platform, cve_source and date_added.
                    // Re-running the request replaces the previous set.
                    try {
                        db()->beginTransaction();

                        $ins = db()->prepare(
                            'INSERT INTO tab_ioc (ioc_id, ioc_type, ioc_content)
                        VALUES (:ioc_id, :ioc_type, :ioc_content)'
                        );
                        $ioc_ids = [];
                        foreach ($ioc_found as $ioc) {
                            $ioc_id = next_id('tab_ioc', 'ioc_id');
                            $ioc_ids[] = $ioc_id;
                            $ins->execute([
                                ':ioc_id'      => $ioc_id,
                                ':ioc_type'    => $ioc['ioc_type']    ?? 'unprovided',
                                ':ioc_content' => $ioc['ioc_content'] ?? '',
                            ]);
                        }

                        // Rewrite the CVE side: one row per couple.
                        db()->prepare('DELETE FROM tab_cve WHERE cve_id = :cve_id')
                            ->execute([':cve_id' => $cve_id]);
                        $ins_cve = db()->prepare(
                            'INSERT INTO tab_cve (cve_id, exploit_id, ioc_id, platform, cve_source, date_added)
                        VALUES (:cve_id, :exploit_id, :ioc_id, :platform, :cve_source, :date_added)'
                        );
                        foreach ($ioc_ids as $ioc_id) {
                            $ins_cve->execute([
                                ':cve_id'     => $cve_id,
                                ':exploit_id' => $cve['exploit_id'],
                                ':ioc_id'     => $ioc_id,
                                ':platform'   => $cve['platform'],
                                ':cve_source' => $cve['cve_source'],
                                ':date_added' => $cve['date_added'],
                            ]);
                        }

                        db()->commit();
                    } catch (PDOException $e) {
                        db()->rollBack();
                        fail(500, 'Failed to store IoCs: ' . $e->getMessage());
                    }

                    // ---- Step 7: close the connection with the user ----
                    json_response(200, [
                        'ioc_found' => $ioc_found,
                        'cve_id'    => $cve_id,
                        'ioc_id'    => $ioc_ids[0],   // first attributed id
                        'ioc_ids'   => $ioc_ids,      // every attributed id
                        'cve_rows'  => count($ioc_ids), // tab_cve rows written
                    ]);
                    break;

                /* ========================================================
                 * POST /ioc-entry — manual IoC ingestion -> tab_ioc
                 * Expected JSON:
                 *   { "ioc_type": "ip", "ioc_content": "6.6.6.6" }
                 * ioc_id is optional: when absent, empty or null the next
                 * free value (last stored + 1) is attributed automatically,
                 * exactly like the /ioc-request pipeline does.
                 * Every submission inserts a new row; /ioc-update changes
                 * an existing one (partial update by internal id).
                 * ioc_type and ioc_content are stored as plain tab_ioc
                 * columns, no JSON encoding involved.
                 * ======================================================== */
                case '/ioc-entry':
                    if ($method !== 'POST') { fail(405, 'Use POST.'); }
                    $data = get_json_body();
                    require_fields($data, ['ioc_type', 'ioc_content']);
                    // No ioc_id given: attribute the next free value.
                    $ioc_id = (isset($data['ioc_id']) && $data['ioc_id'] !== '' && $data['ioc_id'] !== null)
                        ? (int) $data['ioc_id']
                        : next_id('tab_ioc', 'ioc_id');

                    $insert = db()->prepare(
                        'INSERT INTO tab_ioc (ioc_id, ioc_type, ioc_content)
                     VALUES (:ioc_id, :ioc_type, :ioc_content)
                     RETURNING id, ioc_id, ioc_type, ioc_content, date_added, date_modified'
                    );
                    $params = [
                        ':ioc_id'      => $ioc_id,
                        ':ioc_type'    => $data['ioc_type'],
                        ':ioc_content' => $data['ioc_content'],
                    ];
                    try {
                        $insert->execute($params);
                        json_response(201, ['ok' => true, 'created' => $insert->fetch()]);
                    } catch (PDOException $e) {
                        fail(500, 'Insert failed: ' . $e->getMessage());
                    }
                    break;

                /* ========================================================
                 * POST /cve-update — partial update of one tab_cve row
                 * Query: ?id=42 (internal id, shown on the consult page)
                 * Body: only the columns to change, e.g.
                 *   { "platform": "linux_web", "cve_source": "nvd" }
                 * The internal id and the dates are not writable here.
                 * ======================================================== */
                case '/cve-update':
                    if ($method !== 'POST') { fail(405, 'Use POST.'); }
                    $row_id = update_id_param();
                    $data   = get_json_body();
                    $row = apply_partial_update('tab_cve',
                        ['cve_id', 'exploit_id', 'ioc_id', 'platform', 'cve_source'],
                        $data, $row_id,
                        'id, cve_id, exploit_id, ioc_id, platform, cve_source, date_added, date_modified');
                    if ($row === null) { fail(404, 'Unknown cve id: ' . $row_id); }
                    json_response(200, ['ok' => true, 'updated' => $row]);
                    break;

                /* ========================================================
                 * POST /exploit-update — partial update of one tab_exploit row
                 * Query: ?id=42 (internal id, shown on the consult page)
                 * Body: only the columns to change.
                 * ======================================================== */
                case '/exploit-update':
                    if ($method !== 'POST') { fail(405, 'Use POST.'); }
                    $row_id = update_id_param();
                    $data   = get_json_body();
                    $row = apply_partial_update('tab_exploit',
                        ['exploit_id', 'exploit_type', 'exploit_content', 'exploit_source'],
                        $data, $row_id,
                        'id, exploit_id, exploit_type, exploit_source, date_added, date_modified');
                    if ($row === null) { fail(404, 'Unknown exploit id: ' . $row_id); }
                    json_response(200, ['ok' => true, 'updated' => $row]);
                    break;

                /* ========================================================
                 * POST /sample-update — partial update of one tab_sample row
                 * Query: ?id=42 (internal id, shown on the consult page)
                 * Body: only the columns to change; point_of_interest must
                 * be a JSON object (or null to clear it).
                 * ======================================================== */
                case '/sample-update':
                    if ($method !== 'POST') { fail(405, 'Use POST.'); }
                    $row_id = update_id_param();
                    $data   = get_json_body();
                    $row = apply_partial_update('tab_sample',
                        ['platform', 'title', 'point_of_interest', 'sample_content', 'sample_source'],
                        $data, $row_id,
                        'id, platform, title, sample_source, date_added, date_modified');
                    if ($row === null) { fail(404, 'Unknown sample id: ' . $row_id); }
                    json_response(200, ['ok' => true, 'updated' => $row]);
                    break;

                /* ========================================================
                 * POST /ioc-update — partial update of one tab_ioc row
                 * Query: ?id=42 (internal id, shown on the consult page)
                 * Body: only the columns to change.
                 * ======================================================== */
                case '/ioc-update':
                    if ($method !== 'POST') { fail(405, 'Use POST.'); }
                    $row_id = update_id_param();
                    $data   = get_json_body();
                    $row = apply_partial_update('tab_ioc',
                        ['ioc_id', 'ioc_type', 'ioc_content'],
                        $data, $row_id,
                        'id, ioc_id, ioc_type, ioc_content, date_added, date_modified');
                    if ($row === null) { fail(404, 'Unknown ioc id: ' . $row_id); }
                    json_response(200, ['ok' => true, 'updated' => $row]);
                    break;

                /* ========================================================
                 * GET /cve-consult — consult tab_cve
                 * Without query: every registered CVE row.
                 * With ?cve_id=CVE-2026-109618: every row of that cve_id
                 * (a cve_id may span several rows, one per linked IoC).
                 * ======================================================== */
                case '/cve-consult':
                    if ($method !== 'GET') { fail(405, 'Use GET.'); }
                    $cve_id = $_GET['cve_id'] ?? '';
                    if ($cve_id === '') {
                        // No filter given: return every registered CVE.
                        $rows = db()->query(
                            'SELECT id, cve_id, exploit_id, ioc_id, platform, cve_source,
                                    date_added, date_modified
                             FROM tab_cve
                             ORDER BY cve_id'
                        )->fetchAll();
                        json_response(200, ['ok' => true, 'cve' => $rows]);
                    }
                    $stmt = db()->prepare(
                        'SELECT id, cve_id, exploit_id, ioc_id, platform, cve_source,
                                date_added, date_modified
                         FROM tab_cve
                         WHERE cve_id = :cve_id'
                    );
                    $stmt->execute([':cve_id' => $cve_id]);
                    $rows = $stmt->fetchAll();
                    if (count($rows) === 0) {
                        fail(404, 'Unknown CVE: ' . $cve_id);
                    }
                    // Filtered lookup returns an array: a cve_id may
                    // span several rows (one per linked IoC).
                    json_response(200, ['ok' => true, 'cve' => $rows]);
                    break;

                /* ========================================================
                 * GET /exploit-consult — consult tab_exploit
                 * Without query: every registered exploit. The listing
                 * omits exploit_content to keep the payloads light on
                 * both the application and presentation tiers.
                 * With ?exploit_id=317: only that record (full content).
                 * ======================================================== */
                case '/exploit-consult':
                    if ($method !== 'GET') { fail(405, 'Use GET.'); }
                    $exploit_id = $_GET['exploit_id'] ?? '';
                    if ($exploit_id === '') {
                        // No filter given: every registered exploit,
                        // without exploit_content (light listing).
                        $rows = db()->query(
                            'SELECT id, exploit_id, exploit_type, exploit_source,
                                    date_added, date_modified
                             FROM tab_exploit
                             ORDER BY exploit_id'
                        )->fetchAll();
                        json_response(200, ['ok' => true, 'exploit' => $rows]);
                    }
                    if (!ctype_digit((string) $exploit_id)) {
                        fail(422, 'Missing or invalid parameter: exploit_id');
                    }
                    $stmt = db()->prepare(
                        'SELECT id, exploit_id, exploit_type, exploit_content, exploit_source,
                                date_added, date_modified
                         FROM tab_exploit
                         WHERE exploit_id = :exploit_id'
                    );
                    $stmt->execute([':exploit_id' => (int) $exploit_id]);
                    $exploit = $stmt->fetch();
                    if ($exploit === false) {
                        fail(404, 'Unknown exploit_id: ' . $exploit_id);
                    }
                    json_response(200, ['ok' => true, 'exploit' => $exploit]);
                    break;

                /* ========================================================
                 * GET /sample-consult — consult tab_sample
                 * Without query: every registered sample.
                 * With ?platform=linux_x86-64: only that platform's
                 * samples (may be an empty list).
                 * ======================================================== */
                case '/sample-consult':
                    if ($method !== 'GET') { fail(405, 'Use GET.'); }
                    $platform = $_GET['platform'] ?? '';
                    if ($platform === '') {
                        // No filter given: every registered sample.
                        $samples = db()->query(
                            'SELECT id, platform, title, point_of_interest, sample_content,
                                    sample_source, date_added, date_modified
                             FROM tab_sample
                             ORDER BY platform, date_added DESC'
                        )->fetchAll();
                    } else {
                        $stmt = db()->prepare(
                            'SELECT id, platform, title, point_of_interest, sample_content,
                                    sample_source, date_added, date_modified
                             FROM tab_sample
                             WHERE platform = :platform
                             ORDER BY date_added DESC'
                        );
                        $stmt->execute([':platform' => $platform]);
                        $samples = $stmt->fetchAll();
                    }
                    // Decode the JSONB column so the presentation tier
                    // receives a JSON object, not a string.
                    foreach ($samples as &$s) {
                        $s['point_of_interest'] = $s['point_of_interest'] !== null
                            ? json_decode((string) $s['point_of_interest'], true)
                            : null;
                    }
                    unset($s);
                    json_response(200, ['ok' => true, 'samples' => $samples]);
                    break;

                /* ========================================================
                 * GET /ioc-consult — consult tab_ioc
                 * Without query: every stored IoC.
                 * With ?ioc_id=1: only that record.
                 * ioc_type and ioc_content are plain tab_ioc columns, so
                 * rows are returned exactly as stored, no decoding.
                 * ======================================================== */
                case '/ioc-consult':
                    if ($method !== 'GET') { fail(405, 'Use GET.'); }
                    $ioc_id = $_GET['ioc_id'] ?? '';
                    if ($ioc_id === '') {
                        // No filter given: every stored IoC.
                        $iocs = db()->query(
                            'SELECT id, ioc_id, ioc_type, ioc_content, date_added, date_modified
                             FROM tab_ioc
                             ORDER BY ioc_id'
                        )->fetchAll();
                    } else {
                        if (!ctype_digit((string) $ioc_id)) {
                            fail(422, 'Missing or invalid parameter: ioc_id');
                        }
                        $stmt = db()->prepare(
                            'SELECT id, ioc_id, ioc_type, ioc_content, date_added, date_modified
                             FROM tab_ioc
                             WHERE ioc_id = :ioc_id'
                        );
                        $stmt->execute([':ioc_id' => (int) $ioc_id]);
                        $iocs = $stmt->fetchAll();
                        if (count($iocs) === 0) {
                            fail(404, 'Unknown ioc_id: ' . $ioc_id);
                        }
                    }
                    // A filtered lookup keeps the historic single-record
                    // shape; the full listing returns an array.
                    json_response(200, ['ok' => true, 'ioc' => ($ioc_id === '' ? $iocs : $iocs[0])]);
                    break;

                /* ========================================================
                 * DELETE /cve-delete — remove every tab_cve row of a cve_id
                 * Query: ?cve_id=CVE-2026-109618
                 * Deletes all rows of that cve_id (one per linked IoC);
                 * any linked tab_exploit / tab_ioc records are untouched.
                 * ======================================================== */
                case '/cve-delete':
                    if ($method !== 'DELETE') { fail(405, 'Use DELETE.'); }
                    $cve_id = $_GET['cve_id'] ?? '';
                    if ($cve_id === '') { fail(422, 'Missing required parameter: cve_id'); }
                    $stmt = db()->prepare(
                        'SELECT id, cve_id, exploit_id, ioc_id, platform, cve_source,
                                date_added, date_modified
                         FROM tab_cve
                         WHERE cve_id = :cve_id'
                    );
                    $stmt->execute([':cve_id' => $cve_id]);
                    $rows = $stmt->fetchAll();
                    if (count($rows) === 0) { fail(404, 'Unknown CVE: ' . $cve_id); }
                    db()->prepare('DELETE FROM tab_cve WHERE cve_id = :cve_id')
                        ->execute([':cve_id' => $cve_id]);
                    json_response(200, ['ok' => true, 'deleted' => $rows]);
                    break;

                /* ========================================================
                 * DELETE /exploit-delete — remove one tab_exploit record
                 * Query: ?exploit_id=317
                 * Deletes only the tab_exploit row; CVE rows pointing to
                 * it keep their stored exploit_id value.
                 * ======================================================== */
                case '/exploit-delete':
                    if ($method !== 'DELETE') { fail(405, 'Use DELETE.'); }
                    $exploit_id = $_GET['exploit_id'] ?? '';
                    if (!ctype_digit((string) $exploit_id)) {
                        fail(422, 'Missing or invalid parameter: exploit_id');
                    }
                    $stmt = db()->prepare(
                        'SELECT id, exploit_id, exploit_type, exploit_content, exploit_source,
                                date_added, date_modified
                         FROM tab_exploit
                         WHERE exploit_id = :exploit_id'
                    );
                    $stmt->execute([':exploit_id' => (int) $exploit_id]);
                    $row = $stmt->fetch();
                    if ($row === false) { fail(404, 'Unknown exploit_id: ' . $exploit_id); }
                    db()->prepare('DELETE FROM tab_exploit WHERE exploit_id = :exploit_id')
                        ->execute([':exploit_id' => (int) $exploit_id]);
                    json_response(200, ['ok' => true, 'deleted' => $row]);
                    break;

                /* ========================================================
                 * DELETE /sample-delete — remove one tab_sample record
                 * Query: ?id=42 (internal id, shown on the consult page)
                 * tab_sample has no business identifier, so the internal
                 * id is the delete key.
                 * ======================================================== */
                case '/sample-delete':
                    if ($method !== 'DELETE') { fail(405, 'Use DELETE.'); }
                    $sample_id = $_GET['id'] ?? '';
                    if (!ctype_digit((string) $sample_id)) {
                        fail(422, 'Missing or invalid parameter: id');
                    }
                    $stmt = db()->prepare(
                        'SELECT id, platform, title, point_of_interest, sample_content,
                                sample_source, date_added, date_modified
                         FROM tab_sample
                         WHERE id = :id'
                    );
                    $stmt->execute([':id' => (int) $sample_id]);
                    $row = $stmt->fetch();
                    if ($row === false) { fail(404, 'Unknown sample id: ' . $sample_id); }
                    db()->prepare('DELETE FROM tab_sample WHERE id = :id')
                        ->execute([':id' => (int) $sample_id]);
                    json_response(200, ['ok' => true, 'deleted' => $row]);
                    break;

                /* ========================================================
                 * DELETE /ioc-delete — remove one tab_ioc record
                 * Query: ?ioc_id=1
                 * Deletes only the tab_ioc row; CVE rows pointing to it
                 * keep their stored ioc_id value.
                 * ======================================================== */
                case '/ioc-delete':
                    if ($method !== 'DELETE') { fail(405, 'Use DELETE.'); }
                    $ioc_id = $_GET['ioc_id'] ?? '';
                    if (!ctype_digit((string) $ioc_id)) {
                        fail(422, 'Missing or invalid parameter: ioc_id');
                    }
                    $stmt = db()->prepare(
                        'SELECT id, ioc_id, ioc_type, ioc_content, date_added, date_modified
                         FROM tab_ioc
                         WHERE ioc_id = :ioc_id'
                    );
                    $stmt->execute([':ioc_id' => (int) $ioc_id]);
                    $row = $stmt->fetch();
                    if ($row === false) { fail(404, 'Unknown ioc_id: ' . $ioc_id); }
                    db()->prepare('DELETE FROM tab_ioc WHERE ioc_id = :ioc_id')
                        ->execute([':ioc_id' => (int) $ioc_id]);
                    json_response(200, ['ok' => true, 'deleted' => $row]);
                    break;

                    default:
                        fail(404, 'Unknown endpoint: ' . $path);
}
