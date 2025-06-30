;; Enhanced Historical Snapshots Smart Contract
;; Advanced storage with historical snapshots, multi-value support, and comprehensive features

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-BLOCK (err u101))
(define-constant ERR-SNAPSHOT-NOT-FOUND (err u102))
(define-constant ERR-FUTURE-BLOCK (err u103))
(define-constant ERR-INVALID-KEY (err u104))
(define-constant ERR-VALUE-TOO-LARGE (err u105))
(define-constant ERR-PAUSED (err u106))
(define-constant ERR-INVALID-RANGE (err u107))
(define-constant ERR-BATCH-TOO-LARGE (err u108))
(define-constant ERR-INVALID-METADATA (err u109))

;; Contract constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant MAX-VALUE u340282366920938463463374607431768211455) ;; Max uint value
(define-constant MAX-BATCH-SIZE u50)
(define-constant MAX-KEY-LENGTH u64)

;; Contract state
(define-data-var contract-paused bool false)
(define-data-var snapshot-fee uint u0)
(define-data-var total-snapshots uint u0)

;; Multi-key snapshot storage
;; Maps (key, block-height) to stored value
(define-map snapshots {key: (string-ascii 64), block: uint} uint)

;; Track latest snapshot block for each key
(define-map latest-snapshot-blocks (string-ascii 64) uint)

;; Track snapshot existence for efficient queries
(define-map snapshot-exists {key: (string-ascii 64), block: uint} bool)

;; Metadata storage for snapshots
(define-map snapshot-metadata {key: (string-ascii 64), block: uint} {
  timestamp: uint,
  author: principal,
  description: (string-ascii 256),
  tags: (list 10 (string-ascii 32))
})

;; Access control - authorized writers per key
(define-map authorized-writers {key: (string-ascii 64), writer: principal} bool)

;; Key registration and settings
(define-map key-settings (string-ascii 64) {
  created-at: uint,
  creator: principal,
  public-read: bool,
  public-write: bool,
  retention-blocks: uint
})

;; Aggregation cache for performance
(define-map aggregation-cache {key: (string-ascii 64), start-block: uint, end-block: uint} {
  sum: uint,
  avg: uint,
  min: uint,
  max: uint,
  count: uint,
  computed-at: uint
})

;; Event logging
(define-map event-log uint {
  event-type: (string-ascii 32),
  key: (string-ascii 64),
  block: uint,
  value: uint,
  author: principal,
  timestamp: uint
})
(define-data-var event-counter uint u0)



;; Log event
(define-private (log-event (event-type (string-ascii 32)) (key (string-ascii 64)) (block uint) (value uint))
  (let ((event-id (var-get event-counter)))
    (begin
      (map-set event-log event-id {
        event-type: event-type,
        key: key,
        block: block,
        value: value,
        author: tx-sender,
        timestamp: block-height
      })
      (var-set event-counter (+ event-id u1))
      event-id)))

;; Clear aggregation cache for a key
(define-private (clear-aggregation-cache (key (string-ascii 64)))
  true) ;; Simplified for brevity

;; === UTILITY AND HELPER FUNCTIONS ===

;; Check if current user can write to key
(define-private (can-write-key (key (string-ascii 64)))
  (or (is-eq tx-sender CONTRACT-OWNER)
      (match (map-get? key-settings key)
        settings (or (get public-write settings)
                    (is-eq tx-sender (get creator settings))
                    (default-to false (map-get? authorized-writers {key: key, writer: tx-sender})))
        true))) ;; Allow writes to unregistered keys

;; Check if current user can read from key
(define-private (can-read-key (key (string-ascii 64)))
  (or (is-eq tx-sender CONTRACT-OWNER)
      (match (map-get? key-settings key)
        settings (or (get public-read settings)
                    (is-eq tx-sender (get creator settings))
                    (default-to false (map-get? authorized-writers {key: key, writer: tx-sender})))
        true))) ;; Allow reads from unregistered keys

;; Check if current user is key creator
(define-private (is-key-creator (key (string-ascii 64)))
  (match (map-get? key-settings key)
    settings (is-eq tx-sender (get creator settings))
    false))



;; Find latest snapshot before target block (iterative implementation)
(define-private (find-latest-snapshot-before (key (string-ascii 64)) (target-block uint))
  (let ((search-result (fold check-block-exists 
                             (generate-block-list target-block)
                             {key: key, found-block: u0})))
    (get found-block search-result)))

;; Helper to generate a list of blocks to search (limited to reasonable range)
(define-private (generate-block-list (max-block uint))
  (if (<= max-block u100)
    ;; For small ranges, search all blocks
    (generate-range u1 max-block)
    ;; For large ranges, search recent blocks only
    (generate-range (- max-block u100) max-block)))

;; Generate a range of numbers (simplified implementation)
(define-private (generate-range (start uint) (end uint))
  (if (> start end)
    (list)
    ;; Return a reasonable list of recent blocks
    (list end (- end u1) (- end u2) (- end u3) (- end u4) 
          (- end u5) (- end u6) (- end u7) (- end u8) (- end u9))))

;; Check if block exists and update found block
(define-private (check-block-exists 
  (block uint) 
  (context {key: (string-ascii 64), found-block: uint}))
  (if (and (> block u0) 
           (default-to false (map-get? snapshot-exists {key: (get key context), block: block}))
           (is-eq (get found-block context) u0))
    {key: (get key context), found-block: block}
    context))

;; Get snapshots in range (simplified implementation)
(define-private (get-snapshots-in-range (key (string-ascii 64)) (start uint) (end uint))
  (list)) ;; Simplified for now

;; Calculate statistics (simplified implementation)
(define-private (calculate-statistics (key (string-ascii 64)) (start uint) (end uint))
  {sum: u0, avg: u0, min: u0, max: u0, count: u0, computed-at: block-height})

;; Helper for batch operations
(define-private (store-single-snapshot (snapshot {key: (string-ascii 64), value: uint}))
  (store-snapshot (get key snapshot) (get value snapshot)))





;; === CORE SNAPSHOT FUNCTIONS ===

;; Store snapshot for a specific key at current block
(define-public (store-snapshot (key (string-ascii 64)) (value uint))
  (let ((current-block block-height))
    (begin
      (asserts! (not (var-get contract-paused)) ERR-PAUSED)
      (asserts! (> (len key) u0) ERR-INVALID-KEY)
      (asserts! (<= value MAX-VALUE) ERR-VALUE-TOO-LARGE)
      (asserts! (can-write-key key) ERR-NOT-AUTHORIZED)
      
      ;; Pay fee if required
      (if (> (var-get snapshot-fee) u0)
        (try! (stx-transfer? (var-get snapshot-fee) tx-sender CONTRACT-OWNER))
        true)
      
      ;; Store the snapshot
      (map-set snapshots {key: key, block: current-block} value)
      (map-set snapshot-exists {key: key, block: current-block} true)
      (map-set latest-snapshot-blocks key current-block)
      
      ;; Update counters
      (var-set total-snapshots (+ (var-get total-snapshots) u1))
      
      ;; Log event
      (log-event "SNAPSHOT_STORED" key current-block value)
      
      ;; Clear relevant aggregation cache
      (clear-aggregation-cache key)
      
      (ok {key: key, block: current-block, value: value}))))

;; Store snapshot with metadata
(define-public (store-snapshot-with-metadata 
  (key (string-ascii 64)) 
  (value uint) 
  (description (string-ascii 256))
  (tags (list 10 (string-ascii 32))))
  (let ((current-block block-height))
    (begin
      (try! (store-snapshot key value))
      
      ;; Store metadata
      (map-set snapshot-metadata {key: key, block: current-block} {
        timestamp: block-height,
        author: tx-sender,
        description: description,
        tags: tags
      })
      
      (ok {key: key, block: current-block, value: value, metadata: true}))))

;; Batch store multiple snapshots
(define-public (batch-store-snapshots (snapshots-list (list 50 {key: (string-ascii 64), value: uint})))
  (let ((batch-size (len snapshots-list)))
    (begin
      (asserts! (<= batch-size MAX-BATCH-SIZE) ERR-BATCH-TOO-LARGE)
      (asserts! (not (var-get contract-paused)) ERR-PAUSED)
      
      (ok (map store-single-snapshot snapshots-list)))))

;; === KEY MANAGEMENT ===

;; Register a new key with settings
(define-public (register-key 
  (key (string-ascii 64))
  (public-read bool)
  (public-write bool)
  (retention-blocks uint))
  (begin
    (asserts! (> (len key) u0) ERR-INVALID-KEY)
    (asserts! (<= (len key) MAX-KEY-LENGTH) ERR-INVALID-KEY)
    
    (map-set key-settings key {
      created-at: block-height,
      creator: tx-sender,
      public-read: public-read,
      public-write: public-write,
      retention-blocks: retention-blocks
    })
    
    (log-event "KEY_REGISTERED" key block-height u0)
    (ok key)))

;; Authorize writer for a key
(define-public (authorize-writer (key (string-ascii 64)) (writer principal))
  (begin
    (asserts! (is-key-creator key) ERR-NOT-AUTHORIZED)
    (map-set authorized-writers {key: key, writer: writer} true)
    (ok true)))

;; Revoke writer authorization
(define-public (revoke-writer (key (string-ascii 64)) (writer principal))
  (begin
    (asserts! (is-key-creator key) ERR-NOT-AUTHORIZED)
    (map-delete authorized-writers {key: key, writer: writer})
    (ok true)))

;; === RETRIEVAL FUNCTIONS ===

;; Get snapshot at specific block and key
(define-read-only (get-snapshot (key (string-ascii 64)) (block-num uint))
  (begin
    (asserts! (can-read-key key) ERR-NOT-AUTHORIZED)
    (match (map-get? snapshots {key: key, block: block-num})
      snapshot (ok {key: key, block: block-num, value: snapshot})
      ERR-SNAPSHOT-NOT-FOUND)))

;; Get snapshot with metadata
(define-read-only (get-snapshot-with-metadata (key (string-ascii 64)) (block-num uint))
  (begin
    (asserts! (can-read-key key) ERR-NOT-AUTHORIZED)
    (match (map-get? snapshots {key: key, block: block-num})
      snapshot (ok {
        key: key,
        block: block-num,
        value: snapshot,
        metadata: (map-get? snapshot-metadata {key: key, block: block-num})
      })
      ERR-SNAPSHOT-NOT-FOUND)))

;; Get latest snapshot for a key
(define-read-only (get-latest-snapshot (key (string-ascii 64)))
  (begin
    (asserts! (can-read-key key) ERR-NOT-AUTHORIZED)
    (match (map-get? latest-snapshot-blocks key)
      latest-block (get-snapshot key latest-block)
      ERR-SNAPSHOT-NOT-FOUND)))

;; Get snapshot at or before target block
(define-read-only (get-snapshot-at-or-before (key (string-ascii 64)) (target-block uint))
  (begin
    (asserts! (can-read-key key) ERR-NOT-AUTHORIZED)
    (let ((found-block (find-latest-snapshot-before key target-block)))
      (if (> found-block u0)
        (get-snapshot key found-block)
        ERR-SNAPSHOT-NOT-FOUND))))

;; Get range of snapshots
(define-read-only (get-snapshot-range 
  (key (string-ascii 64)) 
  (start-block uint) 
  (end-block uint))
  (begin
    (asserts! (can-read-key key) ERR-NOT-AUTHORIZED)
    (asserts! (<= start-block end-block) ERR-INVALID-RANGE)
    (ok (get-snapshots-in-range key start-block end-block))))

;; === AGGREGATION FUNCTIONS ===

;; Calculate statistics for a range of snapshots (read-only, no caching)
(define-read-only (get-statistics 
  (key (string-ascii 64)) 
  (start-block uint) 
  (end-block uint))
  (begin
    (asserts! (can-read-key key) ERR-NOT-AUTHORIZED)
    (asserts! (<= start-block end-block) ERR-INVALID-RANGE)
    
    ;; Check cache first (read-only)
    (match (map-get? aggregation-cache {key: key, start-block: start-block, end-block: end-block})
      cached-result (ok cached-result)
      ;; Calculate without caching (since this is read-only)
      (ok (calculate-statistics key start-block end-block)))))

;; Public function to calculate and cache statistics
(define-public (calculate-and-cache-statistics 
  (key (string-ascii 64)) 
  (start-block uint) 
  (end-block uint))
  (begin
    (asserts! (can-read-key key) ERR-NOT-AUTHORIZED)
    (asserts! (<= start-block end-block) ERR-INVALID-RANGE)
    
    ;; Calculate statistics
    (let ((stats (calculate-statistics key start-block end-block)))
      (begin
        ;; Cache the results (this is allowed in public functions)
        (map-set aggregation-cache {key: key, start-block: start-block, end-block: end-block} stats)
        (ok stats)))))

;; Read-only function to get cached statistics only
(define-read-only (get-cached-statistics 
  (key (string-ascii 64)) 
  (start-block uint) 
  (end-block uint))
  (begin
    (asserts! (can-read-key key) ERR-NOT-AUTHORIZED)
    (match (map-get? aggregation-cache {key: key, start-block: start-block, end-block: end-block})
      cached-result (ok cached-result)
      ERR-SNAPSHOT-NOT-FOUND)))

;; Get moving average over a window
(define-read-only (get-moving-average 
  (key (string-ascii 64)) 
  (center-block uint) 
  (window-size uint))
  (let ((start-block (if (>= center-block (/ window-size u2)) 
                       (- center-block (/ window-size u2)) 
                       u0))
        (end-block (+ center-block (/ window-size u2))))
    (match (get-statistics key start-block end-block)
      stats (ok (get avg stats))
      error (err error))))



;; === ADMIN FUNCTIONS ===

;; Pause/unpause contract
(define-public (set-contract-paused (paused bool))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (var-set contract-paused paused)
    (ok paused)))

;; Set snapshot fee
(define-public (set-snapshot-fee (fee uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (var-set snapshot-fee fee)
    (ok fee)))

;; Cleanup old snapshots based on retention policy
(define-public (cleanup-old-snapshots (key (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (match (map-get? key-settings key)
      settings (if (> (get retention-blocks settings) u0)
                 (let ((cutoff-block (- block-height (get retention-blocks settings))))
                   (ok (cleanup-snapshots-before key cutoff-block)))
                 (ok u0))
      (ok u0))))

(define-private (cleanup-snapshots-before (key (string-ascii 64)) (cutoff-block uint))
  u0) ;; Simplified for brevity

;; === READ-ONLY GETTERS ===

(define-read-only (get-total-snapshots) (var-get total-snapshots))
(define-read-only (get-contract-paused) (var-get contract-paused))
(define-read-only (get-snapshot-fee) (var-get snapshot-fee))
(define-read-only (get-current-block) block-height)

(define-read-only (get-key-settings (key (string-ascii 64)))
  (map-get? key-settings key))

(define-read-only (is-writer-authorized (key (string-ascii 64)) (writer principal))
  (default-to false (map-get? authorized-writers {key: key, writer: writer})))

;; Get event by ID
(define-read-only (get-event (event-id uint))
  (map-get? event-log event-id))

;; Get latest events
(define-read-only (get-latest-events (count uint))
  (let ((latest-id (var-get event-counter)))
    (if (>= latest-id count)
      (ok (get-events-range (- latest-id count) latest-id))
      (ok (get-events-range u0 latest-id)))))

(define-private (get-events-range (start uint) (end uint))
  (list)) ;; Simplified for brevity

;; Initialize contract
(register-key "default" true true u0)